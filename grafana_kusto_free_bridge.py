#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "azure-identity>=1.15.0",
# ]
# ///
"""
grafana-kusto-free-bridge
=========================
Local Azure Managed Identity Token Bridge for Grafana -> Free Azure Data Explorer (Kusto) clusters.

Why this exists:
1. Free Azure Data Explorer (Kusto) clusters (`https://kvc*.kusto.windows.net`) can be created
   with a personal Microsoft Account (`@outlook.com`, `@hotmail.com`, `@live.com`) without an
   Azure subscription.
2. However, Grafana's Azure Data Explorer plugin only supports Entra ID authentication
   (App Registration Client Secret, Managed Identity, or Workload Identity).
3. Personal Microsoft Accounts cannot issue Service Principal tokens via `/consumers` for Kusto
   (`AADSTS9002332`), and if you create a free Entra ID tenant to hold an App Registration for
   Grafana, Microsoft's automated Tenant Lifecycle policy eventually blocks that tenant due to
   inactivity (`AADSTS5000225: This tenant has been blocked due to inactivity`) and deletes it
   20 days later.

How it works:
This lightweight loopback server emulates the standard Azure App Service Managed Identity
endpoint (`IDENTITY_ENDPOINT` + `IDENTITY_HEADER`) on `127.0.0.1:18492` and delegates token
acquisition to `AzureCliCredential` (`az login`), allowing Grafana to authenticate directly as
your personal Microsoft Account (`msauser=...`) with zero Entra ID tenants or Client Secrets.
"""

from __future__ import annotations

import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse, urlunparse

from azure.core.credentials import AccessToken, TokenCredential
from azure.identity import AzureCliCredential

__version__ = "1.0.0"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18492
DEFAULT_SECRET = "kusto-local-bridge"
DEFAULT_RESOURCE = "https://help.kusto.windows.net"
CONSUMER_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad"
TOKEN_REFRESH_BUFFER_SECONDS = 120
MAX_CACHED_SCOPES = 64

ALLOWED_KUSTO_HOST_SUFFIXES: tuple[str, ...] = (
    ".kusto.windows.net",
    ".kusto.azuresynapse.net",
    ".kusto.chinacloudapi.cn",
    ".kusto.usgovcloudapi.net",
    ".kusto.fabric.microsoft.com",
    ".kustomfa.windows.net",
)

logger = logging.getLogger("grafana-kusto-free-bridge")


def configure_logging() -> None:
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


def ensure_homebrew_path() -> None:
    """Ensure Homebrew and local bin paths are present when launched under macOS launchd."""
    if sys.platform != "darwin":
        return
    extra_paths = ["/opt/homebrew/bin", "/usr/local/bin", str(Path.home() / ".local" / "bin")]
    current_path = os.environ.get("PATH", "/usr/bin:/bin")
    parts = current_path.split(os.pathsep)
    for p in reversed(extra_paths):
        if p not in parts and Path(p).is_dir():
            parts.insert(0, p)
    os.environ["PATH"] = os.pathsep.join(parts)


def is_loopback_host(host: str) -> bool:
    """Return True if `host` is a loopback address (`localhost`, `127.x.x.x`, `::1`)."""
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def normalize_resource_uri(resource: str) -> str:
    """Strip whitespace and trailing slashes, and lowercase scheme + netloc if valid."""
    cleaned = resource.strip().rstrip("/")
    try:
        parsed = urlparse(cleaned)
        if parsed.scheme and parsed.netloc:
            cleaned = urlunparse(
                (
                    parsed.scheme.lower(),
                    parsed.netloc.lower(),
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            ).rstrip("/")
    except ValueError:
        pass
    return cleaned


def resource_to_scope(resource: str) -> str:
    """Convert a resource URI into a canonical Azure OAuth2 `.default` scope."""
    return f"{normalize_resource_uri(resource)}/.default"


def is_allowed_kusto_resource(
    resource: str,
    allowed_resources: set[str] | None = None,
) -> bool:
    """
    Validate that `resource` is a valid HTTPS Kusto cluster URL (or explicitly allowlisted)
    so the bridge cannot be abused to mint tokens for arbitrary Azure services (e.g. ARM or Graph).
    """
    cleaned = normalize_resource_uri(resource)
    try:
        parsed = urlparse(cleaned)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        _ = parsed.port
    except ValueError:
        return False

    if scheme != "https" or not hostname:
        return False
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        return False

    if allowed_resources and cleaned in {normalize_resource_uri(r) for r in allowed_resources}:
        return True

    return any(
        hostname.endswith(suffix) and len(hostname) > len(suffix)
        for suffix in ALLOWED_KUSTO_HOST_SUFFIXES
    )


class CachedTokenCredential:
    """
    Thread-safe in-memory token cache wrapping an Azure `TokenCredential`.
    Uses per-scope locks so refreshing one scope does not block cache hits on another.
    Note: `kwargs` are forwarded to the underlying credential but not included in the cache key.
    """

    def __init__(self, credential: TokenCredential, refresh_buffer_seconds: int = TOKEN_REFRESH_BUFFER_SECONDS):
        self._credential = credential
        self._refresh_buffer = refresh_buffer_seconds
        self._meta_lock = threading.Lock()
        self._scope_locks: dict[str, threading.Lock] = {}
        self._cache: dict[str, AccessToken] = {}

    def _get_scope_lock(self, scope_key: str) -> threading.Lock:
        with self._meta_lock:
            lock = self._scope_locks.get(scope_key)
            if lock is None:
                if len(self._scope_locks) >= MAX_CACHED_SCOPES:
                    oldest_key = next(iter(self._scope_locks))
                    self._scope_locks.pop(oldest_key, None)
                    self._cache.pop(oldest_key, None)
                lock = threading.Lock()
                self._scope_locks[scope_key] = lock
            return lock

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        scope_key = " ".join(scopes)
        now = time.time()
        with self._meta_lock:
            cached = self._cache.get(scope_key)
        if cached is not None and (cached.expires_on - self._refresh_buffer) > now:
            return cached

        scope_lock = self._get_scope_lock(scope_key)
        with scope_lock:
            now = time.time()
            with self._meta_lock:
                cached = self._cache.get(scope_key)
            if cached is not None and (cached.expires_on - self._refresh_buffer) > now:
                return cached

            fresh = self._credential.get_token(*scopes, **kwargs)
            with self._meta_lock:
                self._cache[scope_key] = fresh
            return fresh


def _atomic_write_json(profile_path: Path, data: dict[str, Any]) -> None:
    """Create a `.bak` backup and atomically replace `profile_path` encoded as `utf-8-sig`."""
    backup_path = profile_path.with_suffix(profile_path.suffix + ".bak")
    shutil.copy2(profile_path, backup_path)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{profile_path.name}.",
        suffix=".tmp",
        dir=str(profile_path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        shutil.copymode(profile_path, tmp_path)
        os.replace(tmp_path, profile_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def check_and_fix_az_profile(
    profile_path: Path | None = None,
    fix: bool = False,
) -> tuple[bool, list[str]]:
    """
    Inspect `~/.azure/azureProfile.json` for common personal Microsoft Account (MSA) pitfalls
    with Azure Data Explorer (Kusto):
      - Malformed JSON or missing file
      - Missing or multiple `isDefault=true` entries (`No subscription found`)
      - `tenantId` set to consumer tenant `9188040d-6c67-4c5b-b112-36a304b66dad` (`AADSTS9002332`)
        instead of `organizations`.
    """
    if profile_path is None:
        profile_path = Path.home() / ".azure" / "azureProfile.json"

    messages: list[str] = []
    if not profile_path.exists():
        messages.append(
            f"[ERROR] {profile_path} does not exist. Run: az login --tenant organizations --allow-no-subscriptions"
        )
        return False, messages

    try:
        raw = profile_path.read_text(encoding="utf-8-sig")
        data: dict[str, Any] = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        messages.append(f"[ERROR] Failed to read or parse {profile_path}: {exc}")
        return False, messages

    if not isinstance(data, dict):
        messages.append(f"[ERROR] Expected JSON object in {profile_path}.")
        return False, messages

    subs: list[dict[str, Any]] = data.get("subscriptions", [])
    if not isinstance(subs, list) or not subs:
        messages.append(
            f"[ERROR] No accounts found in {profile_path}. Run: az login --tenant organizations --allow-no-subscriptions"
        )
        return False, messages

    unresolved_issues = 0
    modified = False

    default_indices = [i for i, s in enumerate(subs) if s.get("isDefault")]
    if not default_indices:
        messages.append("[WARN] No default account marked with isDefault=true in azureProfile.json.")
        if fix:
            subs[0]["isDefault"] = True
            default_indices = [0]
            modified = True
            messages.append(f"[FIXED] Marked {subs[0].get('user', {}).get('name', 'first account')} as isDefault=true.")
        else:
            unresolved_issues += 1
    elif len(default_indices) > 1:
        messages.append(f"[WARN] Multiple accounts ({len(default_indices)}) marked with isDefault=true.")
        if fix:
            for idx in default_indices[1:]:
                subs[idx]["isDefault"] = False
            default_indices = [default_indices[0]]
            modified = True
            messages.append(
                f"[FIXED] Kept only '{subs[default_indices[0]].get('user', {}).get('name', 'first default')}' as isDefault=true."
            )
        else:
            unresolved_issues += 1

    for idx in default_indices:
        sub = subs[idx]
        user_name = sub.get("user", {}).get("name", "unknown")
        tenant_id = sub.get("tenantId", "")
        if tenant_id == CONSUMER_TENANT_ID:
            messages.append(
                f"[WARN] Default account '{user_name}' has tenantId='{CONSUMER_TENANT_ID}' (/consumers), "
                "which Kusto rejects with AADSTS9002332."
            )
            if fix:
                sub["tenantId"] = "organizations"
                modified = True
                messages.append(f"[FIXED] Updated tenantId to 'organizations' for '{user_name}'.")
            else:
                unresolved_issues += 1
        else:
            messages.append(
                f"[OK] Default account '{user_name}' configured with tenantId='{tenant_id}'."
            )

    if modified and fix:
        try:
            _atomic_write_json(profile_path, data)
            messages.append(
                f"[SAVED] Wrote updated profile to {profile_path} (utf-8-sig, backup at {profile_path}.bak)."
            )
        except OSError as exc:
            messages.append(f"[ERROR] Failed to write updated profile to {profile_path}: {exc}")
            return False, messages

    return unresolved_issues == 0, messages


def create_bridge_handler(
    credential: TokenCredential,
    expected_secret: str,
    default_resource: str,
    allowed_resources: set[str] | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Create a request handler bound to the given credential, secret, and resource policy."""
    expected_secret_bytes = expected_secret.encode("utf-8")

    class ManagedIdentityBridgeHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/token":
                self._send_json(
                    404,
                    {"error": "not_found", "error_description": "Endpoint not found. Use /token."},
                )
                return

            header_secret = self.headers.get("X-IDENTITY-HEADER") or self.headers.get("Secret") or ""
            if not expected_secret or not hmac.compare_digest(
                header_secret.encode("utf-8"), expected_secret_bytes
            ):
                self._send_json(
                    403,
                    {"error": "forbidden", "error_description": "Missing or invalid X-IDENTITY-HEADER"},
                )
                return

            qs = parse_qs(parsed.query)
            resource = normalize_resource_uri(qs.get("resource", [default_resource])[0])
            if not is_allowed_kusto_resource(resource, allowed_resources=allowed_resources):
                logger.warning("Rejected token request for disallowed resource: %r", resource)
                self._send_json(
                    400,
                    {
                        "error": "invalid_resource",
                        "error_description": "Requested resource is not an allowed Azure Data Explorer (Kusto) cluster URI.",
                    },
                )
                return

            scope = resource_to_scope(resource)

            try:
                tok = credential.get_token(scope)
                expires_on = int(tok.expires_on)
                expires_in = max(0, int(expires_on - time.time()))
                payload = {
                    "access_token": tok.token,
                    "expires_on": str(expires_on),
                    "expires_in": str(expires_in),
                    "resource": resource,
                    "token_type": "Bearer",
                }
                self._send_json(200, payload)
            except Exception as exc:
                logger.error("Failed to acquire token for %s: %s", scope, exc)
                self._send_json(
                    500,
                    {
                        "error": "token_acquisition_failed",
                        "error_description": "Failed to acquire Azure access token. Check bridge logs for details.",
                    },
                )

        def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
            body = json.dumps(data).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            logger.info("%s - %s", self.address_string(), fmt % args)

    return ManagedIdentityBridgeHandler


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="grafana-kusto-free-bridge",
        description=(
            "Local Azure Managed Identity Token Bridge for connecting Grafana to a Free "
            "Azure Data Explorer (Kusto) cluster using a personal Microsoft Account (az login)."
        ),
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("BRIDGE_HOST", DEFAULT_HOST),
        help=f"Bind address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"Bind port (default: {DEFAULT_PORT}, or BRIDGE_PORT env var)",
    )
    parser.add_argument(
        "--secret",
        default=os.environ.get("IDENTITY_HEADER", DEFAULT_SECRET),
        help="Required X-IDENTITY-HEADER shared secret (or IDENTITY_HEADER env var)",
    )
    parser.add_argument(
        "--default-resource",
        default=os.environ.get("DEFAULT_KUSTO_RESOURCE", DEFAULT_RESOURCE),
        help=f"Fallback Kusto resource URI if omitted in query string (default: {DEFAULT_RESOURCE})",
    )
    parser.add_argument(
        "--allowed-resource",
        action="append",
        dest="allowed_resources",
        default=None,
        help="Additional exact HTTPS resource URI(s) to allow (may be specified multiple times)",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Check ~/.azure/azureProfile.json and verify Kusto token acquisition, then exit",
    )
    parser.add_argument(
        "--fix-az-profile",
        action="store_true",
        help=(
            "Repair personal MSA tenantId ('organizations') and default account in "
            "~/.azure/azureProfile.json (with .bak backup), run the --doctor check, and exit"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args(argv)

    if args.port is None:
        env_port = os.environ.get("BRIDGE_PORT")
        if env_port is not None:
            try:
                args.port = int(env_port)
            except ValueError:
                parser.error(f"Invalid BRIDGE_PORT environment variable: {env_port!r} (must be an integer)")
        else:
            args.port = DEFAULT_PORT

    if not (1 <= args.port <= 65535):
        parser.error(f"Port must be between 1 and 65535 (got {args.port})")

    if not args.secret or not args.secret.strip():
        parser.error("--secret / IDENTITY_HEADER must not be empty")

    return args


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    ensure_homebrew_path()
    args = parse_args(argv)

    allowed_set = set(args.allowed_resources) if args.allowed_resources else None
    if not is_allowed_kusto_resource(args.default_resource, allowed_resources=allowed_set):
        logger.error(
            "Default resource %r is not a recognized HTTPS Kusto cluster URI.",
            args.default_resource,
        )
        return 1

    if args.doctor or args.fix_az_profile:
        ok, msgs = check_and_fix_az_profile(fix=args.fix_az_profile)
        for m in msgs:
            print(m)
        if not ok:
            return 1
        try:
            cred = AzureCliCredential()
            scope = resource_to_scope(args.default_resource)
            tok = cred.get_token(scope)
            print(f"[OK] Successfully acquired Kusto token for {scope} (expires_on={tok.expires_on}).")
            return 0
        except Exception as exc:
            print(f"[ERROR] Token acquisition check failed: {exc}", file=sys.stderr)
            return 1

    if not is_loopback_host(args.host) and args.secret == DEFAULT_SECRET:
        logger.error(
            "Refusing to bind to non-loopback address %r with the default public secret. "
            "Specify a strong custom secret via --secret or the IDENTITY_HEADER environment variable.",
            args.host,
        )
        return 1

    cached_credential = CachedTokenCredential(AzureCliCredential())
    handler_cls = create_bridge_handler(
        credential=cached_credential,
        expected_secret=args.secret,
        default_resource=args.default_resource,
        allowed_resources=allowed_set,
    )
    server = ThreadingHTTPServer((args.host, args.port), handler_cls)

    def _handle_sigterm(signum: int, _frame: Any) -> None:
        logger.info("Received signal %d, initiating shutdown.", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _handle_sigterm)

    logger.info(
        "v%s listening on http://%s:%d/token",
        __version__,
        args.host,
        args.port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
