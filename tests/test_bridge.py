from __future__ import annotations

from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import stat
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from azure.core.credentials import AccessToken
import pytest

from grafana_kusto_free_bridge import (
    CONSUMER_TENANT_ID,
    CachedTokenCredential,
    check_and_fix_az_profile,
    create_bridge_handler,
    is_allowed_kusto_resource,
    is_loopback_host,
    main,
    normalize_resource_uri,
    parse_args,
)


@pytest.fixture(autouse=True)
def _clean_bridge_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate tests from any caller-exported bridge environment variables."""
    for var in ("IDENTITY_HEADER", "BRIDGE_HOST", "BRIDGE_PORT", "DEFAULT_KUSTO_RESOURCE"):
        monkeypatch.delenv(var, raising=False)


class DummyCredential:
    def __init__(self, token: str = "fake-jwt-token", expires_on: int = 1900000000, fail: bool = False):
        self.token = token
        self.expires_on = expires_on
        self.fail = fail
        self.requested_scopes: list[str] = []

    def get_token(self, *scopes: str, **kwargs):
        self.requested_scopes.extend(scopes)
        if self.fail:
            raise RuntimeError("Simulated Azure CLI error: sensitive_account@outlook.com")
        return AccessToken(self.token, self.expires_on)


@contextmanager
def _run_test_server(
    cred: DummyCredential | CachedTokenCredential,
    secret: str = "test-secret",
    default_resource: str = "https://help.kusto.windows.net",
    allowed_resources: set[str] | None = None,
):
    handler = create_bridge_handler(
        credential=cred,
        expected_secret=secret,
        default_resource=default_resource,
        allowed_resources=allowed_resources,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


def test_app_service_msi_success_and_case_normalization():
    future_exp = int(time.time()) + 3600
    cred = DummyCredential(token="msa-kusto-token", expires_on=future_exp)
    with _run_test_server(cred, secret="my-bridge-secret") as port:
        url = (
            f"http://127.0.0.1:{port}/token"
            "?api-version=2019-08-01&resource=HTTPS://KVCTEST.NORTHEUROPE.KUSTO.WINDOWS.NET/"
        )
        req = Request(url, headers={"X-IDENTITY-HEADER": "my-bridge-secret"})
        with urlopen(req) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "application/json; charset=utf-8"
            body = json.loads(resp.read().decode("utf-8"))
            assert body["access_token"] == "msa-kusto-token"
            assert body["expires_on"] == str(future_exp)
            assert int(body["expires_in"]) > 3500
            assert body["resource"] == "https://kvctest.northeurope.kusto.windows.net"
            assert body["token_type"] == "Bearer"
        assert cred.requested_scopes == ["https://kvctest.northeurope.kusto.windows.net/.default"]


def test_default_resource_when_omitted():
    cred = DummyCredential(token="default-res-token")
    with _run_test_server(cred, secret="my-bridge-secret") as port:
        req = Request(
            f"http://127.0.0.1:{port}/token?api-version=2019-08-01",
            headers={"X-IDENTITY-HEADER": "my-bridge-secret"},
        )
        with urlopen(req) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
            assert body["resource"] == "https://help.kusto.windows.net"
        assert cred.requested_scopes == ["https://help.kusto.windows.net/.default"]


def test_allowed_resource_end_to_end():
    cred = DummyCredential(token="custom-kusto-token")
    with _run_test_server(
        cred,
        secret="my-bridge-secret",
        allowed_resources={"https://custom.kusto.internal"},
    ) as port:
        req = Request(
            f"http://127.0.0.1:{port}/token?api-version=2019-08-01&resource=https://custom.kusto.internal/",
            headers={"X-IDENTITY-HEADER": "my-bridge-secret"},
        )
        with urlopen(req) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
            assert body["access_token"] == "custom-kusto-token"
            assert body["resource"] == "https://custom.kusto.internal"
        assert cred.requested_scopes == ["https://custom.kusto.internal/.default"]


def test_missing_or_wrong_secret_and_imds_bypass_rejected():
    cred = DummyCredential()
    with _run_test_server(cred, secret="my-bridge-secret") as port:
        # 1. Missing secret -> 403
        req_missing = Request(f"http://127.0.0.1:{port}/token?api-version=2019-08-01")
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req_missing)
        assert exc_info.value.code == 403

        # 2. Wrong secret -> 403
        req_wrong = Request(
            f"http://127.0.0.1:{port}/token?api-version=2019-08-01",
            headers={"X-IDENTITY-HEADER": "wrong-secret"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req_wrong)
        assert exc_info.value.code == 403

        # 3. IMDS Metadata: true header without secret -> 403 (no bypass allowed)
        req_imds = Request(
            f"http://127.0.0.1:{port}/token?api-version=2019-08-01",
            headers={"Metadata": "true"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req_imds)
        assert exc_info.value.code == 403


def test_unknown_path_returns_404():
    cred = DummyCredential()
    with _run_test_server(cred, secret="my-bridge-secret") as port:
        req = Request(
            f"http://127.0.0.1:{port}/other-path",
            headers={"X-IDENTITY-HEADER": "my-bridge-secret"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 404


def test_disallowed_or_malformed_resource_returns_400():
    cred = DummyCredential()
    with _run_test_server(cred, secret="my-bridge-secret") as port:
        for bad_res in (
            "https://management.azure.com",
            "https://graph.microsoft.com",
            "http://help.kusto.windows.net",
            "https://[invalid-ipv6",
        ):
            req = Request(
                f"http://127.0.0.1:{port}/token?api-version=2019-08-01&resource={bad_res}",
                headers={"X-IDENTITY-HEADER": "my-bridge-secret"},
            )
            with pytest.raises(HTTPError) as exc_info:
                urlopen(req)
            assert exc_info.value.code == 400
        assert cred.requested_scopes == []


def test_token_failure_returns_500_without_leaking_exception_details():
    cred = DummyCredential(fail=True)
    with _run_test_server(cred, secret="my-bridge-secret") as port:
        req = Request(
            f"http://127.0.0.1:{port}/token?api-version=2019-08-01",
            headers={"X-IDENTITY-HEADER": "my-bridge-secret"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 500
        err_body = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_body["error"] == "token_acquisition_failed"
        assert "sensitive_account@outlook.com" not in err_body["error_description"]


def test_cached_token_credential_hit_and_near_expiry_refresh():
    now = int(time.time())
    # 1. Valid far-future token is cached and reused
    inner = DummyCredential(token="cached-tok", expires_on=now + 3600)
    cached = CachedTokenCredential(inner)
    t1 = cached.get_token("https://help.kusto.windows.net/.default")
    t2 = cached.get_token("https://help.kusto.windows.net/.default")
    assert t1.token == t2.token == "cached-tok"
    assert len(inner.requested_scopes) == 1

    # 2. Token expiring within the 120s buffer triggers a fresh get_token call
    near_exp_inner = DummyCredential(token="expiring-soon", expires_on=now + 60)
    near_cached = CachedTokenCredential(near_exp_inner)
    near_cached.get_token("https://help.kusto.windows.net/.default")
    near_exp_inner.token = "refreshed-tok"
    near_exp_inner.expires_on = now + 3600
    t_refreshed = near_cached.get_token("https://help.kusto.windows.net/.default")
    assert t_refreshed.token == "refreshed-tok"
    assert len(near_exp_inner.requested_scopes) == 2


def test_non_loopback_with_default_secret_refused():
    # Even if caller's shell had IDENTITY_HEADER set, the autouse fixture clears it,
    # and we also verify explicit default refusal:
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("::1")
    assert is_loopback_host("localhost")
    assert not is_loopback_host("0.0.0.0")
    assert main(["--host", "0.0.0.0"]) == 1


def test_is_allowed_kusto_resource_and_normalization():
    assert normalize_resource_uri("HTTPS://KVC123.NorthEurope.kusto.windows.net/") == (
        "https://kvc123.northeurope.kusto.windows.net"
    )
    assert is_allowed_kusto_resource("https://kvc123.northeurope.kusto.windows.net/")
    assert not is_allowed_kusto_resource("https://management.azure.com")
    assert not is_allowed_kusto_resource("https://[invalid-ipv6")
    assert not is_allowed_kusto_resource("https://kvc123.kusto.windows.net:99999")
    assert is_allowed_kusto_resource(
        "https://custom.kusto.internal",
        allowed_resources={"https://custom.kusto.internal"},
    )
    assert not is_allowed_kusto_resource(
        "http://custom.kusto.internal",
        allowed_resources={"http://custom.kusto.internal"},
    )


def test_parse_args_invalid_port(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BRIDGE_PORT", "not-an-int")
    with pytest.raises(SystemExit):
        parse_args([])


def test_check_and_fix_az_profile_comprehensive(tmp_path: Path):
    # 1. Missing file -> False
    missing = tmp_path / "missing.json"
    ok_missing, _ = check_and_fix_az_profile(profile_path=missing, fix=False)
    assert not ok_missing

    # 2. Malformed JSON -> False
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not valid json", encoding="utf-8-sig")
    ok_bad_json, msgs = check_and_fix_az_profile(profile_path=malformed, fix=True)
    assert not ok_bad_json
    assert any(m.startswith("[ERROR]") for m in msgs)

    # 3. Empty subscriptions -> False
    empty_subs = tmp_path / "empty.json"
    empty_subs.write_text(json.dumps({"subscriptions": []}), encoding="utf-8-sig")
    ok_empty, _ = check_and_fix_az_profile(profile_path=empty_subs, fix=True)
    assert not ok_empty

    # 4. Multiple defaults + consumer tenantId -> fixed + .bak created + mode preserved
    profile = tmp_path / "azureProfile.json"
    initial = {
        "installationId": "00000000-0000-0000-0000-000000000000",
        "subscriptions": [
            {
                "id": "00000000-0000-0000-0000-000000000000",
                "name": "N/A(tenant level account)",
                "state": "Enabled",
                "user": {"name": "user1@outlook.com", "type": "user"},
                "isDefault": True,
                "tenantId": CONSUMER_TENANT_ID,
            },
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "Second",
                "state": "Enabled",
                "user": {"name": "user2@outlook.com", "type": "user"},
                "isDefault": True,
                "tenantId": "organizations",
            },
        ],
    }
    profile.write_text(json.dumps(initial), encoding="utf-8-sig")
    profile.chmod(0o640)

    ok, _ = check_and_fix_az_profile(profile_path=profile, fix=False)
    assert not ok

    ok_fixed, _ = check_and_fix_az_profile(profile_path=profile, fix=True)
    assert ok_fixed
    assert profile.with_suffix(".json.bak").exists()
    assert stat.S_IMODE(profile.stat().st_mode) == 0o640

    raw_updated = profile.read_text(encoding="utf-8-sig")
    assert "\n  " in raw_updated  # Indented formatting preserved
    updated = json.loads(raw_updated)
    assert updated["subscriptions"][0]["isDefault"] is True
    assert updated["subscriptions"][0]["tenantId"] == "organizations"
    assert updated["subscriptions"][1]["isDefault"] is False

    # 5. Already healthy profile -> True without modifying
    ok_healthy, _ = check_and_fix_az_profile(profile_path=profile, fix=False)
    assert ok_healthy
