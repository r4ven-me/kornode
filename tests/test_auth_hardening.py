from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml
from fastapi import Request
from fastapi.testclient import TestClient

from kornode.api import routes_auth
from kornode.api.app import create_app
from kornode.api.auth import (
    SESSION_COOKIE,
    _reject_cross_origin_basic_request,
    invalidate_auth_sessions,
)
from kornode.config.models import AppConfig
from kornode.services.admin_totp import AdminTotpService
from kornode.services.password_hash import verify_password

TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _client(tmp_path: Path, *, totp: bool = False) -> TestClient:
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "system": {
                    key: str(tmp_path / key)
                    for key in ("data_dir", "generated_dir", "log_dir", "secrets_dir")
                },
                "web": {
                    "admin_password": "secret",
                    "admin_totp_enabled": totp,
                    "admin_totp_secret": TOTP_SECRET if totp else None,
                },
            }
        ),
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=path), base_url="https://testserver")


def _code(client: TestClient, secret: str = TOTP_SECRET) -> str:
    return AdminTotpService(client.app.state.config)._code_at(secret, int(time.time()) // 30)


def _login(client: TestClient, *, password: str = "secret", totp: bool = False) -> str:
    payload = {"username": "admin", "password": password}
    if totp:
        payload["totp_code"] = _code(client)
    response = client.post("/api/auth/login", json=payload)
    assert response.status_code == 200, response.text
    return str(response.json()["csrf_token"])


@pytest.mark.parametrize("path", ["/api/config", "/api/auth/me", "/api/auth/totp/status"])
def test_totp_blocks_password_only_basic(tmp_path: Path, path: str) -> None:
    client = _client(tmp_path, totp=True)
    rejected = client.get(path, auth=("admin", "secret"))
    assert rejected.status_code == 401
    assert rejected.json()["detail"] == "totp_session_required"
    _login(client, totp=True)
    assert client.get(path).status_code == 200


def test_totp_blocks_password_only_basic_mutation(tmp_path: Path) -> None:
    client = _client(tmp_path, totp=True)
    response = client.post(
        "/api/auth/totp/disable",
        auth=("admin", "secret"),
        json={"current_password": "secret", "totp_code": _code(client)},
    )
    assert response.status_code == 401
    assert client.app.state.config.web.admin_totp_enabled


def test_auth_change_during_password_verification_cannot_create_new_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path)
    original = routes_auth.authenticate_password

    def verify_then_change_config(request: Request, username: str, password: str) -> None:
        original(request, username, password)
        previous = request.app.state.config
        updated = previous.model_copy(deep=True)
        updated.web.admin_password = "replacement"
        request.app.state.config = updated
        invalidate_auth_sessions(request, previous, updated)

    monkeypatch.setattr(routes_auth, "authenticate_password", verify_then_change_config)
    response = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert response.status_code == 401
    assert response.json()["detail"] == "authentication_changed"
    assert not client.cookies.get(SESSION_COOKIE)


def test_login_rotates_cookie_and_csrf_and_revokes_previous_cookie(tmp_path: Path) -> None:
    client = _client(tmp_path)
    csrf = _login(client)
    token = client.cookies.get(SESSION_COOKIE)
    new_csrf = _login(client)
    assert new_csrf != csrf
    assert client.cookies.get(SESSION_COOKIE) != token
    assert client.app.state.auth_sessions.get(token) is None
    assert client.get("/api/auth/me").status_code == 200


def test_password_change_hashes_and_revokes_all_sessions(tmp_path: Path) -> None:
    client = _client(tmp_path)
    other = TestClient(client.app, base_url="https://testserver")
    csrf = _login(client)
    _login(other)
    old_token = client.cookies.get(SESSION_COOKIE)
    response = client.post(
        "/api/auth/password",
        headers={"X-Kornode-CSRF": csrf},
        json={"current_password": "secret", "new_password": "new-sensitive-password"},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "password_changed", "reauthentication_required": True}
    assert "new-sensitive-password" not in response.text
    assert "secret" not in response.text
    assert not client.cookies.get(SESSION_COOKIE)
    assert client.app.state.auth_sessions.get(old_token) is None
    assert other.get("/api/auth/me").status_code == 401
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert saved["web"]["admin_password"] is None
    assert verify_password("new-sensitive-password", saved["web"]["admin_password_hash"])
    assert client.get("/api/auth/me", auth=("admin", "secret")).status_code == 401
    assert client.get("/api/auth/me", auth=("admin", "new-sensitive-password")).status_code == 200
    _login(client, password="new-sensitive-password")
    assert client.cookies.get(SESSION_COOKIE) != old_token


@pytest.mark.parametrize("totp", [False, True])
def test_password_change_reauthenticates_and_requires_csrf(tmp_path: Path, totp: bool) -> None:
    client = _client(tmp_path, totp=totp)
    csrf = _login(client, totp=totp)
    payload = {"current_password": "wrong", "new_password": "replacement"}
    if totp:
        payload["totp_code"] = _code(client)
    response = client.post("/api/auth/password", headers={"X-Kornode-CSRF": csrf}, json=payload)
    assert response.status_code == 401
    payload["current_password"] = "secret"
    assert client.post("/api/auth/password", json=payload).status_code == 403
    if totp:
        payload.pop("totp_code")
        missing = client.post("/api/auth/password", headers={"X-Kornode-CSRF": csrf}, json=payload)
        assert missing.status_code == 401
        assert missing.json()["detail"] == "totp_code_required"
        payload["totp_code"] = _code(client)
    changed = client.post("/api/auth/password", headers={"X-Kornode-CSRF": csrf}, json=payload)
    assert changed.status_code == 200
    _login(client, password="replacement", totp=totp)


def test_password_change_preserves_scripted_basic_without_totp(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/auth/password",
        auth=("admin", "secret"),
        json={"current_password": "secret", "new_password": "replacement"},
    )
    assert response.status_code == 200
    assert client.get("/api/auth/me", auth=("admin", "replacement")).status_code == 200


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("admin_user", "replacement-admin"),
        ("admin_password", "replacement"),
        ("admin_password_hash", "changed-hash"),
        ("admin_totp_enabled", True),
        ("admin_totp_secret", "KRSXG5DSNFXGOIDB"),
    ],
)
def test_invalidation_helper_revokes_on_auth_changes(
    tmp_path: Path, field: str, value: object
) -> None:
    client = _client(tmp_path)
    if field == "admin_totp_enabled":
        client.app.state.config.web.admin_totp_secret = TOTP_SECRET
    _login(client)
    old = client.app.state.config
    new = old.model_copy(deep=True)
    setattr(new.web, field, value)
    client.app.state.config = new
    invalidate_auth_sessions(Request({"type": "http", "app": client.app}), old, new)
    assert client.get("/api/auth/me").status_code == 401


def test_invalidation_helper_preserves_sessions_for_unrelated_settings(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    old = client.app.state.config
    new = old.model_copy(deep=True)
    new.system.timezone = "Europe/Moscow"
    client.app.state.config = new
    invalidate_auth_sessions(Request({"type": "http", "app": client.app}), old, new)
    assert client.get("/api/auth/me").status_code == 200


@pytest.mark.parametrize("action", ["patch", "source", "source_validate", "validate"])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("admin_password", "replacement"),
        ("admin_password", None),
        ("admin_password_hash", "replacement-hash"),
        ("admin_totp_enabled", False),
        ("admin_totp_secret", "KRSXG5DSNFXGOIDB"),
    ],
)
def test_public_config_endpoints_cannot_bypass_auth_reauthentication(
    tmp_path: Path, action: str, field: str, value: object
) -> None:
    client = _client(tmp_path, totp=True)
    csrf = _login(client, totp=True)
    path = tmp_path / "config.yaml"
    original_source = path.read_text()
    original_config = client.app.state.config
    candidate = yaml.safe_load(original_source)
    candidate["web"][field] = value
    headers = {"X-Kornode-CSRF": csrf}
    if action == "patch":
        response = client.patch(
            "/api/config",
            headers=headers,
            json={"patch": {"web": {field: value}}, "write_rendered": False},
        )
    elif action == "validate":
        response = client.post("/api/config/validate", headers=headers, json=candidate)
    else:
        payload = {"content": yaml.safe_dump(candidate), "write_rendered": False}
        if action == "source":
            payload["etag"] = client.get("/api/config/source").json()["etag"]
        endpoint = "/api/config/source" if action == "source" else "/api/config/source/validate"
        response = client.post(endpoint, headers=headers, json=payload)
    assert response.status_code == 403, response.text
    assert (
        response.json()["detail"] == "admin authentication changes require dedicated auth actions"
    )
    assert path.read_text() == original_source
    assert client.app.state.config is original_config
    assert client.get("/api/auth/me").status_code == 200


def test_masked_source_roundtrip_preserves_mfa_and_sessions(tmp_path: Path) -> None:
    client = _client(tmp_path, totp=True)
    csrf = _login(client, totp=True)
    original = client.app.state.config.web
    source = client.get("/api/config/source").json()
    assert yaml.safe_load(source["content"])["web"]["admin_totp_enabled"] is True
    response = client.post(
        "/api/config/source",
        headers={"X-Kornode-CSRF": csrf},
        json={"content": source["content"], "etag": source["etag"], "write_rendered": False},
    )
    assert response.status_code == 200, response.text
    updated = client.app.state.config.web
    assert updated.admin_totp_enabled is True
    assert updated.admin_totp_secret == original.admin_totp_secret
    assert updated.admin_password == original.admin_password
    assert client.get("/api/auth/me").status_code == 200


def test_web_settings_cannot_smuggle_password_or_mfa_fields(tmp_path: Path) -> None:
    client = _client(tmp_path, totp=True)
    csrf = _login(client, totp=True)
    original = client.app.state.config.web
    response = client.post(
        "/api/web-config/settings",
        headers={"X-Kornode-CSRF": csrf},
        json={
            "admin_password": "replacement",
            "admin_password_hash": "replacement-hash",
            "admin_totp_enabled": False,
            "admin_totp_secret": "KRSXG5DSNFXGOIDB",
        },
    )
    assert response.status_code == 200, response.text
    updated = client.app.state.config.web
    assert updated.admin_password == original.admin_password
    assert updated.admin_password_hash == original.admin_password_hash
    assert updated.admin_totp_enabled is True
    assert updated.admin_totp_secret == original.admin_totp_secret
    assert client.get("/api/auth/me").status_code == 200


def test_in_memory_config_replacement_invalidates_without_helper(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    new = client.app.state.config.model_copy(deep=True)
    new.web.admin_password = "replacement"
    client.app.state.config = new
    assert client.get("/api/auth/me").status_code == 401


@pytest.mark.parametrize(
    "origin",
    [
        "null",
        "",
        "https://evil.example",
        "http://testserver",
        "https://testserver:8443",
        "https://testserver:0",
        "https://testserver:bad",
        "https://testserver:65536",
        "https://testserver/path",
        "https://testserver?query=1",
        "https://testserver#fragment",
        "https://user@testserver",
        "https://testserver https://evil.example",
        "testserver",
    ],
)
def test_origin_rejects_invalid_scheme_host_and_port(tmp_path: Path, origin: str) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/config/render", auth=("admin", "secret"), headers={"Origin": origin}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "cross-origin request rejected"


@pytest.mark.parametrize(
    ("base_url", "origin"),
    [
        ("https://testserver", "https://testserver"),
        ("https://testserver", "https://TESTSERVER:443"),
        ("http://testserver", "http://testserver:80"),
        ("https://testserver:8443", "https://testserver:8443"),
    ],
)
def test_origin_accepts_matching_effective_origin(
    tmp_path: Path, base_url: str, origin: str
) -> None:
    client = _client(tmp_path)
    client.base_url = base_url
    assert (
        client.post(
            "/api/config/render", auth=("admin", "secret"), headers={"Origin": origin}
        ).status_code
        == 200
    )


@pytest.mark.parametrize("origin", ["https://[::1]:8443", "https://[::1]:443", "null"])
def test_ipv6_origin_checks(origin: str) -> None:
    # This Starlette TestClient transport cannot parse IPv6 netlocs, so exercise
    # the real ASGI request directly rather than bypassing IPv6 coverage.
    request = Request(
        {
            "type": "http",
            "scheme": "https",
            "server": ("::1", 8443),
            "path": "/api/config/render",
            "query_string": b"",
            "headers": [(b"host", b"[::1]:8443"), (b"origin", origin.encode())],
        }
    )
    if origin == "https://[::1]:8443":
        _reject_cross_origin_basic_request(request)
    else:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            _reject_cross_origin_basic_request(request)
        assert exc.value.status_code == 403


def test_origin_does_not_fall_back_to_referer_when_null(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/config/render",
        auth=("admin", "secret"),
        headers={"Origin": "null", "Referer": "https://testserver/"},
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "referer", ["http://testserver/page", "https://testserver:8443/page", "null"]
)
def test_referer_validates_full_origin(tmp_path: Path, referer: str) -> None:
    client = _client(tmp_path)
    assert (
        client.post(
            "/api/config/render", auth=("admin", "secret"), headers={"Referer": referer}
        ).status_code
        == 403
    )


def test_cookie_mutations_and_login_reject_cross_origin(tmp_path: Path) -> None:
    client = _client(tmp_path)
    csrf = _login(client)
    assert (
        client.post(
            "/api/config/render", headers={"Origin": "null", "X-Kornode-CSRF": csrf}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "secret"},
            headers={"Origin": "http://testserver"},
        ).status_code
        == 403
    )


def test_request_validation_does_not_echo_password_or_totp_input(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": {"leak": "submitted-secret"}, "totp_code": 123456},
    )
    assert response.status_code == 422
    assert "submitted-secret" not in response.text
    assert "123456" not in response.text
    assert all(set(item) == {"type", "loc", "msg"} for item in response.json()["detail"])


def test_config_validation_does_not_echo_nested_secrets_or_validator_values(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/config/validate",
        auth=("admin", "secret"),
        json={
            "web": {"admin_password": "submitted-config-password"},
            "upstream": {"profiles": [{"name": "submitted-secret-invalid-profile!"}]},
        },
    )
    assert response.status_code == 400
    assert "submitted-config-password" not in response.text
    assert "submitted-secret-invalid-profile" not in response.text
    assert all(set(item) == {"type", "loc", "msg"} for item in response.json()["detail"])


def test_value_error_does_not_echo_exception_or_cause(tmp_path: Path) -> None:
    client = _client(tmp_path)

    @client.app.get("/test-auth-value-error")
    def failure() -> None:
        raise ValueError("new-unconfigured-password-in-exception")

    response = client.get("/test-auth-value-error")
    assert response.status_code == 400
    assert "new-unconfigured-password" not in response.text


def test_validation_error_context_never_serializes_exception_objects(tmp_path: Path) -> None:
    client = _client(tmp_path)

    @client.app.get("/test-auth-validation-error")
    def failure() -> None:
        AppConfig.model_validate({"upstream": {"profiles": [{"name": "secret-profile!"}]}})

    response = client.get("/test-auth-validation-error")
    assert response.status_code == 400
    assert "secret-profile" not in response.text
    assert "ctx" not in response.text
    assert "input" not in response.text
