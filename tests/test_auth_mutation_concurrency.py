from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml
from fastapi import Request
from fastapi.testclient import TestClient
from httpx import Response

from kornode.api import routes_auth
from kornode.api.app import create_app
from kornode.api.auth import SESSION_COOKIE
from kornode.config.loader import deep_merge
from kornode.services.admin_totp import AdminTotpService
from kornode.services.config_store import mutate_config
from kornode.services.password_hash import verify_password

INITIAL_SECRET = "JBSWY3DPEHPK3PXP"
STALE_SECRET = "KRSXG5DSNFXGOIDB"
WINNER_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _clients(tmp_path: Path, *, totp: bool = False) -> tuple[TestClient, TestClient, Path]:
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
                    "admin_totp_secret": INITIAL_SECRET if totp else None,
                },
            }
        ),
        encoding="utf-8",
    )
    app = create_app(config_path=path)
    return (
        TestClient(app, base_url="https://testserver"),
        TestClient(app, base_url="https://testserver"),
        path,
    )


def _code(client: TestClient, secret: str, step: int = 0) -> str:
    return AdminTotpService(client.app.state.config)._code_at(
        secret, int(time.time()) // 30 + step
    )


def _login(client: TestClient, *, totp: bool = False, step: int = 0) -> str:
    # Sign-in codes are single-use: a second browser signs in with the next step's code.
    payload = {"username": "admin", "password": "secret"}
    if totp:
        payload["totp_code"] = _code(client, INITIAL_SECRET, step)
    response = client.post("/api/auth/login", json=payload)
    assert response.status_code == 200, response.text
    return str(response.json()["csrf_token"])


def _payload(client: TestClient, action: str, *, totp: bool = False) -> dict[str, str]:
    result = {"current_password": "secret"}
    if totp:
        result["totp_code"] = _code(client, INITIAL_SECRET)
    if action == "password":
        result["new_password"] = "stale-unapproved-password"
    elif action == "confirm":
        result.update(secret=STALE_SECRET, code=_code(client, STALE_SECRET))
    return result


def _race_after_reauthentication(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    path: Path,
    action: str,
    csrf: str,
    payload: dict[str, str],
    winner: Callable[[], None],
) -> tuple[Response, bytes]:
    reauthenticated = threading.Event()
    resume = threading.Event()
    original = routes_auth._reauthenticate

    def pause(
        request: Request, payload: routes_auth.ReauthenticateRequest
    ) -> routes_auth._ReauthenticationProof:
        proof = original(request, payload)
        if request.headers.get("x-test-pause") == "yes":
            reauthenticated.set()
            assert resume.wait(timeout=10), "stale request was not resumed"
        return proof

    monkeypatch.setattr(routes_auth, "_reauthenticate", pause)
    endpoint = "/api/auth/password" if action == "password" else f"/api/auth/totp/{action}"
    with ThreadPoolExecutor(max_workers=2) as executor:
        stale = executor.submit(
            client.post,
            endpoint,
            headers={"X-Kornode-CSRF": csrf, "X-Test-Pause": "yes"},
            json=payload,
        )
        try:
            assert reauthenticated.wait(timeout=10), "stale request did not reauthenticate"
            executor.submit(winner).result(timeout=10)
            committed_source = path.read_bytes()
        finally:
            resume.set()
        response = stale.result(timeout=10)
    return response, committed_source


@pytest.mark.parametrize("action", ["disable", "password", "confirm"])
def test_mfa_enable_rejects_already_reauthenticated_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    stale, other, path = _clients(tmp_path)
    csrf = _login(stale)
    other_csrf = _login(other)
    old_cookie = stale.cookies.get(SESSION_COOKIE)

    def enable() -> None:
        response = other.post(
            "/api/auth/totp/confirm",
            headers={"X-Kornode-CSRF": other_csrf},
            json={
                "current_password": "secret",
                "secret": WINNER_SECRET,
                "code": _code(other, WINNER_SECRET),
            },
        )
        assert response.status_code == 200, response.text

    response, committed_source = _race_after_reauthentication(
        monkeypatch, stale, path, action, csrf, _payload(stale, action), enable
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "authentication_changed"
    assert path.read_bytes() == committed_source
    assert stale.app.state.config.web.admin_totp_enabled is True
    assert stale.app.state.config.web.admin_totp_secret == WINNER_SECRET
    assert stale.app.state.config.web.admin_password == "secret"
    assert stale.app.state.auth_sessions.get(old_cookie) is None
    login = other.post(
        "/api/auth/login",
        json={"username": "admin", "password": "secret", "totp_code": _code(other, WINNER_SECRET)},
    )
    assert login.status_code == 200, login.text


@pytest.mark.parametrize("action", ["disable", "password", "confirm"])
@pytest.mark.parametrize("totp", [False, True])
def test_password_change_rejects_already_reauthenticated_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str, totp: bool
) -> None:
    stale, other, path = _clients(tmp_path, totp=totp)
    csrf = _login(stale, totp=totp)
    other_csrf = _login(other, totp=totp, step=1)
    old_cookie = stale.cookies.get(SESSION_COOKIE)

    def change_password() -> None:
        payload = {"current_password": "secret", "new_password": "approved-password"}
        if totp:
            payload["totp_code"] = _code(other, INITIAL_SECRET)
        response = other.post(
            "/api/auth/password",
            headers={"X-Kornode-CSRF": other_csrf},
            json=payload,
        )
        assert response.status_code == 200, response.text

    response, committed_source = _race_after_reauthentication(
        monkeypatch, stale, path, action, csrf, _payload(stale, action, totp=totp), change_password
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "authentication_changed"
    assert path.read_bytes() == committed_source
    web = stale.app.state.config.web
    assert web.admin_password is None
    assert verify_password("approved-password", web.admin_password_hash)
    assert not verify_password("stale-unapproved-password", web.admin_password_hash)
    assert web.admin_totp_enabled is totp
    assert web.admin_totp_secret == (INITIAL_SECRET if totp else None)
    assert stale.app.state.auth_sessions.get(old_cookie) is None


@pytest.mark.parametrize("action", ["disable", "password", "confirm"])
@pytest.mark.parametrize("revocation", ["logout", "all"])
def test_revocation_rejects_already_reauthenticated_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str, revocation: str
) -> None:
    stale, other, path = _clients(tmp_path, totp=True)
    csrf = _login(stale, totp=True)
    old_cookie = stale.cookies.get(SESSION_COOKIE)
    original_config = stale.app.state.config

    def revoke() -> None:
        if revocation == "logout":
            response = other.post(
                "/api/auth/logout", headers={"Cookie": f"{SESSION_COOKIE}={old_cookie}"}
            )
            assert response.status_code == 200, response.text
        else:
            stale.app.state.auth_sessions.revoke_all()

    response, committed_source = _race_after_reauthentication(
        monkeypatch, stale, path, action, csrf, _payload(stale, action, totp=True), revoke
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "authentication_changed"
    assert path.read_bytes() == committed_source
    assert stale.app.state.config is original_config
    assert stale.app.state.auth_sessions.get(old_cookie) is None


@pytest.mark.parametrize("action", ["disable", "password", "confirm"])
def test_auth_change_and_restore_does_not_restore_old_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    stale, other, path = _clients(tmp_path)
    csrf = _login(stale)
    other_csrf = _login(other)
    original_web = stale.app.state.config.web.model_dump()

    def enable_and_disable() -> None:
        enabled = other.post(
            "/api/auth/totp/confirm",
            headers={"X-Kornode-CSRF": other_csrf},
            json={
                "current_password": "secret",
                "secret": WINNER_SECRET,
                "code": _code(other, WINNER_SECRET),
            },
        )
        assert enabled.status_code == 200, enabled.text
        login = other.post(
            "/api/auth/login",
            json={
                "username": "admin",
                "password": "secret",
                "totp_code": _code(other, WINNER_SECRET),
            },
        )
        assert login.status_code == 200, login.text
        disabled = other.post(
            "/api/auth/totp/disable",
            headers={"X-Kornode-CSRF": login.json()["csrf_token"]},
            json={"current_password": "secret", "totp_code": _code(other, WINNER_SECRET)},
        )
        assert disabled.status_code == 200, disabled.text
        assert other.app.state.config.web.model_dump() == original_web

    response, committed_source = _race_after_reauthentication(
        monkeypatch, stale, path, action, csrf, _payload(stale, action), enable_and_disable
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "authentication_changed"
    assert path.read_bytes() == committed_source
    assert stale.app.state.config.web.model_dump() == original_web


@pytest.mark.parametrize("action", ["disable", "password", "confirm"])
def test_latest_disk_auth_is_checked_even_without_api_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    stale, _other, path = _clients(tmp_path)
    csrf = _login(stale)
    original_config = stale.app.state.config
    generation = stale.app.state.auth_sessions.generation

    def external_change() -> None:
        mutate_config(
            path,
            lambda raw: deep_merge(
                raw,
                {
                    "web": {
                        "admin_totp_enabled": True,
                        "admin_totp_secret": WINNER_SECRET,
                    }
                },
            ),
            write_rendered=False,
        )
        assert stale.app.state.config is original_config
        assert stale.app.state.auth_sessions.generation == generation

    response, committed_source = _race_after_reauthentication(
        monkeypatch, stale, path, action, csrf, _payload(stale, action), external_change
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "authentication_changed"
    assert path.read_bytes() == committed_source
    assert yaml.safe_load(committed_source)["web"]["admin_totp_enabled"] is True
    assert stale.app.state.config is original_config


@pytest.mark.parametrize("action", ["disable", "password", "confirm"])
def test_unrelated_config_commit_does_not_invalidate_verified_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    stale, other, path = _clients(tmp_path, totp=True)
    csrf = _login(stale, totp=True)
    other_csrf = _login(other, totp=True, step=1)

    def save_timezone() -> None:
        response = other.patch(
            "/api/config",
            headers={"X-Kornode-CSRF": other_csrf},
            json={"patch": {"system": {"timezone": "Europe/Moscow"}}, "write_rendered": False},
        )
        assert response.status_code == 200, response.text

    response, _committed_source = _race_after_reauthentication(
        monkeypatch, stale, path, action, csrf, _payload(stale, action, totp=True), save_timezone
    )
    assert response.status_code == 200, response.text
    assert stale.app.state.config.system.timezone == "Europe/Moscow"
    assert yaml.safe_load(path.read_bytes())["system"]["timezone"] == "Europe/Moscow"
