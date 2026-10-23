from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.config.loader import load_config, load_yaml_file
from kornode.services.admin_totp import AdminTotpService
from kornode.services.password_hash import verify_password

SECRET = "JBSWY3DPEHPK3PXP"
REPLACEMENT_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _code(client: TestClient, secret: str) -> str:
    return AdminTotpService(client.app.state.config)._code_at(secret, int(time.time()) // 30)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("action", ["password", "confirm", "disable"])
def test_auth_mutation_keeps_symlink_environment(
    tmp_path: Path, enabled: bool, action: str
) -> None:
    target = tmp_path / "config.yaml"
    target.write_text(
        yaml.safe_dump(
            {
                "system": {
                    key: str(tmp_path / key)
                    for key in ("data_dir", "generated_dir", "log_dir", "secrets_dir")
                },
                "web": {
                    "admin_password": "${SECRET:ADMIN_PASSWORD}",
                    "admin_totp_secret": "${SECRET:ADMIN_TOTP_SECRET}",
                },
            }
        )
    )
    target.with_name(".env").write_text(
        "ADMIN_PASSWORD=target-password\nADMIN_TOTP_SECRET=KRSXG5DSNFXGOIDB\n"
        "KORNODE_WEB__ADMIN_TOTP_ENABLED=false\n"
    )
    supplied = tmp_path / "supplied"
    supplied.mkdir()
    alias = supplied / "config.yaml"
    alias.symlink_to(target)
    alias.with_name(".env").write_text(
        f"ADMIN_PASSWORD=alias-password\nADMIN_TOTP_SECRET={SECRET}\n"
        f"KORNODE_WEB__ADMIN_TOTP_ENABLED={str(enabled).lower()}\n"
    )
    client = TestClient(create_app(config_path=alias), base_url="https://testserver")
    login_payload = {"username": "admin", "password": "alias-password"}
    if enabled:
        login_payload["totp_code"] = _code(client, SECRET)
    login = client.post("/api/auth/login", json=login_payload)
    assert login.status_code == 200, login.text
    old_cookie = client.cookies.get("kornode_session")
    payload = {"current_password": "alias-password"}
    if enabled:
        payload["totp_code"] = _code(client, SECRET)
    if action == "password":
        endpoint = "/api/auth/password"
        payload["new_password"] = "replacement-password"
    else:
        endpoint = f"/api/auth/totp/{action}"
        if action == "confirm":
            payload.update(secret=REPLACEMENT_SECRET, code=_code(client, REPLACEMENT_SECRET))
    response = client.post(
        endpoint,
        headers={"X-Kornode-CSRF": login.json()["csrf_token"]},
        json=payload,
    )
    assert response.status_code == 200, response.text
    assert response.json()["reauthentication_required"] is True
    assert alias.is_symlink()
    assert client.app.state.auth_sessions.get(old_cookie) is None
    reloaded = load_config(alias)
    assert client.app.state.config == reloaded
    raw = load_yaml_file(target)
    if action == "password":
        assert raw["web"]["admin_password"] is None
        assert verify_password("replacement-password", reloaded.web.admin_password_hash)
        assert reloaded.web.admin_totp_enabled is enabled
        assert reloaded.web.admin_totp_secret == SECRET
        assert raw["web"]["admin_totp_secret"] == "${SECRET:ADMIN_TOTP_SECRET}"
    else:
        assert raw["web"]["admin_password"] == "${SECRET:ADMIN_PASSWORD}"
        assert reloaded.web.admin_password == "alias-password"
        assert reloaded.web.admin_totp_enabled is (action == "confirm")
        assert reloaded.web.admin_totp_secret == (
            REPLACEMENT_SECRET if action == "confirm" else None
        )
    fresh = {
        "username": "admin",
        "password": ("replacement-password" if action == "password" else "alias-password"),
    }
    if reloaded.web.admin_totp_enabled:
        fresh["totp_code"] = _code(client, reloaded.web.admin_totp_secret)
    assert client.post("/api/auth/login", json=fresh).status_code == 200
