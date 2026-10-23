from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app


@pytest.fixture(autouse=True)
def _stub_qrencode(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path_factory.mktemp("bin")
    stub = bin_dir / "qrencode"
    stub.write_text("#!/bin/sh\ncat >/dev/null\necho '<svg></svg>'\n", encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")


def _totp_code(secret: str, at: float | None = None) -> str:
    counter = int(at if at is not None else time.time()) // 30
    padded = secret.upper()
    padded += "=" * (-len(padded) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % 1_000_000).zfill(6)


def _client(config_path: Path, tmp_path: Path) -> TestClient:
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  log_dir: {tmp_path}/logs
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
web:
  enabled: true
  admin_password: secret
""",
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=config_path), base_url="https://testserver")


def test_totp_setup_confirm_and_login_with_code(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    setup = client.post(
        "/api/auth/totp/setup",
        auth=("admin", "secret"),
        json={"current_password": "secret"},
    )
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/")

    confirm = client.post(
        "/api/auth/totp/confirm",
        auth=("admin", "secret"),
        json={"secret": secret, "code": _totp_code(secret), "current_password": "secret"},
    )
    assert confirm.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["web"]["admin_totp_enabled"] is True
    assert saved["web"]["admin_totp_secret"] == secret

    login_without_code = client.post(
        "/api/auth/login", json={"username": "admin", "password": "secret"}
    )
    assert login_without_code.status_code == 401
    assert login_without_code.json()["detail"] == "totp_code_required"

    login_wrong_code = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "secret", "totp_code": "000000"},
    )
    assert login_wrong_code.status_code == 401
    assert login_wrong_code.json()["detail"] == "invalid_totp_code"

    login_with_code = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "secret", "totp_code": _totp_code(secret)},
    )
    assert login_with_code.status_code == 200
    assert login_with_code.cookies.get("kornode_session")


def test_totp_disable_removes_secret_and_stops_requiring_code(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    secret = client.post(
        "/api/auth/totp/setup",
        auth=("admin", "secret"),
        json={"current_password": "secret"},
    ).json()["secret"]
    client.post(
        "/api/auth/totp/confirm",
        auth=("admin", "secret"),
        json={"secret": secret, "code": _totp_code(secret), "current_password": "secret"},
    )
    assert client.get("/api/auth/totp/status", auth=("admin", "secret")).status_code == 401
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "secret", "totp_code": _totp_code(secret)},
    )
    assert login.status_code == 200
    assert client.get("/api/auth/totp/status").json() == {"enabled": True}
    old_token = client.cookies.get("kornode_session")
    csrf = {"X-Kornode-CSRF": login.json()["csrf_token"]}
    missing_code = client.post(
        "/api/auth/totp/disable", headers=csrf, json={"current_password": "secret"}
    )
    assert missing_code.status_code == 401
    disable = client.post(
        "/api/auth/totp/disable",
        headers=csrf,
        json={"current_password": "secret", "totp_code": _totp_code(secret)},
    )
    assert client.app.state.auth_sessions.get(old_token) is None
    assert not client.cookies.get("kornode_session")
    assert disable.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["web"]["admin_totp_enabled"] is False
    assert saved["web"]["admin_totp_secret"] is None

    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert login.status_code == 200


def test_totp_enable_revokes_existing_password_only_sessions(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)
    other = TestClient(client.app, base_url="https://testserver")
    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert login.status_code == 200
    assert (
        other.post("/api/auth/login", json={"username": "admin", "password": "secret"}).status_code
        == 200
    )
    csrf = {"X-Kornode-CSRF": login.json()["csrf_token"]}
    old_cookie = client.cookies.get("kornode_session")
    setup = client.post("/api/auth/totp/setup", headers=csrf, json={"current_password": "secret"})
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    confirm = client.post(
        "/api/auth/totp/confirm",
        headers=csrf,
        json={"current_password": "secret", "secret": secret, "code": _totp_code(secret)},
    )
    assert confirm.status_code == 200
    assert confirm.json()["reauthentication_required"] is True
    assert not client.cookies.get("kornode_session")
    assert client.app.state.auth_sessions.get(old_cookie) is None
    assert other.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", auth=("admin", "secret")).status_code == 401


@pytest.mark.parametrize("action", ["setup", "confirm", "disable"])
def test_totp_mutations_require_password_and_current_factor(tmp_path: Path, action: str) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    secret = client.post(
        "/api/auth/totp/setup", auth=("admin", "secret"), json={"current_password": "secret"}
    ).json()["secret"]
    assert (
        client.post(
            "/api/auth/totp/confirm",
            auth=("admin", "secret"),
            json={"current_password": "secret", "secret": secret, "code": _totp_code(secret)},
        ).status_code
        == 200
    )
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "secret", "totp_code": _totp_code(secret)},
    )
    assert login.status_code == 200
    csrf = {"X-Kornode-CSRF": login.json()["csrf_token"]}
    payload = {"current_password": "wrong"}
    if action == "confirm":
        replacement_secret = "JBSWY3DPEHPK3PXP"
        payload.update(secret=replacement_secret, code=_totp_code(replacement_secret))
    endpoint = f"/api/auth/totp/{action}"
    assert client.post(endpoint, headers=csrf, json=payload).status_code == 401
    payload["current_password"] = "secret"
    missing = client.post(endpoint, headers=csrf, json=payload)
    assert missing.status_code == 401
    assert missing.json()["detail"] == "totp_code_required"
    payload["totp_code"] = "not-a-code"
    rejected = client.post(endpoint, headers=csrf, json=payload)
    assert rejected.status_code == 401
    assert rejected.json()["detail"] == "invalid_totp_code"
    saved = yaml.safe_load(config_path.read_text())
    assert saved["web"]["admin_totp_enabled"] is True
    assert saved["web"]["admin_totp_secret"] == secret
    payload["totp_code"] = _totp_code(secret)
    assert client.post(endpoint, headers=csrf, json=payload).status_code == 200
