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

    setup = client.post("/api/auth/totp/setup", auth=("admin", "secret"))
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/")

    confirm = client.post(
        "/api/auth/totp/confirm",
        auth=("admin", "secret"),
        json={"secret": secret, "code": _totp_code(secret)},
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

    secret = client.post("/api/auth/totp/setup", auth=("admin", "secret")).json()["secret"]
    client.post(
        "/api/auth/totp/confirm",
        auth=("admin", "secret"),
        json={"secret": secret, "code": _totp_code(secret)},
    )
    assert client.get("/api/auth/totp/status", auth=("admin", "secret")).json() == {
        "enabled": True
    }

    disable = client.post("/api/auth/totp/disable", auth=("admin", "secret"))
    assert disable.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["web"]["admin_totp_enabled"] is False
    assert saved["web"]["admin_totp_secret"] is None

    login = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert login.status_code == 200
