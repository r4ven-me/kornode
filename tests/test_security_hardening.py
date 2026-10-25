"""Regression tests for the 2026-10-24 security review."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from kornode import cli
from kornode.api.app import create_app
from kornode.config.models import AppConfig
from kornode.config.reserved import is_reserved_username
from kornode.net.model import DestSet
from kornode.services.admin_totp import AdminTotpService
from kornode.services.doctor import DoctorService
from kornode.services.password_hash import hash_password
from kornode.services.password_policy import validate_new_admin_password
from kornode.services.users import UserService

ROOT = Path(__file__).resolve().parents[1]
STRONG = "a-long-enough-passphrase"


def _write(tmp_path: Path, web: str = "") -> Path:
    config_path = tmp_path / "config.yaml"
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
{web}
""",
        encoding="utf-8",
    )
    return config_path


def _client(tmp_path: Path, web: str = "") -> TestClient:
    config_path = _write(tmp_path, web)
    return TestClient(create_app(config_path=config_path), base_url="https://testserver")


def _totp_code(secret: str, at: float | None = None) -> str:
    counter = int(at if at is not None else time.time()) // 30
    padded = secret.upper() + "=" * (-len(secret) % 8)
    digest = hmac.new(base64.b32decode(padded), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 1_000_000).zfill(6)


# 1. admin password -----------------------------------------------------------------------


@pytest.mark.parametrize("name", ["compose.web.yaml", "compose.proxy.yaml"])
def test_compose_requires_the_admin_password(name: str) -> None:
    spec = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))
    env = spec["services"]["kornode"]["environment"]

    assert (
        env["KORNODE_WEB__ADMIN_PASSWORD"]
        == "${KORNODE_ADMIN_PASSWORD:?set KORNODE_ADMIN_PASSWORD}"
    )
    assert "change-me" not in (ROOT / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", [".env.example", "examples/.env.example"])
def test_env_example_ships_no_default_admin_password(name: str) -> None:
    lines = (ROOT / name).read_text(encoding="utf-8").splitlines()

    assert "KORNODE_ADMIN_PASSWORD=" in lines


@pytest.mark.parametrize(
    "password", ["short", "elevenchars", "change-me", "ChAnGe-Me", "admin", "password", "kornode"]
)
def test_new_admin_password_policy_rejects_weak_values(password: str) -> None:
    with pytest.raises(ValueError):
        validate_new_admin_password(password)


def test_new_admin_password_policy_accepts_a_long_password() -> None:
    assert validate_new_admin_password(STRONG) == STRONG


def test_password_change_api_enforces_the_policy(tmp_path: Path) -> None:
    client = _client(tmp_path)
    for weak in ("short", "change-me", "x" * 11):
        response = client.post(
            "/api/auth/password",
            auth=("admin", "secret"),
            json={"current_password": "secret", "new_password": weak},
        )
        assert response.status_code == 422, weak
    response = client.post(
        "/api/auth/password",
        auth=("admin", "secret"),
        json={"current_password": "secret", "new_password": STRONG},
    )
    assert response.status_code == 200


def test_korctl_hash_password_rejects_weak_passwords() -> None:
    runner = CliRunner()
    weak = runner.invoke(cli.app, ["web", "hash-password"], input="change-me\nchange-me\n")
    strong = runner.invoke(cli.app, ["web", "hash-password"], input=f"{STRONG}\n{STRONG}\n")

    assert weak.exit_code == 1
    assert "scrypt$" not in weak.output
    assert strong.exit_code == 0
    assert "scrypt$" in strong.output


def _doctor_config(tmp_path: Path, **web: object) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
                "log_dir": tmp_path / "logs",
            },
            "web": {"enabled": bool(web), **web},
        }
    )


@pytest.mark.parametrize(
    "web",
    [{"admin_password": "change-me"}, {"admin_password_hash": hash_password("change-me")}],
)
def test_doctor_warns_about_a_placeholder_admin_password(
    tmp_path: Path, web: dict[str, str]
) -> None:
    result = DoctorService(_doctor_config(tmp_path, **web))._check_admin_password()

    assert result.ok  # a warning, not a failure: existing hubs keep working
    assert "placeholder" in result.stderr


def test_doctor_is_quiet_for_a_real_admin_password(tmp_path: Path) -> None:
    for web in ({"admin_password": STRONG}, {"admin_password_hash": hash_password(STRONG)}):
        result = DoctorService(_doctor_config(tmp_path, **web))._check_admin_password()
        assert result.ok
        assert result.stderr == ""


def test_a_placeholder_admin_password_still_loads(tmp_path: Path) -> None:
    assert _doctor_config(tmp_path, admin_password="change-me").web.admin_password == "change-me"


# 2. web settings reauthentication ------------------------------------------------------------


def _web_payload(client: TestClient, **overrides: Any) -> dict[str, Any]:
    web = client.app.state.config.web  # type: ignore[attr-defined]
    base: dict[str, Any] = {
        "enabled": True,
        "listen": web.listen,
        "port": web.port,
        "tls": web.tls,
        "allow_insecure_http": web.allow_insecure_http,
        "trusted_proxies": list(web.trusted_proxies),
        "admin_user": web.admin_user,
        "terminal_enabled": web.terminal_enabled,
        "terminal_idle_timeout": web.terminal_idle_timeout,
        "terminal_max_sessions": web.terminal_max_sessions,
        "client_sync_enabled": web.client_sync_enabled,
        "session_lifetime": web.session_lifetime,
        "session_cookie_secure": web.session_cookie_secure,
    }
    return {**base, **overrides}


@pytest.mark.parametrize(
    "change",
    [
        {"terminal_enabled": True},
        {"admin_user": "root"},
        {"trusted_proxies": ["10.0.0.1"]},
        {"session_cookie_secure": False},
    ],
)
def test_sensitive_web_settings_need_reauthentication(
    tmp_path: Path, change: dict[str, Any]
) -> None:
    client = _client(tmp_path)
    before = client.app.state.config.web.model_dump()  # type: ignore[attr-defined]

    missing = client.post(
        "/api/web-config/settings", auth=("admin", "secret"), json=_web_payload(client, **change)
    )
    wrong = client.post(
        "/api/web-config/settings",
        auth=("admin", "secret"),
        json=_web_payload(client, current_password="nope", **change),
    )

    assert missing.status_code == 403
    assert missing.json()["detail"]["error"] == "reauthentication_required"
    assert wrong.status_code == 401
    assert client.app.state.config.web.model_dump() == before  # type: ignore[attr-defined]
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    for key in change:
        assert key not in saved["web"]


def test_sensitive_web_settings_apply_with_the_current_password(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/api/web-config/settings",
        auth=("admin", "secret"),
        json=_web_payload(
            client, terminal_enabled=True, trusted_proxies=["10.0.0.1"], current_password="secret"
        ),
    )

    assert response.status_code == 200
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert saved["web"]["terminal_enabled"] is True
    assert saved["web"]["trusted_proxies"] == ["10.0.0.1"]
    assert "current_password" not in saved["web"]
    assert "current_password" not in response.text


def test_sensitive_web_settings_need_the_current_totp_when_enabled(tmp_path: Path) -> None:
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    client = _client(tmp_path, f"  admin_totp_enabled: true\n  admin_totp_secret: {secret}")
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "secret", "totp_code": _totp_code(secret)},
    )
    assert login.status_code == 200
    csrf = {"X-Kornode-CSRF": login.json()["csrf_token"]}
    payload = _web_payload(client, terminal_enabled=True, current_password="secret")

    no_code = client.post("/api/web-config/settings", headers=csrf, json=payload)
    # The login consumed this step's code; the next step's code is still in the window.
    ok = client.post(
        "/api/web-config/settings",
        headers=csrf,
        json={**payload, "totp_code": _totp_code(secret, time.time() + 30)},
    )

    assert no_code.status_code == 401
    assert no_code.json()["detail"] == "totp_code_required"
    assert ok.status_code == 200


def test_non_sensitive_web_settings_need_no_reauthentication(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/api/web-config/settings",
        auth=("admin", "secret"),
        json=_web_payload(client, session_lifetime=7200, terminal_enabled=False),
    )

    assert response.status_code == 200
    # Turning the terminal off, or the cookie flag on, is never gated.
    hardened = client.post(
        "/api/web-config/settings",
        auth=("admin", "secret"),
        json=_web_payload(client, session_cookie_secure=True),
    )
    assert hardened.status_code == 200


# 4. trailing newline -------------------------------------------------------------------------


def test_trailing_newline_is_rejected_in_names(tmp_path: Path) -> None:
    config = _doctor_config(tmp_path)
    service = UserService(config)

    for bad in ("alice\n", "agents\n"):
        with pytest.raises(ValueError):
            service.validate_username(bad)
        with pytest.raises(ValueError):
            service.validate_group_name(bad)
    with pytest.raises(ValueError):
        service.validate_username("agent-3\n")
    assert is_reserved_username("agent-3\n") is False  # not a reserved name, just invalid
    assert service.validate_group_name("staff") == "staff"


def test_trailing_newline_is_rejected_in_config_models(tmp_path: Path) -> None:
    from pydantic import ValidationError

    for patch in (
        {"upstreams": {"corp\n": {"type": "openconnect", "server": "vpn.example.com"}}},
        {"domains": {"allow": ["example.com\n"]}},
    ):
        with pytest.raises((ValidationError, ValueError)):
            AppConfig.model_validate(
                {
                    "system": {
                        "data_dir": tmp_path,
                        "generated_dir": tmp_path,
                        "secrets_dir": tmp_path,
                        "log_dir": tmp_path,
                    },
                    **patch,
                }
            )


def test_trailing_newline_is_rejected_in_net_domains() -> None:
    from pydantic import ValidationError

    assert DestSet.model_validate({"domains": ["example.com"]}).domains == ("example.com",)
    with pytest.raises(ValidationError):
        DestSet.model_validate({"domains": ["example.com\n"]})


# 5. OTP delivery test never forwards a stored secret to a new target ---------------------------


def _otp_client(tmp_path: Path) -> TestClient:
    web = """
auth:
  otp:
    smtp_host: mail.example.com
    smtp_port: 587
    smtp_username: mailer
    smtp_password: stored-smtp-secret
    smtp_from: vpn@example.com
    smtp_test_recipient: admin@example.com
    telegram_bot_token: stored-bot-token
    telegram_chat_id: "111"
"""
    path = _write(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + web, encoding="utf-8")
    return TestClient(create_app(config_path=path), base_url="https://testserver")


def test_otp_email_test_refuses_to_send_the_stored_password_to_a_new_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[tuple[str, str | None]] = []

    def fake_send(self: Any) -> None:
        sent.append((self.settings.smtp_host, self.settings.smtp_password))

    monkeypatch.setattr("kornode.api.routes_server.OtpDeliveryService.send_test_email", fake_send)
    client = _otp_client(tmp_path)

    for change in ({"otp_smtp_host": "evil.example.net"}, {"otp_smtp_port": 25}):
        response = client.post(
            "/api/server/auth-settings/test-email", auth=("admin", "secret"), json=change
        )
        assert response.status_code == 400, change
        assert "smtp_password" in response.json()["detail"]
        assert "stored-smtp-secret" not in response.text
    assert sent == []

    # Entering the secret explicitly is allowed; so is testing the saved target.
    explicit = client.post(
        "/api/server/auth-settings/test-email",
        auth=("admin", "secret"),
        json={"otp_smtp_host": "other.example.org", "otp_smtp_password": "typed-now"},
    )
    unchanged = client.post(
        "/api/server/auth-settings/test-email",
        auth=("admin", "secret"),
        json={"otp_smtp_host": "mail.example.com"},
    )
    assert explicit.status_code == 200
    assert unchanged.status_code == 200
    assert sent == [("other.example.org", "typed-now"), ("mail.example.com", "stored-smtp-secret")]


def test_otp_telegram_test_refuses_to_reuse_the_stored_token_for_a_new_chat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[tuple[str | None, str | None]] = []

    def fake_send(self: Any) -> None:
        sent.append((self.settings.telegram_chat_id, self.settings.telegram_bot_token))

    monkeypatch.setattr(
        "kornode.api.routes_server.OtpDeliveryService.send_test_telegram", fake_send
    )
    client = _otp_client(tmp_path)

    refused = client.post(
        "/api/server/auth-settings/test-telegram",
        auth=("admin", "secret"),
        json={"otp_telegram_chat_id": "999"},
    )
    explicit = client.post(
        "/api/server/auth-settings/test-telegram",
        auth=("admin", "secret"),
        json={"otp_telegram_chat_id": "999", "otp_telegram_bot_token": "typed-token"},
    )

    assert refused.status_code == 400
    assert "stored-bot-token" not in refused.text
    assert explicit.status_code == 200
    assert sent == [("999", "typed-token")]


# 6. TOTP replay -----------------------------------------------------------------------------


def test_totp_code_is_single_use(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kornode.api.auth import AuthSessionRegistry

    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXA"
    service = AdminTotpService(_doctor_config(tmp_path))
    registry = AuthSessionRegistry()
    now = 1_900_000_000.0
    monkeypatch.setattr(time, "time", lambda: now)

    def sign_in(code: str) -> bool:
        step = service.matching_step(secret, code)
        return step is not None and registry.accept_totp_step(step)

    code = _totp_code(secret, now)
    assert sign_in(code) is True
    assert sign_in(code) is False
    # The check without consumption (setup confirmation, reauthentication) stays repeatable.
    assert service.verify_code(secret, code) is True
    # An older step inside the window is not accepted after a newer one was used...
    assert sign_in(_totp_code(secret, now - 30)) is False
    # ...a newer one is.
    assert sign_in(_totp_code(secret, now + 30)) is True


def test_login_rejects_a_replayed_totp_code(tmp_path: Path) -> None:
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXC"
    client = _client(tmp_path, f"  admin_totp_enabled: true\n  admin_totp_secret: {secret}")
    body = {"username": "admin", "password": "secret", "totp_code": _totp_code(secret)}

    first = client.post("/api/auth/login", json=body)
    replay = client.post("/api/auth/login", json=body)

    assert first.status_code == 200
    assert replay.status_code == 401
    assert replay.json()["detail"] == "invalid_totp_code"


# 7. no schema/docs endpoints ------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/api/openapi.json"])
def test_api_schema_and_docs_are_not_served(tmp_path: Path, path: str) -> None:
    client = _client(tmp_path)

    assert client.get(path, auth=("admin", "secret")).status_code == 404
    assert client.get(path).status_code in {401, 404}
