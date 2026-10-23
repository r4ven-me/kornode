"""Endpoint regressions for structured GUI edits; no core config/auth fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.config.loader import load_config
from kornode.services.config import ConfigService
from kornode.services.server import ServerService

AUTH = ("admin", "secret")


@pytest.fixture
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, Path]:
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "system": {
                    key: str(tmp_path / key)
                    for key in ("data_dir", "log_dir", "generated_dir", "secrets_dir")
                },
                "web": {"enabled": True, "admin_password": "secret"},
                "server": {"enabled": False},
            }
        )
    )
    monkeypatch.setattr(ConfigService, "write_rendered_files", lambda *_: [])
    monkeypatch.setattr(ServerService, "apply_config_change", lambda *_: None)
    return TestClient(create_app(config_path=path)), path


def _update(path: Path, **blocks: object) -> None:
    raw = yaml.safe_load(path.read_text())
    raw.update(blocks)
    path.write_text(yaml.safe_dump(raw))


def _profiles() -> list[dict[str, object]]:
    return [
        {
            "name": "first",
            "server": "vpn.example.com",
            "username": "first-user",
            "password": "${SECRET:UP_PASS}",
            "cert_pass": "${SECRET:CERT_PASS}",
            "camouflage_secret": "${SECRET:CAMO}",
            "cert_file_base64": "${SECRET:CERT_DATA}",
            "key_file_base64": "${SECRET:KEY_DATA}",
        },
        {
            "name": "second",
            "server": "backup.example.com",
            "username": "backup-user",
            "password": "${SECRET:BACKUP}",
        },
    ]


def _secrets(path: Path, version: str = "one") -> None:
    path.with_name(".env").write_text(
        f"UP_PASS={version}-password\nCERT_PASS={version}-cert\nCAMO={version}-camo\n"
        f"BACKUP={version}-backup\nOIDC={version}-oidc\nSMTP={version}-smtp\n"
        f"TELEGRAM={version}-telegram\nCERT_DATA=Y2VydA==\nKEY_DATA=a2V5\n"
    )


@pytest.mark.parametrize("operation", ["toggle", "save", "delete-other"])
def test_upstream_edits_keep_raw_references_and_rotation(
    panel: tuple[TestClient, Path], operation: str
) -> None:
    client, path = panel
    _secrets(path)
    # Write after app startup: the mutation must read the latest raw collection,
    # not the app's stale resolved model.
    original = _profiles()
    _update(path, upstream={"profiles": original, "active_profile": "first"})
    if operation == "toggle":
        response = client.post(
            "/api/upstream/profiles/first/enabled", auth=AUTH, json={"enabled": False}
        )
    elif operation == "save":
        response = client.post(
            "/api/upstream/profiles",
            auth=AUTH,
            json={"name": "first", "server": "edited.example.com", "username": "first-user"},
        )
    else:
        response = client.delete("/api/upstream/profiles/second", auth=AUTH)
    assert response.status_code == 200, response.text
    saved = yaml.safe_load(path.read_text())["upstream"]["profiles"]
    for key in (
        "password",
        "cert_pass",
        "camouflage_secret",
        "cert_file_base64",
        "key_file_base64",
    ):
        assert saved[0][key] == original[0][key]
    if operation != "delete-other":
        assert saved[1] == original[1]
    assert "one-password" not in response.text
    assert "one-password" not in path.read_text()
    _secrets(path, "two")
    loaded = load_config(path)
    assert loaded.upstream.profiles[0].password == "two-password"
    assert loaded.upstream.profiles[0].cert_pass == "two-cert"
    assert loaded.upstream.profiles[0].camouflage_secret == "two-camo"


@pytest.mark.parametrize(
    "section,field,endpoint,payload",
    [
        ("upstream", "profiles", "/api/upstream/profiles/first/enabled", {"enabled": False}),
        (
            "identity",
            "oidc_providers",
            "/api/identity/oidc/providers",
            {"name": "first", "issuer_url": "https://sso.example.com", "client_id": "edited"},
        ),
    ],
)
def test_env_only_collection_keeps_refs_without_materializing_other_env(
    panel: tuple[TestClient, Path],
    monkeypatch: pytest.MonkeyPatch,
    section: str,
    field: str,
    endpoint: str,
    payload: dict[str, object],
) -> None:
    client, path = panel
    _secrets(path)
    items = (
        _profiles()
        if section == "upstream"
        else [
            {
                "name": "first",
                "issuer_url": "https://sso.example.com",
                "client_id": "vpn",
                "client_secret": "${SECRET:OIDC}",
            }
        ]
    )
    monkeypatch.setenv(f"KORNODE_{section.upper()}__{field.upper()}", json.dumps(items))
    monkeypatch.setenv("KORNODE_SYSTEM__TIMEZONE", "Europe/Moscow")
    response = client.post(endpoint, auth=AUTH, json=payload)
    assert response.status_code == 200, response.text
    saved = yaml.safe_load(path.read_text())
    secret = "password" if section == "upstream" else "client_secret"
    assert saved[section][field][0][secret] == items[0][secret]
    assert "timezone" not in saved["system"]
    _secrets(path, "two")
    loaded = load_config(path)
    effective = getattr(getattr(loaded, section), field)[0]
    assert getattr(effective, secret) == ("two-password" if section == "upstream" else "two-oidc")


def test_oidc_omitted_secret_is_preserved_and_explicit_null_removes_it(
    panel: tuple[TestClient, Path],
) -> None:
    client, path = panel
    _secrets(path)
    providers = [
        {
            "name": name,
            "issuer_url": "https://sso.example.com",
            "client_id": "vpn",
            "client_secret": "${SECRET:OIDC}",
        }
        for name in ("first", "second")
    ]
    _update(path, identity={"oidc_providers": providers})
    edit = {"name": "first", "issuer_url": "https://sso.example.com", "client_id": "edited"}
    response = client.post("/api/identity/oidc/providers", auth=AUTH, json=edit)
    assert response.status_code == 200, response.text
    assert "one-oidc" not in response.text
    saved = yaml.safe_load(path.read_text())["identity"]["oidc_providers"]
    assert [p["name"] for p in saved] == ["first", "second"]
    assert saved[0]["client_secret"] == "${SECRET:OIDC}"
    assert saved[1] == providers[1]
    _secrets(path, "two")
    assert load_config(path).identity.oidc_providers[0].client_secret == "two-oidc"
    response = client.post(
        "/api/identity/oidc/providers", auth=AUTH, json={**edit, "client_secret": None}
    )
    assert response.status_code == 200, response.text
    assert load_config(path).identity.oidc_providers[0].client_secret is None
    assert load_config(path).identity.oidc_providers[1].client_secret == "two-oidc"
    response = client.delete("/api/identity/oidc/providers/first", auth=AUTH)
    assert response.status_code == 200
    assert yaml.safe_load(path.read_text())["identity"]["oidc_providers"] == [providers[1]]


@pytest.mark.parametrize("value", [None, True, False])
def test_nullable_group_booleans_round_trip(
    panel: tuple[TestClient, Path], value: bool | None
) -> None:
    client, path = panel
    response = client.post(
        "/api/identity/groups",
        auth=AUTH,
        json={"name": "devops", "tunnel_all_dns": value, "no_udp": value},
    )
    assert response.status_code == 200, response.text
    group = response.json()["identity"]["group_policies"][0]
    assert group["tunnel_all_dns"] is value
    assert group["no_udp"] is value
    assert yaml.safe_load(path.read_text())["identity"]["group_policies"][0]["no_udp"] is value


@pytest.mark.parametrize("env_only", [False, True])
def test_otp_edits_preserve_refs_and_env_only_secrets(
    panel: tuple[TestClient, Path], monkeypatch: pytest.MonkeyPatch, env_only: bool
) -> None:
    client, path = panel
    _secrets(path)
    if env_only:
        monkeypatch.setenv("KORNODE_AUTH__OTP__SMTP_PASSWORD", "${SECRET:SMTP}")
        monkeypatch.setenv("KORNODE_AUTH__OTP__TELEGRAM_BOT_TOKEN", "${SECRET:TELEGRAM}")
    else:
        _update(
            path,
            auth={
                "otp": {
                    "smtp_password": "${SECRET:SMTP}",
                    "telegram_bot_token": "${SECRET:TELEGRAM}",
                }
            },
        )
    response = client.post(
        "/api/server/auth-settings",
        auth=AUTH,
        json={
            "otp_enabled": True,
            "otp_issuer": "Updated",
            "otp_smtp_password": None,
            "otp_telegram_bot_token": "",
        },
    )
    assert response.status_code == 200, response.text
    otp = yaml.safe_load(path.read_text())["auth"]["otp"]
    if env_only:
        assert "smtp_password" not in otp
        assert "telegram_bot_token" not in otp
    else:
        assert otp["smtp_password"] == "${SECRET:SMTP}"
        assert otp["telegram_bot_token"] == "${SECRET:TELEGRAM}"
    _secrets(path, "two")
    assert load_config(path).auth.otp.smtp_password == "two-smtp"
    assert load_config(path).auth.otp.telegram_bot_token == "two-telegram"


def test_control_settings_preserve_omitted_signing_key_path(
    panel: tuple[TestClient, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, path = panel
    signing_key = str(path.parent / "signing.pem")
    monkeypatch.setenv("SIGNING_PATH", signing_key)
    _update(path, control={"signing_key": "${SECRET:SIGNING_PATH}"})
    settings = {
        "enabled": True,
        "port": 9444,
        "long_poll_seconds": 100,
        "report_interval_seconds": 40,
        "offline_after_seconds": 120,
        "cert_lifetime_days": 60,
        "enroll_token_ttl_minutes": 30,
        "bundle_history": 10,
        "min_agent_version": "2.1.0",
    }
    response = client.post("/api/web-config/control-settings", auth=AUTH, json=settings)
    assert response.status_code == 200, response.text
    assert response.json()["control"] == {**settings, "signing_key": signing_key}
    assert response.json()["restart_required"] is True
    assert yaml.safe_load(path.read_text())["control"] == {
        **settings,
        "signing_key": "${SECRET:SIGNING_PATH}",
    }
    assert not Path(signing_key).exists()
    new_signing_key = path.parent / "new-location" / "signing.pem"
    changed = client.post(
        "/api/web-config/control-settings", auth=AUTH, json={"signing_key": str(new_signing_key)}
    )
    assert changed.status_code == 200
    assert changed.json()["control"]["signing_key"] == str(new_signing_key)
    assert not new_signing_key.exists()
    cleared = client.post("/api/web-config/control-settings", auth=AUTH, json={"signing_key": None})
    assert cleared.status_code == 200
    assert cleared.json()["control"]["signing_key"] is None
    assert yaml.safe_load(path.read_text())["control"]["signing_key"] is None
    default_key = path.parent / "data_dir" / "control" / "signing.ed25519"
    assert load_config(path).control.signing_key == default_key
    assert not default_key.exists()
    assert (
        client.post(
            "/api/web-config/control-settings", auth=AUTH, json={"signing_key": 123}
        ).status_code
        == 422
    )
    assert (
        client.post("/api/web-config/control-settings", auth=AUTH, json={"port": 0}).status_code
        == 422
    )
    assert client.post("/api/web-config/control-settings", json=settings).status_code == 401
