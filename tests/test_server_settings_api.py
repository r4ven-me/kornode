from __future__ import annotations

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app


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
auth:
  password:
    enabled: true
""",
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=config_path))


def test_server_settings_saves_vpn_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/server/settings",
        auth=("admin", "secret"),
        json={
            "port": 8443,
            "ipv4_network": "10.20.0.0/24",
            "dns": ["9.9.9.9"],
            "max_clients": 64,
            "compression": True,
            "camouflage": {"enabled": True, "secret": "shh", "realm": "Hidden"},
            "debug_level": 3,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    # camouflage.secret is a shared TLS camouflage password, not a per-user
    # credential, so it round-trips in plain text like any other setting.
    assert payload["server"]["camouflage"]["secret"] == "shh"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["server"]["port"] == 8443
    assert saved["server"]["ipv4_network"] == "10.20.0.0/24"
    assert saved["server"]["dns"] == ["9.9.9.9"]
    assert saved["server"]["max_clients"] == 64
    assert saved["server"]["compression"] is True
    assert saved["server"]["camouflage"]["secret"] == "shh"
    assert saved["server"]["debug_level"] == 3


def test_server_settings_saves_new_tuning_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/server/settings",
        auth=("admin", "secret"),
        json={
            "dpd": 60,
            "deny_roaming": True,
            "rekey_method": "new-tunnel",
            "cert_user_oid": "0.9.2342.19200300.100.1.1",
            "tls_priorities": "NORMAL:%SERVER_PRECEDENCE",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["server"]["dpd"] == 60
    assert payload["server"]["rekey_method"] == "new-tunnel"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["server"]["dpd"] == 60
    assert saved["server"]["deny_roaming"] is True
    assert saved["server"]["rekey_method"] == "new-tunnel"
    assert saved["server"]["cert_user_oid"] == "0.9.2342.19200300.100.1.1"
    assert saved["server"]["tls_priorities"] == "NORMAL:%SERVER_PRECEDENCE"


def test_server_settings_resave_with_returned_secret_keeps_camouflage_enabled(
    tmp_path: Path,
) -> None:
    # Regression test: the UI re-sends whatever the last GET/POST returned for
    # camouflage.secret. Since that value is no longer masked to "***", saving
    # an unrelated field (e.g. max_clients) must not blank the secret and trip
    # the "secret is required when camouflage is enabled" validation error.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    first = client.post(
        "/api/server/settings",
        auth=("admin", "secret"),
        json={"camouflage": {"enabled": True, "secret": "shh", "realm": "Hidden"}},
    )
    assert first.status_code == 200
    returned_secret = first.json()["server"]["camouflage"]["secret"]

    second = client.post(
        "/api/server/settings",
        auth=("admin", "secret"),
        json={
            "max_clients": 200,
            "camouflage": {"enabled": True, "secret": returned_secret, "realm": "Hidden"},
        },
    )
    assert second.status_code == 200
    payload = second.json()
    assert payload["server"]["camouflage"]["secret"] == "shh"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["server"]["max_clients"] == 200
    assert saved["server"]["camouflage"]["secret"] == "shh"


def test_auth_methods_settings_saves_and_survives_reload(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/server/auth-settings",
        auth=("admin", "secret"),
        json={
            "password_enabled": True,
            "certificate_enabled": True,
            "otp_enabled": True,
            "otp_ocserv_oath_auth": True,
            "otp_issuer": "Acme VPN",
            "otp_send_by_email": True,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["auth"]["certificate"]["enabled"] is True
    assert saved["auth"]["otp"]["issuer"] == "Acme VPN"
    assert saved["auth"]["otp"]["ocserv_oath_auth"] is True


def test_auth_methods_settings_does_not_clobber_oidc_settings(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/identity/oidc/settings",
        auth=("admin", "secret"),
        json={"enabled": True, "connector": "pam", "pam_service": "custom-ocserv"},
    )

    client.post(
        "/api/server/auth-settings",
        auth=("admin", "secret"),
        json={"password_enabled": True},
    )

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["auth"]["oidc"]["pam"]["service"] == "custom-ocserv"
