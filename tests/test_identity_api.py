from __future__ import annotations

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app


def _client(config_path: Path, tmp_path: Path | None = None) -> TestClient:
    system_block = (
        f"""
system:
  data_dir: {tmp_path}/data
  log_dir: {tmp_path}/logs
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
"""
        if tmp_path is not None
        else ""
    )
    config_path.write_text(
        f"""
{system_block}
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


def test_identity_api_saves_oidc_provider_without_returning_secret(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/identity/oidc/providers",
        auth=("admin", "secret"),
        json={
            "name": "keycloak",
            "issuer_url": "https://sso.example.com/realms/vpn",
            "client_id": "kornode-vpn",
            "client_secret": "top-secret",
            "allowed_groups": ["vpn-admins"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert "top-secret" not in str(payload)
    assert payload["identity"]["oidc_providers"][0]["name"] == "keycloak"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["identity"]["oidc_providers"][0]["client_secret"] == "top-secret"


def test_identity_api_saves_group_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/identity/groups",
        auth=("admin", "secret"),
        json={
            "name": "devops",
            "display_name": "DevOps",
            "routes": ["10.20.0.0/16"],
            "dns": ["10.10.10.1"],
            "split_dns": ["corp.example.com"],
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["identity"]["group_policies"][0]["name"] == "devops"
    assert saved["identity"]["group_policies"][0]["routes"] == ["10.20.0.0/16"]


def test_identity_api_saves_group_policy_dns_and_client_limits(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/identity/groups",
        auth=("admin", "secret"),
        json={
            "name": "devops",
            "tunnel_all_dns": True,
            "idle_timeout": 900,
            "no_udp": True,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["identity"]["group_policies"][0]["tunnel_all_dns"] is True
    assert saved["identity"]["group_policies"][0]["idle_timeout"] == 900
    assert saved["identity"]["group_policies"][0]["no_udp"] is True


def test_identity_api_saves_oidc_provider_claim_mappings(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/identity/oidc/providers",
        auth=("admin", "secret"),
        json={
            "name": "keycloak",
            "issuer_url": "https://sso.example.com/realms/vpn",
            "client_id": "kornode-vpn",
            "username_claim": "email",
            "groups_claim": "roles",
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["identity"]["oidc_providers"][0]["username_claim"] == "email"
    assert saved["identity"]["oidc_providers"][0]["groups_claim"] == "roles"


def test_identity_settings_saves_group_routing_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/identity/groups",
        auth=("admin", "secret"),
        json={"name": "devops"},
    )

    response = client.post(
        "/api/identity/settings",
        auth=("admin", "secret"),
        json={
            "select_group_by_url": True,
            "default_select_group": "devops",
            "default_group_config": "/var/lib/kornode/generated/config-per-group/default",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["identity"]["select_group_by_url"] is True
    assert payload["identity"]["default_select_group"] == "devops"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["identity"]["select_group_by_url"] is True
    assert saved["identity"]["default_select_group"] == "devops"
