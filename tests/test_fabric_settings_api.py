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


def test_fabric_settings_saves_node_and_fabric_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/config/fabric-settings",
        auth=("admin", "secret"),
        json={
            "node_id": 3,
            "enabled": True,
            "cidr": "10.99.0.0/24",
            "client_pool": "10.100.{id}.0/24",
            "source_pool": "10.8.{id}.0/24",
            "enroll_pool": "10.99.255.240/28",
            "domain": "kornode.internal",
            "reserved": ["10.200.0.0/16"],
            "write_rendered": False,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["server"]["ipv4_network"] == "10.100.3.0/24"
    assert payload["internal_dns"]["listen"] == "10.100.3.1"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["node"]["id"] == 3
    assert saved["fabric"]["enabled"] is True
    assert saved["fabric"]["enroll_pool"] == "10.99.255.240/28"
    assert saved["fabric"]["reserved"] == ["10.200.0.0/16"]


def test_fabric_settings_rejects_invalid_template(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/config/fabric-settings",
        auth=("admin", "secret"),
        json={
            "enabled": True,
            "client_pool": "10.100.{node}.0/24",
            "write_rendered": False,
        },
    )

    assert response.status_code == 400
    assert "must contain exactly one {id} placeholder" in response.text


def test_config_patch_reports_fabric_overlap_conflict(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.patch(
        "/api/config",
        auth=("admin", "secret"),
        json={
            "write_rendered": False,
            "patch": {
                "fabric": {"enabled": True, "reserved": ["10.120.0.0/16"]},
                "server": {"ipv4_network": "10.120.1.0/24"},
                "internal_dns": {"listen": "10.120.1.1"},
            },
        },
    )

    assert response.status_code == 409
    assert response.json() == {
        "error": "address_overlap",
        "conflicts": [
            {
                "prefix": "10.120.1.0/24",
                "node": 1,
                "with": "10.120.0.0/16",
                "owner": "fabric.reserved",
            }
        ],
    }
