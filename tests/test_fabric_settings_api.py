from __future__ import annotations

from pathlib import Path

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


def test_config_patch_reports_fabric_overlap_conflict(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.patch(
        "/api/config",
        auth=("admin", "secret"),
        json={
            "write_rendered": False,
            "patch": {
                "fabric": {"reserved": ["10.120.0.0/16"]},
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
