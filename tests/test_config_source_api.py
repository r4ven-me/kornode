from __future__ import annotations

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app


def _client(config_path: Path) -> TestClient:
    root = config_path.parent
    config_path.write_text(
        f"""
system:
  data_dir: {root / "data"}
  generated_dir: {root / "generated"}
  log_dir: {root / "logs"}
  secrets_dir: {root / "secrets"}
web:
  enabled: true
  listen: 127.0.0.1
  admin_password: secret
server:
  realm: Korvus Node VPN
auth:
  password:
    enabled: true
""",
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=config_path))


def test_config_source_masks_secret_values(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml")

    response = client.get("/api/config/source", auth=("admin", "secret"))

    assert response.status_code == 200
    payload = response.json()
    assert "admin_password: secret" not in payload["content"]
    assert "admin_password: '***'" in payload["content"]


def test_config_source_includes_unset_defaults(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml")

    response = client.get("/api/config/source", auth=("admin", "secret"))

    assert response.status_code == 200
    effective = yaml.safe_load(response.json()["content"])
    assert effective["server"]["realm"] == "Korvus Node VPN"
    assert effective["server"]["port"] == 443
    assert effective["server"]["max_clients"] == 128
    assert effective["web"]["admin_password"] == "***"
    assert effective["advanced"]["raw_ocserv_options"] == []


def test_config_source_save_preserves_masked_secret_values(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path)
    source = client.get("/api/config/source", auth=("admin", "secret")).json()["content"]
    edited = source.replace("realm: Korvus Node VPN", "realm: Edited VPN")

    response = client.post(
        "/api/config/source",
        auth=("admin", "secret"),
        json={"content": edited, "write_rendered": False},
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["web"]["admin_password"] == "secret"
    assert saved["server"]["realm"] == "Edited VPN"
    assert response.json()["config"]["web"]["admin_password"] == "***"
