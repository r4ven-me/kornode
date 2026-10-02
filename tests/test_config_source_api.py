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


def test_config_source_contains_only_persisted_yaml(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml")

    response = client.get("/api/config/source", auth=("admin", "secret"))

    assert response.status_code == 200
    source = yaml.safe_load(response.json()["content"])
    assert source["server"] == {"realm": "Korvus Node VPN"}
    assert source["web"]["admin_password"] == "***"
    assert "advanced" not in source


def test_missing_config_source_does_not_materialize_env_or_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    (tmp_path / ".env").write_text(
        "KORNODE_WEB__ADMIN_PASSWORD=secret\nKORNODE_SERVER__PORT=4443\n",
        encoding="utf-8",
    )
    client = TestClient(create_app(config_path=config_path))

    source_response = client.get("/api/config/source", auth=("admin", "secret"))

    assert source_response.status_code == 200
    assert source_response.json()["exists"] is False
    assert source_response.json()["content"] == ""
    assert client.get("/api/config", auth=("admin", "secret")).json()["server"]["port"] == 4443

    save_response = client.post(
        "/api/config/source",
        auth=("admin", "secret"),
        json={"content": "server:\n  realm: Saved VPN\n", "write_rendered": False},
    )

    assert save_response.status_code == 200
    assert yaml.safe_load(config_path.read_text(encoding="utf-8")) == {
        "server": {"realm": "Saved VPN"}
    }
    assert save_response.json()["config"]["server"]["port"] == 4443


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
