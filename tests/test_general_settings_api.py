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


def test_general_settings_saves_system_and_cli_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/config/general-settings",
        auth=("admin", "secret"),
        json={
            "timezone": "Europe/Moscow",
            "log_level": "debug",
            "project_name": "acme-vpn",
            "cli_enabled": False,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["system"]["timezone"] == "Europe/Moscow"
    assert saved["system"]["log_level"] == "debug"
    assert saved["system"]["project_name"] == "acme-vpn"
    assert saved["cli"]["enabled"] is False
