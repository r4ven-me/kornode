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


def test_web_settings_saves_panel_fields_without_touching_admin_password(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/web-config/settings",
        auth=("admin", "secret"),
        json={
            "enabled": True,
            "listen": "0.0.0.0",
            "trusted_proxies": ["127.0.0.1"],
            "terminal_enabled": True,
            "terminal_idle_timeout": 600,
            "session_lifetime": 1800,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["web"]["listen"] == "0.0.0.0"
    assert saved["web"]["trusted_proxies"] == ["127.0.0.1"]
    assert saved["web"]["terminal_enabled"] is True
    assert saved["web"]["terminal_idle_timeout"] == 600
    assert saved["web"]["session_lifetime"] == 1800
    assert saved["web"]["admin_password"] == "secret"
