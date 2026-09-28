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


def test_rotation_settings_roundtrip(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    initial = client.get("/api/logs/rotation", auth=("admin", "secret"))
    assert initial.status_code == 200
    assert initial.json()["enabled"] is False

    response = client.post(
        "/api/logs/rotation",
        auth=("admin", "secret"),
        json={
            "enabled": True,
            "max_size_mb": 10,
            "max_age": 2,
            "max_age_unit": "weeks",
            "keep_files": 3,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["system"]["log_rotation"] == {
        "enabled": True,
        "max_size_mb": 10,
        "max_age": 2,
        "max_age_unit": "weeks",
        "keep_files": 3,
    }
    followup = client.get("/api/logs/rotation", auth=("admin", "secret"))
    assert followup.json()["max_age_unit"] == "weeks"


def test_rotation_run_rotates_logs_now(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True)
    (log_dir / "api.log").write_text("hello\n", encoding="utf-8")
    client = _client(config_path, tmp_path)

    response = client.post("/api/logs/rotation/run", auth=("admin", "secret"), json={})

    assert response.status_code == 200
    assert response.json()["rotated"] == ["api.log"]
    assert (log_dir / "api.log").stat().st_size == 0
    assert (log_dir / "api.log.1").read_text(encoding="utf-8") == "hello\n"


def test_rotation_settings_reject_invalid_unit(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/logs/rotation",
        auth=("admin", "secret"),
        json={
            "enabled": True,
            "max_size_mb": 10,
            "max_age": 2,
            "max_age_unit": "fortnights",
            "keep_files": 3,
        },
    )

    assert response.status_code == 422
