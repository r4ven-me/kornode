from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.config.models import AppConfig


def _config(tmp_path: Path, **web: object) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "web": {"admin_password": "secret", **web},
        }
    )


def test_terminal_session_requires_admin_auth(tmp_path: Path) -> None:
    config = _config(tmp_path, terminal_enabled=True)
    client = TestClient(create_app(config))

    response = client.post("/api/terminal/sessions", json={"cwd": "/", "rows": 30, "cols": 100})

    assert response.status_code == 401


def test_terminal_session_returns_one_time_ticket(tmp_path: Path) -> None:
    config = _config(tmp_path, terminal_enabled=True)
    client = TestClient(create_app(config))

    response = client.post(
        "/api/terminal/sessions",
        auth=("admin", "secret"),
        json={"cwd": "/", "rows": 30, "cols": 100},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["cwd"] == "/"
    assert isinstance(payload["token"], str)
    assert len(payload["token"]) > 20


def test_terminal_is_disabled_by_default(tmp_path: Path) -> None:
    config = _config(tmp_path)
    client = TestClient(create_app(config))

    response = client.post(
        "/api/terminal/sessions",
        auth=("admin", "secret"),
        json={"cwd": "/", "rows": 30, "cols": 100},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "web terminal is disabled"
