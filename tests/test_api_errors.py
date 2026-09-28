from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.config.models import AppConfig


def test_user_config_validation_error_is_readable(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "web": {"admin_password": "secret"},
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
        }
    )
    client = TestClient(create_app(config=config))

    response = client.put(
        "/api/users/alice/config",
        json={"dns": ["not-an-ip"]},
        auth=("admin", "secret"),
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail[0]["loc"] == ["body", "dns"]
    assert "valid IP" in detail[0]["msg"] or "address" in detail[0]["msg"]
