from __future__ import annotations

from pathlib import Path

import pytest

from kornode.config.models import AppConfig
from kornode.main import initialize_runtime
from kornode.services.net import NetApplyError


class FailingNetService:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def converge(self) -> dict[str, object]:
        raise NetApplyError("kernel did not converge: OSError: permission denied")


def test_initialize_runtime_aborts_when_the_kernel_does_not_converge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "log_dir": tmp_path / "logs",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    monkeypatch.setattr("kornode.main.load_config", lambda _path: config)
    monkeypatch.setattr("kornode.main.NetService", FailingNetService)
    monkeypatch.setattr("kornode.main.prepare_startup_letsencrypt", lambda cfg, *_a: cfg)

    with pytest.raises(SystemExit) as exc:
        initialize_runtime(tmp_path / "config.yaml")

    assert "failed to converge kernel networking state" in str(exc.value)
    assert "permission denied" in str(exc.value)
