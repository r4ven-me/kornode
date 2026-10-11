from __future__ import annotations

from pathlib import Path

import pytest

from kornode.config.models import AppConfig
from kornode.main import initialize_runtime
from kornode.services.command import CommandResult


class FailingSysctlService:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def apply_global(self) -> list[CommandResult]:
        return [
            CommandResult(
                argv=("sysctl", "-w", "net.ipv4.ip_forward=1"),
                returncode=1,
                stdout="",
                stderr="permission denied",
            )
        ]


def test_initialize_runtime_aborts_when_required_sysctls_fail(
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
    monkeypatch.setattr("kornode.main.SysctlService", FailingSysctlService)
    monkeypatch.setattr(
        "kornode.main.FileManager",
        lambda: pytest.fail("startup continued after sysctl failure"),
    )

    with pytest.raises(SystemExit) as exc:
        initialize_runtime(tmp_path / "config.yaml")

    assert "failed to apply required sysctl settings" in str(exc.value)
    assert "permission denied" in str(exc.value)
