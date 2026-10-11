from __future__ import annotations

import pytest

from kornode import cli
from kornode.config.models import AppConfig
from kornode.services.command import CommandResult


class FakeSysctlService:
    interfaces: list[str] = []

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def apply_interface(self, iface: str) -> list[CommandResult]:
        self.interfaces.append(iface)
        return [CommandResult(("sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter=2"), 0, "", "")]


def test_server_hook_applies_sysctl_to_ocserv_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeSysctlService.interfaces = []
    monkeypatch.setenv("DEVICE", "vpns0")
    monkeypatch.setattr(cli, "get_config", lambda: AppConfig.model_validate({}))
    monkeypatch.setattr(cli, "SysctlService", FakeSysctlService)

    cli.server_hook()

    assert FakeSysctlService.interfaces == ["vpns0"]


def test_server_hook_fails_without_device(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEVICE", raising=False)

    with pytest.raises(cli.typer.Exit) as exc:
        cli.server_hook()

    assert exc.value.exit_code == 1
