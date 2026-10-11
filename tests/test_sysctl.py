from __future__ import annotations

from typing import Any

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.sysctl import GLOBAL_SYSCTLS, SysctlService


class FakeRunner:
    def __init__(self, values: dict[str, CommandResult] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.values = values or {}

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        self.calls.append(list(argv))
        if argv[:2] == ["sysctl", "-n"]:
            return self.values.get(
                argv[2],
                CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr=""),
            )
        if argv == ["sysctl", "-w", "net.ipv4.conf.bad0.rp_filter=2"]:
            return CommandResult(argv=tuple(argv), returncode=1, stdout="", stderr="bad key")
        return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")


def _config() -> AppConfig:
    return AppConfig.model_validate({})


def test_apply_global_sets_required_sysctls() -> None:
    runner = FakeRunner()

    SysctlService(_config(), runner=runner).apply_global()

    assert runner.calls == [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["sysctl", "-w", "net.ipv4.conf.all.src_valid_mark=1"],
        ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"],
        ["sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"],
    ]


def test_apply_interface_sets_rp_filter_for_one_interface() -> None:
    runner = FakeRunner()

    SysctlService(_config(), runner=runner).apply_interface("tun0")

    assert runner.calls == [["sysctl", "-w", "net.ipv4.conf.tun0.rp_filter=2"]]


def test_check_reports_matching_global_values() -> None:
    runner = FakeRunner(
        {
            "net.ipv4.ip_forward": CommandResult(("sysctl",), 0, "1\n", ""),
            "net.ipv4.conf.all.src_valid_mark": CommandResult(("sysctl",), 0, "0\n", ""),
            "net.ipv4.conf.all.rp_filter": CommandResult(("sysctl",), 1, "", "missing"),
            "net.ipv4.conf.default.rp_filter": CommandResult(("sysctl",), 0, "2\n", ""),
        }
    )

    assert SysctlService(_config(), runner=runner).check() == {
        "net.ipv4.ip_forward": True,
        "net.ipv4.conf.all.src_valid_mark": False,
        "net.ipv4.conf.all.rp_filter": False,
        "net.ipv4.conf.default.rp_filter": True,
    }
    assert runner.calls == [["sysctl", "-n", key] for key in GLOBAL_SYSCTLS]


def test_apply_interface_returns_nonzero_command_result() -> None:
    result = SysctlService(_config(), runner=FakeRunner()).apply_interface("bad0")

    assert result == [
        CommandResult(
            argv=("sysctl", "-w", "net.ipv4.conf.bad0.rp_filter=2"),
            returncode=1,
            stdout="",
            stderr="bad key",
        )
    ]
