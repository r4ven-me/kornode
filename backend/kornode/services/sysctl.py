from __future__ import annotations

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner

GLOBAL_SYSCTLS: dict[str, str] = {
    "net.ipv4.ip_forward": "1",
    "net.ipv4.conf.all.src_valid_mark": "1",
    "net.ipv4.conf.all.rp_filter": "2",
    "net.ipv4.conf.default.rp_filter": "2",
}


class SysctlService:
    def __init__(self, config: AppConfig, runner: CommandRunner | None = None) -> None:
        self.config = config
        self.runner = runner or CommandRunner()

    def apply_global(self, *, dry_run: bool = False) -> list[CommandResult]:
        return [
            self._write(key, value, dry_run=dry_run)
            for key, value in GLOBAL_SYSCTLS.items()
        ]

    def apply_interface(self, iface: str, *, dry_run: bool = False) -> list[CommandResult]:
        return [
            self._write(f"net.ipv4.conf.{iface}.rp_filter", "2", dry_run=dry_run)
        ]

    def check(self) -> dict[str, bool]:
        status: dict[str, bool] = {}
        for key, value in GLOBAL_SYSCTLS.items():
            result = self._read(key)
            status[key] = result.ok and result.stdout.strip() == value
        return status

    def _write(self, key: str, value: str, *, dry_run: bool) -> CommandResult:
        return self.runner.run(
            ["sysctl", "-w", f"{key}={value}"],
            check=False,
            dry_run=dry_run,
        )

    def _read(self, key: str) -> CommandResult:
        return self.runner.run(["sysctl", "-n", key], check=False, timeout=5)
