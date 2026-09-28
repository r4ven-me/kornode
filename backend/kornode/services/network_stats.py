from __future__ import annotations

import re
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.command import CommandRunner

_DEFAULT_ROUTE_DEVICE_RE = re.compile(r"\bdev\s+(\S+)")


class NetworkStatsService:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        sys_class_net: Path = Path("/sys/class/net"),
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.sys_class_net = sys_class_net

    def resolve_interface(self) -> str | None:
        configured = self.config.routing.main_interface
        if configured and configured != "auto":
            return configured
        result = self.runner.run(
            ["ip", "route", "show", "default"], timeout=5, check=False
        )
        if not result.ok:
            return None
        match = _DEFAULT_ROUTE_DEVICE_RE.search(result.stdout)
        return match.group(1) if match else None

    def read_counters(self, interface: str) -> tuple[int, int] | None:
        stats_dir = self.sys_class_net / interface / "statistics"
        try:
            rx_bytes = int((stats_dir / "rx_bytes").read_text(encoding="utf-8").strip())
            tx_bytes = int((stats_dir / "tx_bytes").read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None
        return rx_bytes, tx_bytes

    def snapshot(self) -> dict[str, object]:
        interface = self.resolve_interface()
        counters = self.read_counters(interface) if interface else None
        rx_bytes, tx_bytes = counters if counters else (None, None)
        return {
            "interface": interface,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
        }
