from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.network_stats import NetworkStatsService


class StaticRunner(CommandRunner):
    def __init__(self, stdout: str, returncode: int = 0) -> None:
        super().__init__()
        self._stdout = stdout
        self._returncode = returncode

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        cwd: str | None = None,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, cwd, input_text, env, check, extra_secrets
        return CommandResult(tuple(argv), self._returncode, self._stdout, "", dry_run=dry_run)


def _write_counters(sys_class_net: Path, interface: str, rx_bytes: int, tx_bytes: int) -> None:
    stats_dir = sys_class_net / interface / "statistics"
    stats_dir.mkdir(parents=True)
    (stats_dir / "rx_bytes").write_text(f"{rx_bytes}\n", encoding="utf-8")
    (stats_dir / "tx_bytes").write_text(f"{tx_bytes}\n", encoding="utf-8")


def test_resolve_interface_uses_configured_value_without_shelling_out(tmp_path: Path) -> None:
    config = AppConfig.model_validate({"routing": {"main_interface": "eth0"}})
    runner = StaticRunner("")

    service = NetworkStatsService(config, runner=runner, sys_class_net=tmp_path)

    assert service.resolve_interface() == "eth0"


def test_resolve_interface_parses_default_route_when_auto(tmp_path: Path) -> None:
    config = AppConfig.model_validate({"routing": {"main_interface": "auto"}})
    runner = StaticRunner("default via 192.0.2.1 dev eth1 proto dhcp metric 100 \n")

    service = NetworkStatsService(config, runner=runner, sys_class_net=tmp_path)

    assert service.resolve_interface() == "eth1"


def test_snapshot_reads_rx_tx_byte_counters(tmp_path: Path) -> None:
    config = AppConfig.model_validate({"routing": {"main_interface": "eth0"}})
    _write_counters(tmp_path, "eth0", rx_bytes=1000, tx_bytes=2000)
    service = NetworkStatsService(config, runner=StaticRunner(""), sys_class_net=tmp_path)

    snapshot = service.snapshot()

    assert snapshot == {"interface": "eth0", "rx_bytes": 1000, "tx_bytes": 2000}


def test_snapshot_handles_missing_interface_gracefully(tmp_path: Path) -> None:
    config = AppConfig.model_validate({"routing": {"main_interface": "missing0"}})
    service = NetworkStatsService(config, runner=StaticRunner(""), sys_class_net=tmp_path)

    snapshot = service.snapshot()

    assert snapshot == {"interface": "missing0", "rx_bytes": None, "tx_bytes": None}
