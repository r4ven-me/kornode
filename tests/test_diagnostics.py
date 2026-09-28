from __future__ import annotations

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.diagnostics import DiagnosticProbe, DiagnosticsService


def test_missing_nft_table_warns_when_routing_needs_nftables() -> None:
    config = AppConfig.model_validate({"routing": {"mode": "split"}})
    probe = DiagnosticProbe("nft nat table", ("nft", "list", "table", "ip", "kornode_nat"))
    result = CommandResult(probe.argv, 1, "", "Error: No such file or directory")

    normalized = DiagnosticsService(config).normalize(probe, result)

    assert normalized.returncode == 0
    assert "not installed yet" in normalized.stdout
    assert "run korctl nft apply" in normalized.stdout
