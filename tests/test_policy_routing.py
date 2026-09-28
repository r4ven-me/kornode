from __future__ import annotations

from typing import Any

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.policy_routing import PolicyRoutingService


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        del kwargs
        self.calls.append(list(argv))
        return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")


def _config(mode: str = "full") -> AppConfig:
    return AppConfig.model_validate(
        {
            "routing": {"mode": mode, "fwmark": "0x0c01", "table_id": 1201},
            "upstream": {"interface": "oc-middle0"},
        }
    )


def test_apply_deletes_then_adds_the_rule_and_replaces_the_route() -> None:
    runner = FakeRunner()

    PolicyRoutingService(_config(), runner=runner).apply()

    assert runner.calls == [
        ["ip", "rule", "del", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "rule", "add", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "route", "replace", "default", "dev", "oc-middle0", "table", "1201"],
    ]


def test_cleanup_deletes_the_rule_and_flushes_the_table() -> None:
    runner = FakeRunner()

    PolicyRoutingService(_config(), runner=runner).cleanup()

    assert runner.calls == [
        ["ip", "rule", "del", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "route", "flush", "table", "1201"],
    ]


class RuleShowRunner(FakeRunner):
    """FakeRunner that answers `ip -j rule show` with a fixed rule list."""

    def __init__(self, rules_json: str) -> None:
        super().__init__()
        self.rules_json = rules_json

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        result = super().run(argv, **kwargs)
        if argv[:4] == ["ip", "-j", "rule", "show"]:
            return CommandResult(
                argv=tuple(argv), returncode=0, stdout=self.rules_json, stderr=""
            )
        return result


def test_ensure_reinstalls_missing_rule_and_route() -> None:
    runner = RuleShowRunner("[]")

    PolicyRoutingService(_config("split"), runner=runner).ensure("oc-middle0")

    assert runner.calls[1:] == [
        ["ip", "rule", "add", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "route", "replace", "default", "dev", "oc-middle0", "table", "1201"],
    ]


def test_ensure_skips_rule_add_when_rule_already_present() -> None:
    # iproute2 prints the mark without the leading zero (0xc01, not 0x0c01)
    # and the table by id; ensure() must treat that as "already installed"
    # instead of piling up duplicate rules on every watchdog tick.
    runner = RuleShowRunner('[{"priority":100,"src":"all","fwmark":"0xc01","table":"1201"}]')

    PolicyRoutingService(_config("split"), runner=runner).ensure("oc-middle0")

    assert ["ip", "rule", "add", "fwmark", "0x0c01", "table", "1201", "priority", "100"] \
        not in runner.calls
    assert runner.calls[-1] == [
        "ip", "route", "replace", "default", "dev", "oc-middle0", "table", "1201",
    ]
