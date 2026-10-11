from __future__ import annotations

import json
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


def _config_with_named_target() -> AppConfig:
    return AppConfig.model_validate(
        {
            "routing": {"mode": "full", "fwmark": "0x0c01", "table_id": 1201},
            "upstream": {
                "enabled": True,
                "interface": "oc-middle0",
                "profiles": [
                    {
                        "name": "primary",
                        "server": "vpn-primary.example",
                        "username": "alice",
                        "routes": ["10.8.0.0/24"],
                    },
                ],
            },
        }
    )


def test_apply_installs_suppress_rule_when_absent_then_replaces_profile_rule() -> None:
    runner = RuleShowRunner("[]")

    PolicyRoutingService(_config(), runner=runner).apply()

    assert runner.calls == [
        ["ip", "-j", "rule", "show"],
        [
            "ip",
            "rule",
            "add",
            "priority",
            "90",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
        ],
        ["ip", "rule", "del", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "rule", "add", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "route", "replace", "default", "dev", "oc-middle0", "table", "1201"],
        ["ip", "route", "show", "table", "1201"],
        [
            "ip",
            "route",
            "add",
            "unreachable",
            "default",
            "metric",
            "4096",
            "table",
            "1201",
        ],
    ]


def test_apply_adds_unreachable_default_route_on_first_apply() -> None:
    runner = PolicyRoutingRunner(rules=[], routes=[])

    PolicyRoutingService(_config(), runner=runner).apply()

    assert [
        "ip",
        "route",
        "add",
        "unreachable",
        "default",
        "metric",
        "4096",
        "table",
        "1201",
    ] in runner.calls
    assert "unreachable default metric 4096" in runner.routes


def test_cleanup_deletes_the_rule_and_flushes_the_table() -> None:
    runner = StatefulRuleRunner(
        [
            {"priority": 90, "src": "all", "table": "main", "suppress_prefixlength": 0},
            {"priority": 100, "src": "all", "fwmark": "0xc01", "table": "1201"},
        ]
    )

    PolicyRoutingService(_config(), runner=runner).cleanup()

    assert runner.calls == [
        ["ip", "rule", "del", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "route", "flush", "table", "1201"],
        ["ip", "-j", "rule", "show"],
        [
            "ip",
            "rule",
            "del",
            "priority",
            "90",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
        ],
    ]


def test_cleanup_keeps_suppress_rule_while_another_configured_policy_rule_exists() -> None:
    runner = StatefulRuleRunner(
        [
            {"priority": 90, "src": "all", "table": "main", "suppress_prefixlength": 0},
            {"priority": 100, "src": "all", "fwmark": "0xc01", "table": "1201"},
            {"priority": 100, "src": "all", "fwmark": "0xc02", "table": "1202"},
        ]
    )

    PolicyRoutingService(_config_with_named_target(), runner=runner).cleanup()

    assert [
        "ip",
        "rule",
        "del",
        "priority",
        "90",
        "lookup",
        "main",
        "suppress_prefixlength",
        "0",
    ] not in runner.calls
    assert runner.calls == [
        ["ip", "rule", "del", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "route", "flush", "table", "1201"],
        ["ip", "-j", "rule", "show"],
    ]


class RuleShowRunner(FakeRunner):
    """FakeRunner that answers `ip -j rule show` with a fixed rule list."""

    def __init__(self, rules_json: str) -> None:
        super().__init__()
        self.rules_json = rules_json

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        result = super().run(argv, **kwargs)
        if argv[:4] == ["ip", "-j", "rule", "show"]:
            return CommandResult(argv=tuple(argv), returncode=0, stdout=self.rules_json, stderr="")
        return result


class StatefulRuleRunner(FakeRunner):
    """FakeRunner that mutates its `ip -j rule show` output for rule deletes."""

    def __init__(self, rules: list[dict[str, object]]) -> None:
        super().__init__()
        self.rules = rules

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        self.calls.append(list(argv))
        if argv[:4] == ["ip", "-j", "rule", "show"]:
            return CommandResult(
                argv=tuple(argv), returncode=0, stdout=json.dumps(self.rules), stderr=""
            )
        if argv[:3] == ["ip", "rule", "del"] and "fwmark" in argv and "table" in argv:
            fwmark = argv[argv.index("fwmark") + 1]
            table = argv[argv.index("table") + 1]
            fwmark_value = int(fwmark, 0)
            self.rules = [
                rule
                for rule in self.rules
                if (
                    rule.get("fwmark") is None
                    or int(str(rule["fwmark"]), 0) != fwmark_value
                    or str(rule.get("table", "")) != table
                )
            ]
        return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")


class PolicyRoutingRunner(StatefulRuleRunner):
    """Stateful rule and route-table fake for PolicyRoutingService drift tests."""

    def __init__(self, rules: list[dict[str, object]], routes: list[str]) -> None:
        super().__init__(rules)
        self.routes = routes

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        if argv[:5] == ["ip", "route", "show", "table", "1201"]:
            self.calls.append(list(argv))
            return CommandResult(
                argv=tuple(argv), returncode=0, stdout="\n".join(self.routes), stderr=""
            )
        if argv[:3] == ["ip", "route", "replace"] and argv[3:5] == ["default", "dev"]:
            self.calls.append(list(argv))
            route = f"default dev {argv[5]}"
            self.routes = [existing for existing in self.routes if not existing.startswith(route)]
            self.routes.insert(0, route)
            return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")
        if argv[:4] == ["ip", "route", "add", "unreachable"]:
            self.calls.append(list(argv))
            route = "unreachable default metric 4096"
            if route not in self.routes:
                self.routes.append(route)
            return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")
        if argv[:4] == ["ip", "route", "flush", "table"]:
            self.calls.append(list(argv))
            if argv[4] == "1201":
                self.routes = []
            return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")
        return super().run(argv, **kwargs)


def test_ensure_reinstalls_missing_rule_and_route() -> None:
    runner = RuleShowRunner("[]")

    PolicyRoutingService(_config("split"), runner=runner).ensure("oc-middle0")

    assert runner.calls == [
        ["ip", "-j", "rule", "show"],
        [
            "ip",
            "rule",
            "add",
            "priority",
            "90",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
        ],
        ["ip", "-j", "rule", "show"],
        ["ip", "rule", "add", "fwmark", "0x0c01", "table", "1201", "priority", "100"],
        ["ip", "route", "replace", "default", "dev", "oc-middle0", "table", "1201"],
        ["ip", "route", "show", "table", "1201"],
        [
            "ip",
            "route",
            "add",
            "unreachable",
            "default",
            "metric",
            "4096",
            "table",
            "1201",
        ],
    ]


def test_ensure_skips_rule_add_when_suppress_and_profile_rules_already_present() -> None:
    # iproute2 prints the mark without the leading zero (0xc01, not 0x0c01)
    # and the table by id; ensure() must treat that as "already installed"
    # instead of piling up duplicate rules on every watchdog tick.
    runner = RuleShowRunner(
        "["
        '{"priority":90,"src":"all","table":"main","suppress_prefixlength":0},'
        '{"priority":100,"src":"all","fwmark":"0xc01","table":"1201"}'
        "]"
    )

    PolicyRoutingService(_config("split"), runner=runner).ensure("oc-middle0")

    assert [
        "ip",
        "rule",
        "add",
        "priority",
        "90",
        "lookup",
        "main",
        "suppress_prefixlength",
        "0",
    ] not in runner.calls
    assert [
        "ip",
        "rule",
        "add",
        "fwmark",
        "0x0c01",
        "table",
        "1201",
        "priority",
        "100",
    ] not in runner.calls
    # RuleShowRunner fakes no route-table state, so the route table looks
    # empty from ensure()'s perspective and it (correctly) restores the
    # missing unreachable-default route as its last action.
    assert runner.calls[-1] == [
        "ip",
        "route",
        "add",
        "unreachable",
        "default",
        "metric",
        "4096",
        "table",
        "1201",
    ]


def test_ensure_leaves_existing_unreachable_route_untouched() -> None:
    runner = PolicyRoutingRunner(
        rules=[
            {"priority": 90, "src": "all", "table": "main", "suppress_prefixlength": 0},
            {"priority": 100, "src": "all", "fwmark": "0xc01", "table": "1201"},
        ],
        routes=["default dev oc-middle0", "unreachable default metric 4096"],
    )

    PolicyRoutingService(_config("split"), runner=runner).ensure("oc-middle0")

    assert [
        "ip",
        "route",
        "add",
        "unreachable",
        "default",
        "metric",
        "4096",
        "table",
        "1201",
    ] not in runner.calls
    assert runner.routes == ["default dev oc-middle0", "unreachable default metric 4096"]


def test_ensure_restores_missing_unreachable_route() -> None:
    runner = PolicyRoutingRunner(
        rules=[
            {"priority": 90, "src": "all", "table": "main", "suppress_prefixlength": 0},
            {"priority": 100, "src": "all", "fwmark": "0xc01", "table": "1201"},
        ],
        routes=["default dev oc-middle0"],
    )

    PolicyRoutingService(_config("split"), runner=runner).ensure("oc-middle0")

    assert runner.calls[-1] == [
        "ip",
        "route",
        "add",
        "unreachable",
        "default",
        "metric",
        "4096",
        "table",
        "1201",
    ]
    assert runner.routes == ["default dev oc-middle0", "unreachable default metric 4096"]


def test_cleanup_removes_unreachable_route_by_flushing_table() -> None:
    runner = PolicyRoutingRunner(
        rules=[
            {"priority": 90, "src": "all", "table": "main", "suppress_prefixlength": 0},
            {"priority": 100, "src": "all", "fwmark": "0xc01", "table": "1201"},
        ],
        routes=["default dev oc-middle0", "unreachable default metric 4096"],
    )

    PolicyRoutingService(_config(), runner=runner).cleanup()

    assert ["ip", "route", "flush", "table", "1201"] in runner.calls
    assert runner.routes == []
