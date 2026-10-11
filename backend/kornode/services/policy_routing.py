from __future__ import annotations

import json

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.routing import RoutingService

RULE_PRIORITY = 100
SUPPRESS_RULE_PRIORITY = 90
SUPPRESS_PREFIX_LENGTH = 0
UNREACHABLE_DEFAULT_METRIC = 4096


class PolicyRoutingService:
    """Forces routing.client_policy=full/split marked traffic to actually egress via
    the upstream tunnel, instead of relying on the kernel's normal routing
    table to happen to send it there.

    The nftables ruleset (see renderers/nftables.py) marks the relevant
    traffic with routing.fwmark and, when the mark's carrier doesn't leave
    via the upstream interface, drops it (kill switch). This service is
    what makes marked traffic actually *reach* that interface in the first
    place: an `ip rule` sends fwmark'd packets to a dedicated routing
    table, and that table's only route is a default route via the
    upstream interface.
    """

    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        *,
        fwmark: str | None = None,
        table_id: int | None = None,
    ) -> None:
        """fwmark/table_id default to the top-level routing.fwmark/table_id
        (the default target). Pass a named target's own auto-derived values
        (see RoutingService.list_targets()) to manage its table instead --
        each target gets its own independent instance."""
        self.config = config
        self.runner = runner or CommandRunner()
        self._fwmark = config.routing.fwmark if fwmark is None else fwmark
        self._table_id = config.routing.table_id if table_id is None else table_id

    @property
    def table(self) -> str:
        return str(self._table_id)

    @property
    def fwmark(self) -> str:
        return self._fwmark

    def apply(self, interface: str | None = None, *, dry_run: bool = False) -> list[CommandResult]:
        """Point the fwmark table's default route at `interface`.

        The caller (UpstreamService) passes the ACTIVE profile's tunnel
        device; falling back to the top-level upstream.interface keeps
        standalone `korctl nft`-style invocations working.
        """
        device = interface or self.config.upstream.interface
        results: list[CommandResult] = []
        if not self._suppress_rule_present():
            results.append(self._add_suppress_rule(dry_run=dry_run))
        results.extend(
            [
                *self._delete_rule(dry_run=dry_run),
                self.runner.run(
                    [
                        "ip",
                        "rule",
                        "add",
                        "fwmark",
                        self.fwmark,
                        "table",
                        self.table,
                        "priority",
                        str(RULE_PRIORITY),
                    ],
                    check=False,
                    dry_run=dry_run,
                ),
                self.runner.run(
                    ["ip", "route", "replace", "default", "dev", device, "table", self.table],
                    check=False,
                    dry_run=dry_run,
                ),
            ]
        )
        if not self._unreachable_default_route_present():
            results.append(self._add_unreachable_default_route(dry_run=dry_run))
        return results

    def _add_suppress_rule(self, *, dry_run: bool) -> CommandResult:
        return self.runner.run(
            [
                "ip",
                "rule",
                "add",
                "priority",
                str(SUPPRESS_RULE_PRIORITY),
                "lookup",
                "main",
                "suppress_prefixlength",
                str(SUPPRESS_PREFIX_LENGTH),
            ],
            check=False,
            dry_run=dry_run,
        )

    def _delete_suppress_rule(self, *, dry_run: bool) -> CommandResult:
        return self.runner.run(
            [
                "ip",
                "rule",
                "del",
                "priority",
                str(SUPPRESS_RULE_PRIORITY),
                "lookup",
                "main",
                "suppress_prefixlength",
                str(SUPPRESS_PREFIX_LENGTH),
            ],
            check=False,
            dry_run=dry_run,
        )

    def _rules(self) -> list[dict[str, object]]:
        result = self.runner.run(["ip", "-j", "rule", "show"], check=False, timeout=5)
        if not result.ok:
            return []
        try:
            rules = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []
        if not isinstance(rules, list):
            return []
        return [rule for rule in rules if isinstance(rule, dict)]

    def _suppress_rule_present(self) -> bool:
        for rule in self._rules():
            try:
                priority = int(str(rule.get("priority", "")), 0)
            except ValueError:
                continue
            if priority != SUPPRESS_RULE_PRIORITY:
                continue
            table = str(rule.get("table", ""))
            suppress_prefixlength = rule.get("suppress_prefixlength")
            try:
                prefix_length = (
                    int(str(suppress_prefixlength), 0)
                    if suppress_prefixlength is not None
                    else None
                )
            except ValueError:
                continue
            if table in ("main", "254") and prefix_length == SUPPRESS_PREFIX_LENGTH:
                return True
        return False

    def _other_configured_managed_rules_present(self) -> bool:
        targets = RoutingService(self.config).list_targets(
            default_interface=self.config.routing.main_interface
        )
        current = (int(self.fwmark, 0), self.table)
        expected = {
            (int(target.fwmark, 0), str(target.table_id))
            for target in targets
            if (int(target.fwmark, 0), str(target.table_id)) != current
        }
        for rule in self._rules():
            mark = rule.get("fwmark")
            table = str(rule.get("table", ""))
            try:
                mark_value = int(str(mark), 0) if mark is not None else None
            except ValueError:
                continue
            if mark_value is not None and (mark_value, table) in expected:
                return True
        return False

    def ensure(self, interface: str | None = None, *, dry_run: bool = False) -> list[CommandResult]:
        """Idempotently re-assert the rule and route, adding only what is
        missing.

        Unlike apply(), safe to run on every watchdog tick: no del/add
        churn, so there is no window where marked packets fall through to
        the main table. Needed because the kernel silently purges every
        route referencing a tunnel device the moment it bounces (e.g.
        openconnect's own reconnect) -- after that the connection looks
        healthy while the fwmark table stays empty forever.
        """
        device = interface or self.config.upstream.interface
        results: list[CommandResult] = []
        if not self._suppress_rule_present():
            results.append(self._add_suppress_rule(dry_run=dry_run))
        if not self._rule_present():
            results.append(
                self.runner.run(
                    [
                        "ip",
                        "rule",
                        "add",
                        "fwmark",
                        self.fwmark,
                        "table",
                        self.table,
                        "priority",
                        str(RULE_PRIORITY),
                    ],
                    check=False,
                    dry_run=dry_run,
                )
            )
        # replace is atomic and a no-op when the route already matches.
        results.append(
            self.runner.run(
                ["ip", "route", "replace", "default", "dev", device, "table", self.table],
                check=False,
                dry_run=dry_run,
            )
        )
        if not self._unreachable_default_route_present():
            results.append(self._add_unreachable_default_route(dry_run=dry_run))
        return results

    def _rule_present(self) -> bool:
        expected_mark = int(self.fwmark, 0)
        for rule in self._rules():
            mark = rule.get("fwmark")
            table = str(rule.get("table", ""))
            try:
                # iproute2 prints the mark as a hex string (e.g. "0xc01").
                mark_value = int(str(mark), 0) if mark is not None else None
            except ValueError:
                continue
            if mark_value == expected_mark and table == self.table:
                return True
        return False

    def _routes(self) -> list[str]:
        result = self.runner.run(
            ["ip", "route", "show", "table", self.table], check=False, timeout=5
        )
        if not result.ok:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _unreachable_default_route_present(self) -> bool:
        for route in self._routes():
            tokens = route.split()
            if tokens[:2] != ["unreachable", "default"]:
                continue
            if "metric" not in tokens:
                continue
            metric_index = tokens.index("metric") + 1
            if metric_index >= len(tokens):
                continue
            try:
                metric = int(tokens[metric_index], 0)
            except ValueError:
                continue
            if metric == UNREACHABLE_DEFAULT_METRIC:
                return True
        return False

    def _add_unreachable_default_route(self, *, dry_run: bool) -> CommandResult:
        return self.runner.run(
            [
                "ip",
                "route",
                "add",
                "unreachable",
                "default",
                "metric",
                str(UNREACHABLE_DEFAULT_METRIC),
                "table",
                self.table,
            ],
            check=False,
            dry_run=dry_run,
        )

    def cleanup(self, *, dry_run: bool = False) -> list[CommandResult]:
        results = [
            *self._delete_rule(dry_run=dry_run),
            self.runner.run(
                ["ip", "route", "flush", "table", self.table],
                check=False,
                dry_run=dry_run,
            ),
        ]
        if not self._other_configured_managed_rules_present():
            results.append(self._delete_suppress_rule(dry_run=dry_run))
        return results

    def _delete_rule(self, *, dry_run: bool) -> list[CommandResult]:
        return [
            self.runner.run(
                [
                    "ip",
                    "rule",
                    "del",
                    "fwmark",
                    self.fwmark,
                    "table",
                    self.table,
                    "priority",
                    str(RULE_PRIORITY),
                ],
                check=False,
                dry_run=dry_run,
            )
        ]
