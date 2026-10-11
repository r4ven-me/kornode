from __future__ import annotations

import ipaddress
import json

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.routing import RoutingService
from kornode.services.sysctl import SysctlService
from kornode.services.upstream import CARRIER_EXCLUSION_PRIORITY, UpstreamService
from kornode.services.upstream_pushed import PushedRoutingStore


class DoctorService:
    """Network-sanity checks for this node, surfaced as `korctl doctor`.

    Deliberately separate from DiagnosticsService (`korctl diagnose`,
    software versions/raw command dumps): doctor answers "is the routing
    model actually in the state P0 expects", not "show me the raw tool
    output". Every check must degrade to a failing CommandResult instead of
    raising -- this is a diagnostic surface, it must never crash the CLI/API
    it's reported through.
    """

    def __init__(self, config: AppConfig, runner: CommandRunner | None = None) -> None:
        self.config = config
        self.runner = runner or CommandRunner()

    def run(self) -> dict[str, CommandResult]:
        checks = (
            ("sysctl", self._check_sysctl),
            ("overlapping-subnets", self._check_overlapping_subnets),
            ("policy-tables", self._check_policy_tables),
            ("nft-version", self._check_nft_version),
            ("carrier-exclusions", self._check_carrier_exclusions),
        )
        results: dict[str, CommandResult] = {}
        for name, check in checks:
            try:
                results[name] = check()
            except Exception as exc:  # noqa: BLE001 - doctor must never crash
                results[name] = CommandResult((name,), 1, "", f"check failed: {exc}", False)
        return results

    def _check_sysctl(self) -> CommandResult:
        status = SysctlService(self.config, self.runner).check()
        bad = sorted(key for key, ok in status.items() if not ok)
        if bad:
            return CommandResult(
                ("sysctl", "check"), 1, "", f"not applied: {', '.join(bad)}", False
            )
        return CommandResult(("sysctl", "check"), 0, "all required sysctls are applied", "", False)

    def _check_overlapping_subnets(self) -> CommandResult:
        argv = ("ip", "route", "show", "table", "all")
        result = self.runner.run(list(argv), check=False, timeout=10)
        if not result.ok:
            return CommandResult(argv, 1, "", "could not list routes to check for overlaps", False)
        pool = ipaddress.ip_network(self.config.server.ipv4_network, strict=False)
        conflicts: list[str] = []
        for line in result.stdout.splitlines():
            tokens = line.split()
            if not tokens:
                continue
            try:
                network = ipaddress.ip_network(tokens[0], strict=False)
            except ValueError:
                continue
            if network == pool:
                continue  # this node's own VPN pool route, not a conflict with itself
            if network.overlaps(pool):
                conflicts.append(tokens[0])
        for profile in self.config.upstream.profiles:
            for route in PushedRoutingStore(self.config).load(profile).routes:
                try:
                    network = ipaddress.ip_network(route, strict=False)
                except ValueError:
                    continue
                if network.overlaps(pool):
                    conflicts.append(f"{route} (pushed by upstream profile '{profile.name}')")
        if conflicts:
            return CommandResult(
                argv, 1, "", f"overlaps VPN pool {pool}: {', '.join(conflicts)}", False
            )
        return CommandResult(argv, 0, f"no route overlaps VPN pool {pool}", "", False)

    def _table_routes(self, table_id: int) -> list[str]:
        result = self.runner.run(
            ["ip", "route", "show", "table", str(table_id)], check=False, timeout=5
        )
        if not result.ok:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _check_policy_tables(self) -> CommandResult:
        argv = ("ip", "route", "show", "table", "<policy-table>")
        targets = RoutingService(self.config).list_targets(
            default_interface=self.config.routing.main_interface
        )
        upstream = UpstreamService(self.config, runner=self.runner)
        problems: list[str] = []
        checked = 0
        for target in targets:
            if target.profile is None or not upstream.is_profile_connected(target.profile):
                continue
            checked += 1
            routes = self._table_routes(target.table_id)
            has_default = any(line.startswith("default ") for line in routes)
            has_unreachable = any(line.startswith("unreachable default") for line in routes)
            if not (has_default and has_unreachable):
                problems.append(f"table {target.table_id} ('{target.name}') missing default routes")
        if problems:
            return CommandResult(argv, 1, "", "; ".join(problems), False)
        if checked == 0:
            return CommandResult(argv, 0, "no connected upstream profile to check", "", False)
        return CommandResult(argv, 0, f"{checked} policy table(s) OK", "", False)

    def _check_nft_version(self) -> CommandResult:
        nft_result = self.runner.run(["nft", "--version"], check=False, timeout=5)
        if not nft_result.ok:
            return CommandResult(
                ("nft", "--version"), 1, "", "nft userspace tool not found or failed to run", False
            )
        kernel_result = self.runner.run(["uname", "-r"], check=False, timeout=5)
        kernel = kernel_result.stdout.strip() if kernel_result.ok else "unknown"
        # There is no generic, maintainable "is this nft compatible with
        # this kernel" rule -- report both versions for the operator to
        # judge rather than asserting a compatibility check we can't
        # actually back with real knowledge of every kernel/nft pairing.
        message = f"nft: {nft_result.stdout.strip()}; kernel: {kernel}"
        return CommandResult(("nft", "--version"), 0, message, "", False)

    def _check_carrier_exclusions(self) -> CommandResult:
        argv = ("ip", "-j", "rule", "show")
        result = self.runner.run(list(argv), check=False, timeout=5)
        installed: set[str] = set()
        if result.ok:
            try:
                rules = json.loads(result.stdout or "[]")
            except json.JSONDecodeError:
                rules = []
            for rule in rules if isinstance(rules, list) else []:
                if not isinstance(rule, dict):
                    continue
                if rule.get("priority") != CARRIER_EXCLUSION_PRIORITY:
                    continue
                dst = rule.get("dst")
                if isinstance(dst, str):
                    installed.add(dst.split("/")[0])
        upstream = UpstreamService(self.config, runner=self.runner)
        problems: list[str] = []
        checked = 0
        for profile in self.config.upstream.profiles:
            if not upstream.is_profile_connected(profile):
                continue
            checked += 1
            missing = [
                addr
                for addr in upstream.resolved_carrier_addresses(profile)
                if addr not in installed
            ]
            if missing:
                problems.append(f"{profile.name}: missing exclusion for {', '.join(missing)}")
        if problems:
            return CommandResult(argv, 1, "", "; ".join(problems), False)
        if checked == 0:
            return CommandResult(argv, 0, "no connected upstream profiles", "", False)
        return CommandResult(argv, 0, f"{checked} profile(s) excluded", "", False)
