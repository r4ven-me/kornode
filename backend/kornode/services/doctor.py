from __future__ import annotations

import ipaddress
from typing import Any

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.net import NetService


class DoctorService:
    """Network-sanity checks for this node, surfaced as `korctl doctor`.

    Deliberately separate from DiagnosticsService (`korctl diagnose`,
    software versions/raw command dumps): doctor answers "is the routing
    model actually in the state P0 expects", not "show me the raw tool
    output". Every check must degrade to a failing CommandResult instead of
    raising -- this is a diagnostic surface, it must never crash the CLI/API
    it's reported through.
    """

    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        net: NetService | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.net = net or NetService(config, runner=self.runner)
        self._cached_plan: dict[str, Any] | None = None

    def run(self) -> dict[str, CommandResult]:
        checks = (
            ("kernel-plan", self._check_kernel_plan),
            ("sysctl", self._check_sysctl),
            ("overlapping-subnets", self._check_overlapping_subnets),
            ("policy-tables", self._check_exit_tables),
            ("nft-version", self._check_nft_version),
            ("carrier-exclusions", self._check_carrier_exclusions),
            ("access-certificates", self._check_access_certificates),
        )
        results: dict[str, CommandResult] = {}
        for name, check in checks:
            try:
                results[name] = check()
            except Exception as exc:  # noqa: BLE001 - doctor must never crash
                results[name] = CommandResult((name,), 1, "", f"check failed: {exc}", False)
        return results

    def _check_sysctl(self) -> CommandResult:
        return self._verdict(
            ("sysctl", "check"), self._pending({"SetSysctl"}), "all required sysctls are applied"
        )

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
        if conflicts:
            return CommandResult(
                argv, 1, "", f"overlaps VPN pool {pool}: {', '.join(conflicts)}", False
            )
        return CommandResult(argv, 0, f"no route overlaps VPN pool {pool}", "", False)

    def _pending(self, kinds: set[str]) -> list[str]:
        plan = self._plan()
        return [str(op["text"]) for op in plan["ops"] if op["op"] in kinds]

    def _plan(self) -> dict[str, Any]:
        if self._cached_plan is None:
            self._cached_plan = self.net.plan()
        return self._cached_plan

    def _verdict(self, argv: tuple[str, ...], pending: list[str], ok: str) -> CommandResult:
        if not pending:
            return CommandResult(argv, 0, ok, "", False)
        shown = "; ".join(pending[:5])
        if len(pending) > 5:
            shown += f"; ... {len(pending)} in total"
        return CommandResult(argv, 1, "", f"kernel differs from the policy: {shown}", False)

    def _check_kernel_plan(self) -> CommandResult:
        return self._verdict(
            ("net", "plan"),
            [str(op["text"]) for op in self._plan()["ops"]],
            "the kernel matches the compiled policy",
        )

    def _check_exit_tables(self) -> CommandResult:
        # Exit tables (default via the tunnel + the killswitch route) are
        # reconciler state: a missing or stale route is a pending plan op.
        return self._verdict(
            ("net", "plan", "routes"),
            self._pending({"ReplaceRoute", "DelRoute"}),
            f"{len(self._plan()['exits'])} exit(s), routes as planned",
        )

    def _check_carrier_exclusions(self) -> CommandResult:
        return self._verdict(
            ("net", "plan", "rules"),
            self._pending({"AddRule", "DelRule"}),
            "policy rules (carrier exclusions included) as planned",
        )

    def _check_access_certificates(self) -> CommandResult:
        """Listener certificates of agents with role access (P4-04, D-67) are
        valid for 825 days and renewed only on request: warn 30 days ahead,
        because clients pin them and an expired one fails without any signal."""
        argv = ("registry", "access-certificates")
        path = self.config.system.data_dir / "registry.db"
        if not path.exists():
            return CommandResult(argv, 0, "no agent access listeners", "", False)
        from datetime import UTC, datetime, timedelta

        from kornode.registry.db import migrate, open_registry
        from kornode.registry.repository import Registry

        conn = open_registry(path)
        try:
            migrate(conn)
            nodes = Registry(conn).list_nodes()
        finally:
            conn.close()
        limit = datetime.now(UTC) + timedelta(days=30)
        due = []
        for node in nodes:
            raw = node.access.get("cert_not_after")
            if node.state == "revoked" or not raw:
                continue
            if datetime.fromisoformat(str(raw).replace("Z", "+00:00")) < limit:
                due.append(
                    f"{node.name} ({raw}): korctl agent access set {node.name} --reissue ..."
                )
        if due:
            return CommandResult(
                argv, 1, "", "listener certificate expires within 30 days: " + "; ".join(due), False
            )
        listeners = sum(1 for node in nodes if node.access.get("cert_not_after"))
        return CommandResult(argv, 0, f"{listeners} agent access listener(s) valid", "", False)

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
