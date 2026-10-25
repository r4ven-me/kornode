from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig
from kornode.net.sourcecheck import foreign_nat, iptables_nat
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.net import NetService
from kornode.services.password_hash import verify_password
from kornode.services.password_policy import PLACEHOLDER_PASSWORDS, is_placeholder_password


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
            ("agent-versions", self._check_agent_versions),
            ("sources", self._check_sources),
            ("admin-password", self._check_admin_password),
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

    def _check_admin_password(self) -> CommandResult:
        """Warn (never fail) when the panel admin password is a well-known placeholder.

        Existing hubs keep working: the policy applies to new passwords only. A hash is
        checked against the placeholder list too, since examples ship those values."""
        argv = ("doctor", "admin-password")
        web = self.config.web
        weak = False
        if web.admin_password is not None:
            weak = is_placeholder_password(web.admin_password)
        elif web.admin_password_hash is not None:
            weak = any(
                verify_password(candidate, web.admin_password_hash)
                for candidate in sorted(PLACEHOLDER_PASSWORDS)
            )
        if weak:
            return CommandResult(
                argv,
                0,
                "",
                "warning: the web admin password is a well-known placeholder; "
                "change it (panel: Config -> Administrator password)",
                False,
            )
        return CommandResult(argv, 0, "web admin password is not a known placeholder", "", False)

    def _check_agent_versions(self) -> CommandResult:
        """Spec 12 "upgrade required": an agent whose newest report names a version
        below the effective `min_agent_version` refuses the bundles the hub compiles,
        so it stays on its cached configuration until its image is upgraded."""
        argv = ("registry", "agent-versions")
        path = self.config.system.data_dir / "registry.db"
        if not path.exists():
            return CommandResult(argv, 0, "no agents", "", False)
        from kornode.registry.db import migrate, open_registry
        from kornode.registry.repository import Registry
        from kornode.services.bundle import effective_min_agent_version, upgrade_required

        conn = open_registry(path)
        try:
            migrate(conn)
            registry = Registry(conn)
            nodes = registry.list_nodes()
            versions = registry.last_agent_versions()
        finally:
            conn.close()
        minimum = effective_min_agent_version(self.config)
        outdated = [
            f"{node.name} ({versions[node.id]})"
            for node in nodes
            if node.id != 1
            and node.state != "revoked"
            and upgrade_required(versions.get(node.id), minimum)
        ]
        if outdated:
            return CommandResult(
                argv,
                1,
                "",
                f"upgrade required (agent below {minimum}): "
                + "; ".join(outdated)
                + ". Upgrade the agent image; it keeps its cached bundle until then.",
                False,
            )
        reported = sum(1 for node in nodes if node.id in versions and node.state != "revoked")
        return CommandResult(
            argv, 0, f"{reported} reporting agent(s) at or above {minimum}", "", False
        )

    def _check_sources(self) -> CommandResult:
        """Hub sources (D-72, D-68): the interface of every source exists, and no foreign NAT
        (wg-easy PostUp, Amnezia) matches its subnet or interface: kornode owns NAT and
        forwarding for it. Findings are errors only when traffic is provably affected; a
        missing interface is reported too, because the rules then match nothing."""
        argv = ("doctor", "sources")
        sources = tuple(
            (item.name, item.interface, item.cidr) for item in self.config.egress_policy().sources
        )
        if not sources:
            return CommandResult(argv, 0, "no sources configured", "", False)
        problems: list[str] = []
        links = self.runner.run(["ip", "-j", "link", "show"], check=False, timeout=10)
        try:
            present = {str(link["ifname"]) for link in json.loads(links.stdout)}
        except (ValueError, TypeError, KeyError):
            return CommandResult(argv, 1, "", "could not list network interfaces", False)
        problems += [
            f"source {name}: interface {interface} is absent"
            for name, interface, _ in sources
            if interface not in present
        ]
        ruleset = self.runner.run(["nft", "-j", "list", "ruleset"], check=False, timeout=10)
        try:
            if not ruleset.ok:
                raise ValueError("cannot list ruleset")
            found = foreign_nat(json.loads(ruleset.stdout), sources)
            problems += [f["message"] for f in found if f["code"] == "foreign_nat_on_source"]
        except (ValueError, TypeError, AttributeError):
            problems.append("could not inspect the nft ruleset for foreign NAT")
        if _legacy_nat_loaded():
            legacy = self.runner.run(["iptables-legacy-save", "-t", "nat"], check=False, timeout=10)
            if legacy.ok:
                found = iptables_nat(legacy.stdout, sources)
                problems += [f["message"] for f in found if f["code"] == "foreign_nat_on_source"]
        if problems:
            return CommandResult(argv, 1, "", "; ".join(problems[:5]), False)
        return CommandResult(
            argv, 0, f"{len(sources)} source(s) present, no foreign NAT", "", False
        )

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


def _legacy_nat_loaded() -> bool:
    """Asking `iptables-legacy-save -t nat` creates an empty legacy nat table that can pre-empt
    nftables NAT: only look when the table already exists (the doctor must not change what it
    inspects)."""
    try:
        return "nat" in Path("/proc/net/ip_tables_names").read_text().split()
    except OSError:
        return False
