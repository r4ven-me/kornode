"""Read-only agent checks. No hub imports and no call to Kernel.apply/run_once."""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509

from kornode.net.compile import Compiled, NodeFacts, compile_policy
from kornode.net.diff import diff
from kornode.net.kernel import Kernel
from kornode.net.model import EgressPolicy
from kornode.net.sourcecheck import (  # noqa: F401 - re-exported for callers and tests
    Finding,
    SourceRef,
    finding,
    foreign_nat,
    iptables_nat,
)
from kornode.net.state import ActualState
from kornode_agent.inputs import AgentNetInputs

__all__ = [
    "Finding",
    "SourceRef",
    "finding",
    "foreign_nat",
    "inspect_state",
    "iptables_nat",
    "run_doctor",
]

log = logging.getLogger("kornode_agent.doctor")


def inspect_state(
    compiled: Compiled,
    policy: EgressPolicy,
    facts: NodeFacts,
    actual: ActualState,
    mtus: dict[str, int],
) -> list[Finding]:
    desired = compiled.desired
    out = []
    for sysctl in sorted(desired.sysctls - actual.sysctls, key=lambda s: s.key):
        out.append(
            finding(
                "sysctl_mismatch",
                f"{sysctl.key} must be {sysctl.value}",
                "Check reconciler errors and host sysctl overrides.",
            )
        )
    for route in sorted(desired.routes - actual.routes, key=lambda r: r.key):
        code = "exit_guard_missing" if route.type == "unreachable" else "route_drift"
        out.append(
            finding(
                code,
                f"table {route.table}: missing {route.type} {route.dst}",
                "Check tunnel state and the reconciler; do not add routes manually.",
            )
        )
    if desired.rules - actual.rules:
        out.append(
            finding(
                "carrier_exclusion_missing",
                "Policy rules differ from desired state",
                "Check rule priorities, carrier resolution and reconciler errors.",
            )
        )
    if (
        desired.nft and desired.nft.schema_hash != actual.nft_schema_hash
    ) or desired.elements != actual.elements:
        out.append(
            finding(
                "nft_drift",
                "Owned nftables schema or set contents differ",
                "Check reconciler errors and competing firewall tools.",
            )
        )
    if not diff(actual, desired).is_empty:
        out.append(
            finding(
                "kernel_drift",
                "Kernel does not match the active policy",
                "Inspect the reconciler's last error and pending plan.",
            )
        )
    for source in policy.sources:
        fact = facts.sources.get(source.name)
        if fact is None or not fact.present:
            out.append(
                finding(
                    "missing_source",
                    f"Source {source.name}: {source.interface} is absent",
                    "Start the attached access service or correct its interface.",
                    "warning",
                )
            )
    owned = ([facts.client_pool] if facts.client_pool else []) + [
        ipaddress.ip_network(s.cidr) for s in policy.sources
    ]
    for network in owned:
        for local in facts.local_networks:
            if network.version == local.version and network.overlaps(local):
                if network == local == facts.client_pool:
                    continue  # this node's own access pool is connected by design
                if network == facts.client_pool and local.prefixlen == local.max_prefixlen:
                    continue  # per-session host routes of connected access clients (vpns*)
                # A configured source's own connected subnet is expected.
                if any(ipaddress.ip_network(s.cidr) == network == local for s in policy.sources):
                    continue
                out.append(
                    finding(
                        "overlapping_networks",
                        f"{network} overlaps connected {local}",
                        "Correct the hub's node/source addressing.",
                    )
                )
    for tunnel in facts.tunnels.values():
        mtu = mtus.get(tunnel.interface)
        if mtu is not None and mtu < 1280:
            out.append(
                finding(
                    "low_mtu",
                    f"{tunnel.interface}: MTU {mtu} < 1280",
                    "Check nested tunnel MTUs and MSS clamping.",
                    "warning",
                )
            )
    out.extend(
        finding("policy_warning", str(w), "Review the node's egress policy.", "warning")
        for w in compiled.warnings
        # `missing_source` above already reports a source whose interface is absent.
        if not str(w).startswith("source '")
    )
    return out


def _capture(argv: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
        return result.returncode == 0, result.stdout
    except (OSError, subprocess.SubprocessError):
        return False, ""


def _legacy_nat_loaded() -> bool:
    """Whether the legacy `nat` table already exists in this netns. Asking
    `iptables-legacy-save -t nat` otherwise *creates* an empty one, and an empty legacy
    nat table can pre-empt nftables NAT: the doctor must never change what it inspects."""
    try:
        return "nat" in Path("/proc/net/ip_tables_names").read_text().split()
    except OSError:
        return False


def run_doctor(inputs: AgentNetInputs, root: Path, kernel: Kernel) -> list[Finding]:
    findings = []
    try:
        policy, facts = inputs.policy(), inputs.facts()
        compiled = compile_policy(policy, facts)
        mtus = {}
        for tunnel in facts.tunnels.values():
            try:
                mtus[tunnel.interface] = int(
                    (Path("/sys/class/net") / tunnel.interface / "mtu").read_text()
                )
            except (OSError, ValueError):
                findings.append(
                    finding(
                        "mtu_unavailable",
                        f"Cannot read MTU for {tunnel.interface}",
                        "Check tunnel presence and sysfs access.",
                        "warning",
                    )
                )
        d = compiled.desired
        actual = kernel.read(
            [s.key for s in d.sysctls],
            sorted({r.chain_key for r in d.foreign_rules}),
            sorted({a.dev for a in d.addresses}),
        )
        findings += inspect_state(compiled, policy, facts, actual, mtus)
    except Exception as exc:
        log.error("kernel inspection failed: %s", type(exc).__name__)
        findings.append(
            finding(
                "kernel_unavailable",
                "Cannot inspect kernel state",
                "Run as the agent owner with NET_ADMIN and inspect runtime errors.",
            )
        )
    ok, output = _capture(["nft", "--version"])
    findings.append(
        finding(
            "nft_version" if ok else "nft_unavailable",
            output.strip() if ok else "Cannot run nft --version",
            "Version information only; compatibility is not inferred.",
            "info" if ok else "error",
        )
    )
    try:
        sources = tuple((item.name, item.interface, item.cidr) for item in inputs.policy().sources)
    except Exception as exc:
        log.error("source lookup failed: %s", type(exc).__name__)
        sources = ()
    ok, output = _capture(["nft", "-j", "list", "ruleset"])
    try:
        if not ok:
            raise ValueError("cannot list ruleset")
        findings += foreign_nat(json.loads(output), sources)
    except (ValueError, TypeError, AttributeError):
        findings.append(
            finding(
                "foreign_nat_unchecked",
                "Cannot inspect foreign NAT",
                "Check nft permissions and JSON output.",
                "warning",
            )
        )
    if sources and _legacy_nat_loaded():
        ok, output = _capture(["iptables-legacy-save", "-t", "nat"])
        if ok:
            try:
                findings += iptables_nat(output, sources)
            except (ValueError, IndexError, KeyError):
                findings.append(
                    finding(
                        "foreign_nat_unchecked",
                        "Cannot parse the legacy iptables NAT rules",
                        "Inspect `iptables-legacy-save -t nat` by hand.",
                        "warning",
                    )
                )
    try:
        cert = x509.load_pem_x509_certificate((root / "tls/cert.pem").read_bytes())
        now = datetime.now(UTC)
        if now < cert.not_valid_before_utc or now >= cert.not_valid_after_utc:
            findings.append(
                finding(
                    "certificate_invalid_time",
                    "Agent certificate is not currently valid",
                    "Check the local clock and enrollment/renewal.",
                )
            )
        elif (cert.not_valid_after_utc - now).total_seconds() <= 14 * 86400:
            findings.append(
                finding(
                    "certificate_expiring",
                    "Agent certificate expires within 14 days",
                    "Check hub reachability and renewal errors.",
                    "warning",
                )
            )
    except (OSError, ValueError):
        findings.append(
            finding(
                "certificate_unavailable",
                "Cannot read agent certificate",
                "Check enrollment and TLS file permissions.",
            )
        )
    findings.append(
        finding(
            "clock_skew_unchecked",
            "No trusted hub time observation available",
            "Check host time synchronization independently.",
            "info",
        )
    )
    return findings
