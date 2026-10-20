"""Read-only agent checks. No hub imports and no call to Kernel.apply/run_once."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509

from kornode.net.compile import Compiled, NodeFacts, compile_policy
from kornode.net.diff import diff
from kornode.net.kernel import Kernel
from kornode.net.model import EgressPolicy
from kornode.net.state import OWNED_NFT_TABLES, ActualState
from kornode_agent.inputs import AgentNetInputs

Finding = dict[str, str]

log = logging.getLogger("kornode_agent.doctor")


def finding(code: str, message: str, hint: str, severity: str = "error") -> Finding:
    return {"severity": severity, "code": code, "message": message, "hint": hint}


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


SourceRef = tuple[str, str, str]  # (name, interface, cidr)

_NAT_HINT = (
    "Disable the server's own NAT hooks (wg-easy PostUp/PostDown, Amnezia equivalents): "
    "kornode owns NAT and forwarding for the source subnet."
)


def _values(right: Any) -> list[Any]:
    """Flatten the right-hand side of an nft `match`: scalars, prefixes, ranges, sets."""
    if isinstance(right, dict):
        if "set" in right:
            return [v for item in right["set"] for v in _values(item)]
        if "prefix" in right:
            prefix = right["prefix"]
            return [f"{prefix['addr']}/{prefix['len']}"]
        if "range" in right:
            return [tuple(right["range"])]
        return []
    return [right]


def _networks(values: list[Any]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    found: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        try:
            if isinstance(value, tuple):
                low, high = (ipaddress.ip_address(v) for v in value)
                found.extend(ipaddress.summarize_address_range(low, high))
            else:
                found.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    return found


def _iface_matches(pattern: str, interface: str) -> bool:
    """nft `"wg*"` and iptables `wg+` wildcards as well as exact names."""
    return fnmatch.fnmatchcase(interface, pattern.replace("+", "*"))


def _source_hit(
    sources: tuple[SourceRef, ...],
    saddrs: list[Any],
    ifaces: list[str],
) -> SourceRef | None:
    nets = _networks(saddrs)
    for source in sources:
        _, interface, cidr = source
        network = ipaddress.ip_network(cidr, strict=False)
        if any(_iface_matches(pattern, interface) for pattern in ifaces) or any(
            net.version == network.version and net.overlaps(network) for net in nets
        ):
            return source
    return None


def foreign_nat(doc: dict[str, Any], sources: tuple[SourceRef, ...] = ()) -> list[Finding]:
    """Flag foreign NAT. A masquerade/snat rule that matches a source's subnet or
    interface is an **error** (kornode owns NAT for it, D-68); any other foreign NAT
    stays a warning, because arbitrary nft expressions cannot establish which packets
    a rule matches without evaluating a packet."""
    found = []
    for entry in doc.get("nftables", []):
        rule = entry.get("rule", {})
        if (rule.get("family"), rule.get("table")) in OWNED_NFT_TABLES:
            continue
        expr = [e for e in rule.get("expr", []) if isinstance(e, dict)]
        if not any({"masquerade", "snat"} & e.keys() for e in expr):
            continue
        saddrs: list[Any] = []
        ifaces: list[str] = []
        for item in expr:
            match = item.get("match")
            if not match or match.get("op") not in ("==", "in"):
                continue  # a negated match says nothing about the source
            left = match.get("left", {})
            payload, meta = left.get("payload", {}), left.get("meta", {})
            if payload.get("field") == "saddr":
                saddrs += _values(match.get("right"))
            elif meta.get("key") in ("iifname", "oifname"):
                ifaces += [str(v) for v in _values(match.get("right"))]
        where = f"{rule.get('table')}/{rule.get('chain')}"
        hit = _source_hit(sources, saddrs, ifaces)
        if hit is not None:
            found.append(
                finding(
                    "foreign_nat_on_source",
                    f"Source {hit[0]}: foreign NAT in {where} matches {hit[2]} or {hit[1]}",
                    _NAT_HINT,
                )
            )
        else:
            found.append(
                finding(
                    "foreign_nat",
                    f"Foreign NAT in {where}",
                    "Review whether this NATs owned subnets; not proven by this check.",
                    "warning",
                )
            )
    return found


def _iptables_chains(text: str) -> dict[str, list[list[str]]]:
    chains: dict[str, list[list[str]]] = {}
    for line in text.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if len(tokens) >= 2 and tokens[0] == "-A":
            chains.setdefault(tokens[1], []).append(tokens[2:])
    return chains


def iptables_nat(text: str, sources: tuple[SourceRef, ...]) -> list[Finding]:
    """The legacy iptables backend is invisible to `nft list ruleset`: read the output
    of `iptables-legacy-save -t nat` for MASQUERADE/SNAT rules reachable from POSTROUTING
    (user chains are followed) that match a source; a catch-all NAT is a warning."""
    chains = _iptables_chains(text)
    found: list[Finding] = []
    pending, seen = ["POSTROUTING"], set()
    while pending:
        chain = pending.pop()
        if chain in seen:
            continue
        seen.add(chain)
        for rule in chains.get(chain, []):
            if "-j" not in rule or rule.index("-j") + 1 >= len(rule):
                continue
            target = rule[rule.index("-j") + 1]
            if target not in ("MASQUERADE", "SNAT"):
                if target in chains:
                    pending.append(target)
                continue
            saddrs: list[str] = []
            ifaces: list[str] = []
            negated = False
            for position, token in enumerate(rule):
                if token == "!":
                    negated = True
                    continue
                if position + 1 < len(rule) and not negated:
                    if token in ("-s", "--source"):
                        saddrs.append(rule[position + 1])
                    elif token in ("-i", "-o", "--in-interface", "--out-interface"):
                        ifaces.append(rule[position + 1])
                if token.startswith("-"):
                    negated = False
            text_rule = " ".join(rule)[:120]
            hit = _source_hit(sources, saddrs, ifaces)
            if hit is not None:
                found.append(
                    finding(
                        "foreign_nat_on_source",
                        f"Source {hit[0]}: iptables NAT matches {hit[2]} or {hit[1]}: {text_rule}",
                        _NAT_HINT,
                    )
                )
            elif not saddrs and not ifaces:
                found.append(
                    finding(
                        "foreign_nat",
                        f"Unscoped iptables NAT in {chain}: {text_rule}",
                        "Review whether this NATs owned subnets; not proven by this check.",
                        "warning",
                    )
                )
    return found


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
