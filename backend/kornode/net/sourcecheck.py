"""Foreign-NAT inspection for attached sources (D-68), shared by the agent and the hub doctor.

Pure functions over `nft -j list ruleset` JSON and `iptables-legacy-save -t nat` text: kornode
owns NAT and forwarding for a source's subnet, so another masquerade/SNAT that matches it is
an error.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import shlex
from typing import Any

from kornode.net.state import OWNED_NFT_TABLES

Finding = dict[str, str]


def finding(code: str, message: str, hint: str, severity: str = "error") -> Finding:
    return {"severity": severity, "code": code, "message": message, "hint": hint}


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
