"""Compiled egress -> nft script text. Deterministic, Jinja-free, and never
inlines set elements (D-22): sets are only declared here and filled through
NftElements."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kornode.net.compile import ClassifyRule, DestSetDecl, Exit, NodeFacts
    from kornode.net.model import EgressPolicy

MARK_MASK = "0xffffff00"
OWN_MARKS = "ct mark & 0xff000000 == 0x0c000000"
MSS_CLAMP = "tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
REJECT = "reject with icmpx admin-prohibited"
IMPLICIT_RETURNS = (
    "fib daddr type local return",
    "ip daddr @local_v4 return",
    "ip6 daddr @local_v6 return",
    "ip daddr @carrier_v4 return",
    "ip6 daddr @carrier_v6 return",
)


def _hex(mark: int) -> str:
    return f"0x{mark:08x}"


def _set_decl(name: str, kind: str) -> list[str]:
    if kind == "ifname":
        return [f"  set {name} {{", "    type ifname;", "  }"]
    return [
        f"  set {name} {{",
        f"    type {kind};",
        "    flags interval;",
        "    auto-merge;",
        "  }",
    ]


def _classify_lines(rule: ClassifyRule) -> list[str]:
    """One nft line per address family the rule can match."""
    action = (
        REJECT
        if rule.exit is None
        else f"meta mark set {_hex(rule.exit.mark)} ct mark set meta mark accept"
    )
    comment = f'comment "egress rule {rule.index}"'
    match = list(rule.match)
    v4_only = any(part.startswith("ip saddr") for part in match)
    v6_only = any(part.startswith("ip6 saddr") for part in match)
    if not rule.to_sets:
        return [" ".join(["   ", *match, action, comment])]
    v4_set, v6_set = rule.to_sets
    lines = []
    if not v6_only:
        lines.append(" ".join(["   ", *match, f"ip daddr @{v4_set}", action, comment]))
    if not v4_only:
        lines.append(" ".join(["   ", *match, f"ip6 daddr @{v6_set}", action, comment]))
    return lines


def _kill_switch(exits: tuple[Exit, ...], uplink: str | None) -> list[str]:
    guarded = [exit_ for exit_ in exits if exit_.kill_switch]
    if not guarded:
        return []
    if uplink:
        # D-21: marked traffic must never leave via the uplink; traffic that
        # routing sends to a connected LAN/docker/client network is fine.
        marks = ", ".join(_hex(exit_.mark) for exit_ in guarded)
        return [f'    meta mark & {MARK_MASK} {{ {marks} }} oifname "{uplink}" {REJECT}']
    # Uplink unknown: fall back to the strict per-exit form (fail closed).
    return [
        f'    meta mark & {MARK_MASK} == {_hex(exit_.mark)} oifname != "{exit_.interface}" {REJECT}'
        for exit_ in guarded
        if exit_.interface
    ]


def render_script(
    *,
    exits: tuple[Exit, ...],
    sets: tuple[DestSetDecl, ...],
    classify: tuple[ClassifyRule, ...],
    classify_host: tuple[ClassifyRule, ...],
    facts: NodeFacts,
    policy: EgressPolicy,
) -> str:
    lines: list[str] = ["table inet kornode {"]
    lines += _set_decl("fabric_ifaces", "ifname")
    for name, kind in (
        ("local_v4", "ipv4_addr"),
        ("local_v6", "ipv6_addr"),
        ("carrier_v4", "ipv4_addr"),
        ("carrier_v6", "ipv6_addr"),
    ):
        lines += _set_decl(name, kind)
    for decl in sets:
        lines += _set_decl(decl.name, "ipv4_addr" if decl.family == 4 else "ipv6_addr")

    lines += [
        "  chain prerouting {",
        "    type filter hook prerouting priority mangle; policy accept;",
        f"    {OWN_MARKS} meta mark set ct mark return",
        "    jump egress_classify",
        "  }",
        "  chain egress_classify {",
        *(f"    {line}" for line in IMPLICIT_RETURNS),
    ]
    for rule in classify:
        lines += _classify_lines(rule)
    lines += [
        "  }",
        "  chain output {",
        "    type route hook output priority mangle; policy accept;",
        f"    {OWN_MARKS} meta mark set ct mark return",
        "    jump egress_classify_host",
        "  }",
        "  chain egress_classify_host {",
        "    ct direction reply return",
        *(f"    {line}" for line in IMPLICIT_RETURNS),
    ]
    for rule in classify_host:
        lines += _classify_lines(rule)
    lines += [
        "  }",
        "  chain input {",
        "    type filter hook input priority mangle; policy accept;",
    ]
    # Connections arriving through a tunnel are answered through it too.
    for exit_ in exits:
        if exit_.kind != "local" and exit_.interface:
            lines.append(
                f'    ct state new iifname "{exit_.interface}" ct mark set {_hex(exit_.mark)}'
            )
    kill = _kill_switch(exits, facts.uplink)
    lines += [
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy accept;",
        f"    {MSS_CLAMP}",
        *kill,
        "  }",
        "  chain postrouting {",
        "    type filter hook postrouting priority filter; policy accept;",
        '    oifname "lo" accept',
        f"    {MSS_CLAMP}",
        *kill,
        "  }",
        "}",
        "table ip kornode_nat {",
        "  chain postrouting {",
        "    type nat hook postrouting priority srcnat; policy accept;",
    ]
    for exit_ in exits:
        if not exit_.nat:
            continue
        mark = f"meta mark & {MARK_MASK} == {_hex(exit_.mark)}"
        if exit_.kind == "local":
            lines.append(f'    {mark} oifname != "lo" masquerade')
        elif exit_.interface:
            lines.append(f'    {mark} oifname "{exit_.interface}" masquerade')
    # Unmarked client/source traffic only gets here on its way to this
    # node's own connected networks (it was returned before classification);
    # NAT it so LAN hosts without a route back to the pool still answer (D-26).
    unmarked = f"meta mark & {MARK_MASK} == 0x00000000"
    if facts.client_pool is not None:
        pool = facts.client_pool
        lines.append(f"    ip saddr {pool} ip daddr != {pool} {unmarked} masquerade")
    for source in policy.sources:
        if ":" not in source.cidr:
            lines.append(
                f"    ip saddr {source.cidr} ip daddr != {source.cidr} {unmarked} masquerade"
            )
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"
