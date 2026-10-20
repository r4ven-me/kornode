"""Compiled egress -> nft script text. Deterministic, Jinja-free, and never
inlines set elements (D-22): sets are only declared here and filled through
NftElements."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from kornode.net.errors import PolicyError

if TYPE_CHECKING:
    from kornode.net.compile import ClassifyRule, DestSetDecl, Exit, NodeFacts
    from kornode.net.model import EgressPolicy

MARK_MASK = "0xffffff00"
IFNAME = re.compile(r"[A-Za-z0-9_.-]{1,15}")
IFNAME_GLOB = re.compile(r"[A-Za-z0-9_.-]{1,14}\*")
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


def _kill_switch(exits: tuple[Exit, ...], uplink: str | None, action: str) -> list[str]:
    guarded = [exit_ for exit_ in exits if exit_.kill_switch]
    if not guarded:
        return []
    if uplink:
        # D-21: marked traffic must never leave via the uplink; traffic that
        # routing sends to a connected LAN/docker/client network is fine.
        marks = ", ".join(_hex(exit_.mark) for exit_ in guarded)
        return [f'    meta mark & {MARK_MASK} {{ {marks} }} oifname "{_ifname(uplink)}" {action}']
    # Uplink unknown: fall back to the strict per-exit form (fail closed).
    return [
        f"    meta mark & {MARK_MASK} == {_hex(exit_.mark)} "
        f'oifname != "{_ifname(exit_.interface)}" {action}'
        for exit_ in guarded
        if exit_.interface
    ]


def _stale_marks(exits: tuple[Exit, ...], uplink: str | None, action: str) -> list[str]:
    """D-32: established flows keep the ct mark of the exit they started on.
    Once that exit is gone from the policy its mark has no ip rule and no
    kill-switch, so the flow would fall through to main and leave via the
    uplink without NAT. Any own mark that is not a current exit's never
    leaves via the uplink (anywhere at all when the uplink is unknown)."""
    own = "meta mark & 0xff000000 == 0x0c000000"
    marks = ", ".join(_hex(exit_.mark) for exit_ in exits)
    current = f" meta mark & {MARK_MASK} != {{ {marks} }}" if marks else ""
    oif = f' oifname "{_ifname(uplink)}"' if uplink else ""
    return [f"    {own}{current}{oif} {action}"]


def _ifname(value: str) -> str:
    """Interface names are quoted into the script: anything but a kernel
    ifname could close the quote and inject rules."""
    if not IFNAME.fullmatch(value):
        raise PolicyError(f"invalid interface name: {value!r}")
    return value


def _ifname_glob(value: str) -> str:
    if not IFNAME_GLOB.fullmatch(value):
        raise PolicyError(f"invalid interface name pattern: {value!r}")
    return value


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
        *(
            [
                "    # strict reverse path for ocserv sessions: a session may only use a "
                "source address routed back through its own device (D-47)",
                f'    iifname "{_ifname_glob(facts.enroll.session_iface)}" meta nfproto ipv4 '
                "fib saddr . iif oif missing drop",
            ]
            if facts.enroll is not None
            else []
        ),
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
                f'    ct state new iifname "{_ifname(exit_.interface)}" '
                f"ct mark set {_hex(exit_.mark)}"
            )
    if facts.enroll is not None:
        lines.extend(
            [
                f"    ip saddr {facts.enroll.pool} ip daddr {facts.enroll.address} "
                f"tcp dport {facts.enroll.port} accept",
                f"    ip saddr {facts.enroll.pool} drop",
            ]
        )
    # `reject` is only valid in input/forward/output hooks; the kernel refuses
    # it in postrouting (nft -c does not catch this), so host traffic is
    # dropped there (D-28).
    kill_forward = _kill_switch(exits, facts.uplink, REJECT)
    kill_forward += _stale_marks(exits, facts.uplink, REJECT)
    kill_postrouting = _kill_switch(exits, facts.uplink, "drop")
    kill_postrouting += _stale_marks(exits, facts.uplink, "drop")
    lines += [
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy accept;",
        *(
            [
                f"    ip saddr {facts.enroll.pool} drop",
                f"    ip daddr {facts.enroll.pool} drop",
            ]
            if facts.enroll is not None
            else []
        ),
        f"    {MSS_CLAMP}",
        *kill_forward,
        "  }",
        "  chain postrouting {",
        "    type filter hook postrouting priority filter; policy accept;",
        '    oifname "lo" accept',
        f"    {MSS_CLAMP}",
        *kill_postrouting,
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
            lines.append(f'    {mark} oifname "{_ifname(exit_.interface)}" masquerade')
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
