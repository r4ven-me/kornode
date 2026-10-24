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


def label_bits(label: str) -> str:
    """nft ct_label literals are bit *indices*, not integer bitmaps (ct.c).

    A parenthesized OR expression represents the complete 128-bit identity.
    Commas are accepted for comparisons but NOT in ct-label assignment grammar.
    Validation uses explicit ==, never implicit flag membership. The kernel's
    label setter ORs bits rather than clearing them, so validate after setting
    too: preexisting foreign/failed labels must fail closed on the first packet.
    """
    value = int(label, 16)
    if not 0 < value < 1 << 128:
        raise PolicyError("conntrack identity must be a nonzero 128-bit label")
    return "(" + " | ".join(str(bit) for bit in range(128) if value & (1 << bit)) + ")"


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
    if rule.exit is None:
        action = rule.verdict or REJECT
    else:
        action = (
            f"meta mark set {_hex(rule.exit.mark)} ct mark set meta mark "
            f"ct label set {label_bits(rule.exit.identity_label)} goto validate_connection"
        )
    comment = f'comment "{rule.label or f"egress rule {rule.index}"}"'
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
    down = [
        exit_ for exit_ in exits if exit_.kill_switch and exit_.kind == "upstream" and not exit_.up
    ]
    blocked = [f"    meta mark & {MARK_MASK} == {_hex(exit_.mark)} {action}" for exit_ in down]
    guarded = [exit_ for exit_ in exits if exit_.kill_switch and exit_ not in down]
    if not guarded:
        return blocked
    if uplink:
        # D-21: marked traffic must never leave via the uplink; traffic that
        # routing sends to a connected LAN/docker/client network is fine.
        marks = ", ".join(_hex(exit_.mark) for exit_ in guarded)
        return blocked + [
            f'    meta mark & {MARK_MASK} {{ {marks} }} oifname "{_ifname(uplink)}" {action}'
        ]
    # Uplink unknown: fall back to the strict per-exit form (fail closed).
    return blocked + [
        f"    meta mark & {MARK_MASK} == {_hex(exit_.mark)} "
        f'oifname != "{_ifname(exit_.interface)}" {action}'
        for exit_ in guarded
        if exit_.interface
    ]


def _local_icmp_errors(uplink: str | None) -> list[str]:
    """ICMP errors this node sends back toward a client must not die with the flow.

    When an exit is down its table answers with ``unreachable`` and the kernel
    (or a forward ``reject``) sends an ICMP error. ``icmp_send`` attaches the
    flow's conntrack, so output restores the dead exit's mark onto the error
    and the unconditional postrouting drop for that mark would swallow it:
    the promised fast failure (D-28) becomes a silent timeout. Errors that
    originate here and leave through anything but the uplink are let through
    before the kill switch; toward the uplink, and when the uplink is unknown,
    the kill switch still applies (fail closed).
    """
    if not uplink:
        return []
    out = f'oifname != "{_ifname(uplink)}"'
    return [
        "    meta l4proto icmp icmp type { destination-unreachable, time-exceeded, "
        f"parameter-problem }} fib saddr type local {out} accept",
        "    meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, "
        f"time-exceeded, parameter-problem }} fib saddr type local {out} accept",
    ]


def _stale_marks(exits: tuple[Exit, ...], uplink: str | None, action: str) -> list[str]:
    """Defense in depth: removed and legacy marks may not leave on any
    interface, even if a main-table route points somewhere other than the
    reported uplink. Identity validation in the early hooks also protects
    against a historical numeric-mark collision.
    """
    own = "meta mark & 0xff000000 == 0x0c000000"
    marks = ", ".join(_hex(exit_.mark) for exit_ in exits)
    current = f" meta mark & {MARK_MASK} != {{ {marks} }}" if marks else ""
    return [f"    {own}{current} {action}"]


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


def _session_rpf(facts: NodeFacts) -> list[str]:
    """Strict reverse path for ocserv sessions: a session may only use a
    source address routed back through its own device (D-47)."""
    globs = [facts.enroll.session_iface] if facts.enroll is not None else []
    globs += [item for item in facts.access_ifaces if item not in globs]
    if not globs:
        return []
    lines: list[str] = []
    if facts.transit_exits:
        # D-69: answers from an exit node carry the internet's addresses, which are
        # not routed through its session; the flow is established by a marked packet
        # that passed the check when it came in from the agent.
        lines.append(
            "    iifname @transit_ifaces ct direction reply ct state established,related return"
        )
    lines += [
        "    # strict reverse path for ocserv sessions: a session may only use a "
        "source address routed back through its own device (D-47)"
    ]
    lines += [
        f'    iifname "{_ifname_glob(item)}" meta nfproto ipv4 fib saddr . iif oif missing drop'
        for item in globs
    ]
    return lines


def _access_input(facts: NodeFacts) -> list[str]:
    """VPN clients of an access node reach the node's own services only for DNS and
    ping (D-67); forwarded traffic (LAN, interlink, exits) is governed by the egress
    policy as usual. Anything else addressed to the host is dropped."""
    lines: list[str] = []
    for glob in facts.access_ifaces:
        iface = _ifname_glob(glob)
        lines.append(f'    iifname "{iface}" ct state established,related accept')
        for address in facts.local_addresses:  # the node resolver
            for proto in ("udp", "tcp"):
                lines.append(f'    iifname "{iface}" ip daddr {address} {proto} dport 53 accept')
        lines.append(f'    iifname "{iface}" icmp type echo-request accept')
        lines.append(f'    iifname "{iface}" fib daddr type local drop')
    return lines


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
    lines += _set_decl("interlink_ifaces", "ifname")
    if facts.transit_exits:
        lines += _set_decl("transit_ifaces", "ifname")
    for name, kind in (
        ("local_v4", "ipv4_addr"),
        ("local_v6", "ipv6_addr"),
        ("carrier_v4", "ipv4_addr"),
        ("carrier_v6", "ipv6_addr"),
    ):
        lines += _set_decl(name, kind)
    for decl in sets:
        lines += _set_decl(decl.name, "ipv4_addr" if decl.family == 4 else "ipv6_addr")

    # A numeric mark alone is not an identity: hashes can collide after an
    # exit was deleted. Labels travel with conntrack across process restarts;
    # legacy (unlabeled), removed and colliding flows must never be adopted.
    lines += ["  chain validate_connection {"]
    for exit_ in exits:
        lines.append(
            f"    ct mark & {MARK_MASK} == {_hex(exit_.mark)} "
            f"ct label == {label_bits(exit_.identity_label)} return"
        )
    lines += ["    drop", "  }"]
    rpf = _session_rpf(facts)
    if rpf:
        # A reply exemption must return only from RPF, not from prerouting:
        # the latter would also bypass conntrack identity validation/barriers.
        lines += ["  chain session_rpf {", *rpf, "  }"]
    lines += [
        "  chain prerouting {",
        "    type filter hook prerouting priority mangle; policy accept;",
        *(["    jump session_rpf"] if rpf else []),
        f"    {OWN_MARKS} meta mark set ct mark goto validate_connection",
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
        f"    {OWN_MARKS} meta mark set ct mark goto validate_connection",
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
    # Connections arriving through a tunnel are answered through it too. One mark per
    # interface (the first exit wins: on an agent `interlink` precedes `node:<n>`, which
    # shares the hub tunnel); a hub transit exit's session device changes with every
    # connect and its main-table routes already answer the node.
    answered: set[str] = set()
    for exit_ in exits:
        if exit_.kind == "local" or not exit_.interface or exit_.interface in answered:
            continue
        if exit_.kind == "node" and facts.interlink_guard:
            continue
        answered.add(exit_.interface)
        lines.append(
            f'    ct state new iifname "{_ifname(exit_.interface)}" ct mark set {_hex(exit_.mark)} '
            f"ct label set {label_bits(exit_.identity_label)}"
        )
    lines += _access_input(facts)
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
        *_local_icmp_errors(facts.uplink),
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
