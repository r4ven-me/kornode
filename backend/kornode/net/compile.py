"""(EgressPolicy, NodeFacts) -> DesiredState. Pure and deterministic.

Kernel layout per docs/spec/03-kernel-dataplane.md, rule semantics per
docs/spec/02-egress-and-sources.md, with the netlab-driven decisions D-20
(carrier never marked), D-21 (kill-switch drops on the uplink) and D-24..D-27
(this module).
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field

from kornode.net.errors import PolicyError
from kornode.net.model import EgressPolicy, InlineDest, NodeRef, Rule, SetRef, Via
from kornode.net.state import (
    KORNODE_RTPROTO,
    MAIN_TABLE,
    Address,
    DesiredState,
    Family,
    ForeignNftRule,
    IpRule,
    NftElements,
    NftRuleset,
    Route,
    Sysctl,
)

MARK_BASE = 0x0C000000
MARK_MASK = 0xFFFFFF00
TABLE_BASE = 12000
SUPPRESS_PRIORITY = 90
CARRIER_PRIORITY = 95
EXIT_PRIORITY_BASE = 100
KILL_SWITCH_METRIC = 4096
FILTER_TABLE = ("inet", "kornode")
NAT_TABLE = ("ip", "kornode_nat")
FAMILIES: tuple[Family, Family] = (4, 6)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class TunnelFact:
    """An exit's tunnel as it is right now. `interface` is the device the
    exit sends through (agent: tun to the hub for `interlink`; hub: an agent's
    vpnsN session for `node:<n>`)."""

    interface: str
    up: bool
    carrier: tuple[str, ...] = ()
    mtu: int | None = None


@dataclass(frozen=True, slots=True)
class SourceFact:
    present: bool


@dataclass(frozen=True, slots=True)
class EnrollGuard:
    pool: ipaddress.IPv4Network
    address: ipaddress.IPv4Address
    port: int
    # Glob of ocserv session devices ("vpns*"): strict reverse-path check (D-47).
    session_iface: str = "vpns*"


@dataclass(frozen=True, slots=True)
class TransitExit:
    """Hub only (D-69): the traffic of agents whose policy says `node:<n>` leaves
    through that node's ocserv session. `sources` are the prefixes those agents send
    from (client pool, source subnets); `exit_iface` is the node's session device right
    now, None while it is offline (the exit table then only fails closed)."""

    node: int
    sources: tuple[Network, ...]
    exit_iface: str | None
    # Set/domain exits (D-79): only these destinations of `sources` leave through the
    # node (routes plus the addresses the agent reported); None means `to: any`.
    dest: frozenset[str] | None = None


@dataclass(frozen=True, slots=True)
class NodeFacts:
    node_id: int
    client_pool: ipaddress.IPv4Network | None
    tunnels: Mapping[str, TunnelFact] = field(default_factory=dict)
    sources: Mapping[str, SourceFact] = field(default_factory=dict)
    local_networks: tuple[Network, ...] = ()
    resolved: Mapping[str, frozenset[str]] = field(default_factory=dict)
    upstreams: tuple[str, ...] = ()
    # Alias selection is independent of tunnel/link availability.
    active_upstream: str | None = None
    disabled_upstreams: tuple[str, ...] = ()
    node_prefixes: Mapping[int, tuple[Network, ...]] = field(default_factory=dict)
    interlink_ifaces: tuple[str, ...] = ()
    # Hub: (exported agent prefix, ocserv session device) for connected agents;
    # installed in main since ocserv's iroute does not (S-03, D-63).
    session_routes: tuple[tuple[Network, str], ...] = ()
    uplink: str | None = None
    all_rp_filter: str | None = None
    enroll: EnrollGuard | None = None
    # Hub control-plane address, bound to `lo` so it never depends on a link.
    service_address: ipaddress.IPv4Address | None = None
    # Further addresses bound to `lo`, e.g. an agent's resolver address (D-66).
    local_addresses: tuple[ipaddress.IPv4Address, ...] = ()
    # Hub: agent sessions are policed (D-69): traffic of an agent to a non-interlink
    # destination is dropped unless an agent policy declares an exit for its source.
    interlink_guard: bool = False
    transit_exits: tuple[TransitExit, ...] = ()
    # Globs of the agent's own ocserv session devices ("vpns*", role access):
    # the same strict reverse-path check as the hub's enroll guard (D-47, D-67).
    access_ifaces: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Exit:
    name: str
    kind: str
    index: int
    interface: str | None
    up: bool
    kill_switch: bool
    nat: bool

    @property
    def mark(self) -> int:
        return exit_mark(self.name)

    @property
    def identity_label(self) -> str:
        return "0x" + hashlib.sha256(self.name.encode("utf-8")).hexdigest()[:32]

    @property
    def table(self) -> int:
        return TABLE_BASE + self.index

    @property
    def has_table(self) -> bool:
        return self.kind not in ("local", "drop")


@dataclass(frozen=True, slots=True)
class DestSetDecl:
    name: str
    family: int


@dataclass(frozen=True, slots=True)
class ClassifyRule:
    index: int
    from_: str
    match: tuple[str, ...]
    to_sets: tuple[str, ...]
    exit: Exit | None
    # Instead of rejecting when `exit` is None (e.g. "return": leave unmarked).
    verdict: str | None = None
    # Replaces the "egress rule N" comment (transit and guard lines have no rule number).
    label: str | None = None


@dataclass(frozen=True, slots=True)
class Compiled:
    desired: DesiredState
    exits: tuple[Exit, ...]
    sets: tuple[DestSetDecl, ...]
    classify: tuple[ClassifyRule, ...]
    classify_host: tuple[ClassifyRule, ...]
    script: str
    warnings: tuple[str, ...]


def exit_mark(name: str) -> int:
    """Stable identity, not a policy position. The high index bit separates
    these marks from the legacy positional allocation (at most 99 exits).
    Local/interlink marks are reserved, never candidates for upstream collisions.
    Conntrack labels disambiguate even a collision with a *deleted* identity.
    """
    if name == "local":
        slot = 0x8000
    elif name == "interlink":
        slot = 0x8001
    else:
        digest = hashlib.sha256(name.encode("utf-8")).digest()
        slot = 0x8002 + int.from_bytes(digest[:4], "big") % 0x7FFE
    return MARK_BASE | (slot << 8)


def _resolved_via(via: Via, facts: NodeFacts) -> Via:
    if via.name == "upstream:active" and facts.active_upstream is not None:
        return Via("upstream", facts.active_upstream)
    return via


def _addresses(facts: NodeFacts) -> frozenset[Address]:
    bound = (facts.service_address, *facts.local_addresses)
    return frozenset(Address("lo", f"{address}/32") for address in bound if address is not None)


def gateway_tunnels(policy: EgressPolicy, interface: str, up: bool) -> dict[str, TunnelFact]:
    """An agent reaches `node:<n>` through its tunnel to the hub (D-69): one tunnel
    fact per gateway node named by the policy, all on the interlink interface."""
    return {
        rule.parsed_via.name: TunnelFact(interface=interface, up=up)
        for rule in policy.egress
        if rule.parsed_via.kind == "node"
    }


def _dest_name(rule: Rule, index: int) -> str | None:
    to = rule.to
    if to == "any":
        return None
    if to == "interlink":
        return "interlink"
    if isinstance(to, SetRef):
        return to.set
    if isinstance(to, NodeRef):
        return f"node{to.node}"
    return f"rule{index}"


def dest_members(
    rule: Rule, index: int, policy: EgressPolicy, facts: NodeFacts
) -> tuple[frozenset[str], bool]:
    """Destination elements (routes + resolved domain addresses) and whether
    the destination involves domains."""
    to = rule.to
    if to == "interlink":
        prefixes = {
            str(prefix)
            for node, items in facts.node_prefixes.items()
            if node != facts.node_id
            for prefix in items
        }
        return frozenset(prefixes), False
    if isinstance(to, NodeRef):
        return frozenset(str(prefix) for prefix in facts.node_prefixes.get(to.node, ())), False
    if isinstance(to, SetRef):
        dest = policy.sets[to.set]
        resolved = facts.resolved.get(to.set, frozenset())
        return frozenset(dest.routes) | resolved, bool(
            dest.domains or dest.domain_urls or dest.route_urls
        )
    assert isinstance(to, InlineDest)
    resolved = facts.resolved.get(to.resolved_key(), frozenset())
    return frozenset(to.routes) | resolved, bool(to.domains)


def _validate(policy: EgressPolicy, facts: NodeFacts) -> None:
    for index, rule in enumerate(policy.egress):
        via = rule.parsed_via
        if via.kind == "upstream" and via.target != "active" and via.target not in facts.upstreams:
            raise PolicyError(f"rule {index}: unknown upstream {via.target!r}")
        if via.kind == "node":
            node = int(via.target or 0)
            if node == facts.node_id:
                raise PolicyError(f"rule {index}: node:{node} is this node")
            if node not in facts.node_prefixes:
                raise PolicyError(f"rule {index}: unknown node {node} in node:{node}")
        if isinstance(rule.to, NodeRef) and rule.to.node not in facts.node_prefixes:
            raise PolicyError(f"rule {index}: unknown node {rule.to.node}")
        if "clients" in rule.from_ and facts.client_pool is None:
            raise PolicyError(f"rule {index}: `clients` used but this node has no client pool")


def _covers(earlier: Rule, later: Rule, policy: EgressPolicy) -> bool:
    if not set(later.from_) <= set(earlier.from_):
        return False
    if earlier.to == "any":
        return True
    if later.to == "any":
        return False
    if later.to == earlier.to:
        return not _has_domains(later, policy)
    if earlier.to == "interlink" and isinstance(later.to, NodeRef):
        return True
    if isinstance(later.to, InlineDest) and not later.to.domains and later.to.routes:
        earlier_routes = _static_routes(earlier, policy)
        return earlier_routes is not None and all(
            any(
                ipaddress.ip_network(route).subnet_of(ipaddress.ip_network(other))  # type: ignore[arg-type]
                for other in earlier_routes
                if ipaddress.ip_network(other).version == ipaddress.ip_network(route).version
            )
            for route in later.to.routes
        )
    return False


def _has_domains(rule: Rule, policy: EgressPolicy) -> bool:
    if isinstance(rule.to, InlineDest):
        return bool(rule.to.domains)
    if isinstance(rule.to, SetRef):
        dest = policy.sets[rule.to.set]
        return bool(dest.domains or dest.domain_urls or dest.route_urls)
    return False


def _static_routes(rule: Rule, policy: EgressPolicy) -> tuple[str, ...] | None:
    if isinstance(rule.to, InlineDest):
        return rule.to.routes
    if isinstance(rule.to, SetRef):
        dest = policy.sets[rule.to.set]
        return dest.routes
    return None


def dead_rules(policy: EgressPolicy) -> list[tuple[int, int]]:
    """(dead rule index, shadowing rule index) for rules fully covered by an
    earlier one. Domain-based destinations are never considered covered."""
    found: list[tuple[int, int]] = []
    for later_index, later in enumerate(policy.egress):
        for earlier_index in range(later_index):
            if _covers(policy.egress[earlier_index], later, policy):
                found.append((later_index, earlier_index))
                break
    return found


def compile_policy(policy: EgressPolicy, facts: NodeFacts) -> Compiled:
    _validate(policy, facts)

    if "active" in facts.upstreams:
        raise PolicyError(
            "upstream profile slug 'active' is reserved for the selected-profile alias"
        )
    if facts.active_upstream is not None and facts.active_upstream not in facts.upstreams:
        raise PolicyError("active upstream is not a known profile")
    exits: dict[str, Exit] = {}
    for rule in policy.egress:
        via = _resolved_via(rule.parsed_via, facts)
        if via.kind == "drop" or via.name in exits:
            continue
        exits[via.name] = _make_exit(via, len(exits) + 1, policy, facts)
    # Hub (D-69): the exits declared by agents' policies, one per gateway node.
    for transit in facts.transit_exits:
        name = f"node:{transit.node}"
        if name not in exits:
            exits[name] = Exit(
                name=name,
                kind="node",
                index=len(exits) + 1,
                interface=transit.exit_iface,
                up=transit.exit_iface is not None,
                kill_switch=True,
                nat=False,
            )

    # Priorities 100+i must stay inside 90..199; the mark space is separate.
    if len(exits) > 99:
        raise PolicyError("at most 99 distinct exits are supported")
    marks: dict[int, str] = {}
    for candidate in exits.values():
        previous = marks.setdefault(candidate.mark, candidate.name)
        if previous != candidate.name:
            raise PolicyError(f"exit mark collision: {previous!r} and {candidate.name!r}")

    sets: dict[str, DestSetDecl] = {}
    elements: dict[str, set[str]] = {}
    classify: list[ClassifyRule] = []
    classify_host: list[ClassifyRule] = []
    for index, rule in enumerate(policy.egress):
        dest = _dest_name(rule, index)
        to_sets: tuple[str, ...] = ()
        if dest is not None:
            members, _ = dest_members(rule, index, policy, facts)
            for family in (4, 6):
                set_name = f"{dest}_v{family}"
                sets.setdefault(set_name, DestSetDecl(set_name, family))
                elements.setdefault(set_name, set()).update(
                    member
                    for member in members
                    if ipaddress.ip_network(member, strict=False).version == family
                )
            to_sets = (f"{dest}_v4", f"{dest}_v6")
        via = _resolved_via(rule.parsed_via, facts)
        exit_ = None if via.kind == "drop" else exits[via.name]
        if exit_ is not None and falls_through(exit_):
            # Spec 02: `kill_switch: false` means fall through to later rules while
            # the upstream is down, not "leave through main un-NATed" (the throw route).
            continue
        for source in rule.from_:
            target = classify_host if source == "host" else classify
            target.append(
                ClassifyRule(index, source, _from_match(source, policy, facts), to_sets, exit_)
            )

    if facts.interlink_guard:
        classify[:0] = _transit_head(facts, exits, sets, elements)

    # Appended implicit rule: nothing from clients/sources escapes unrouted.
    tail_index = len(policy.egress)
    for name in ("clients", *(item.name for item in policy.sources)):
        if name == "clients" and facts.client_pool is None:
            continue
        classify.append(ClassifyRule(tail_index, name, _from_match(name, policy, facts), (), None))
    if facts.interlink_guard:
        # Agents never reach a destination outside the interlink unless a policy says so
        # (spec 07: the hub accepts exit traffic only from nodes that declare it).
        classify.append(
            ClassifyRule(
                tail_index,
                "interlink-guard",
                ("iifname @interlink_ifaces",),
                (),
                None,
                label="agents: no exit declared",
            )
        )

    warnings = [f"rule {dead} is shadowed by rule {shadow}" for dead, shadow in dead_rules(policy)]
    for declared in policy.sources:
        fact = facts.sources.get(declared.name)
        if fact is None or not fact.present:
            warnings.append(f"source {declared.name!r}: interface {declared.interface} is missing")

    exit_list = tuple(exits.values())
    set_list = tuple(sorted(sets.values(), key=lambda item: item.name))
    from kornode.net.nftgen import render_script

    script = render_script(
        exits=exit_list,
        sets=set_list,
        classify=tuple(classify),
        classify_host=tuple(classify_host),
        facts=facts,
        policy=policy,
    )
    desired = DesiredState(
        sysctls=_sysctls(exit_list, policy, facts),
        addresses=_addresses(facts),
        rules=_rules(exit_list, facts),
        routes=_routes(exit_list, facts),
        nft=NftRuleset(script),
        elements=_elements(elements, policy, facts),
        foreign_rules=_docker_user_rules(policy, facts),
    )
    return Compiled(
        desired=desired,
        exits=exit_list,
        sets=set_list,
        classify=tuple(classify),
        classify_host=tuple(classify_host),
        script=script,
        warnings=tuple(warnings),
    )


def _transit_head(
    facts: NodeFacts,
    exits: dict[str, Exit],
    sets: dict[str, DestSetDecl],
    elements: dict[str, set[str]],
) -> list[ClassifyRule]:
    """Hub classification of agent traffic (D-69), before every other rule:
    interlink destinations are left to routing, a declared exit marks the flow for its
    per-node table, everything else from an agent falls to the guard at the end.
    Matching is by source prefix (strict reverse path guarantees that only the owning
    agent can send from it) so the script does not change when sessions come and go."""
    head: list[ClassifyRule] = []
    for family in (4, 6):
        name = f"interlink_v{family}"
        sets.setdefault(name, DestSetDecl(name, family))
        elements.setdefault(name, set()).update(
            str(prefix)
            for prefixes in facts.node_prefixes.values()
            for prefix in prefixes
            if prefix.version == family
        )
    head.append(
        ClassifyRule(
            -1,
            "interlink-guard",
            ("iifname @interlink_ifaces",),
            ("interlink_v4", "interlink_v6"),
            None,
            verdict="return",
            label="agents: interlink destinations are routed",
        )
    )
    # Rules are emitted in the order of the agent's policy, first match wins, exactly as
    # the agent classified the traffic it sent into the tunnel. Only adjacent `to: any`
    # entries of one node share a source set (merging across other rules would change
    # which rule a flow matches).
    used: set[str] = set()
    merged: tuple[int, str, set[str]] | None = None  # (node, set name, its elements)
    for index, transit in enumerate(facts.transit_exits):
        nets = {str(net) for net in transit.sources if net.version == 4}
        if not nets:
            # The hub's own exit (egress.hub): only here for the answers' reverse path.
            continue
        if transit.dest is None and merged is not None and merged[0] == transit.node:
            merged[2].update(nets)
            elements[merged[1]].update(nets)
            continue
        name = f"transit{transit.node}_v4"
        if name in used:
            name = f"transit{transit.node}_{index}_v4"
        used.add(name)
        sets.setdefault(name, DestSetDecl(name, 4))
        elements.setdefault(name, set()).update(nets)
        match = ("iifname @interlink_ifaces", f"ip saddr @{name}")
        to_sets: tuple[str, ...] = ()
        if transit.dest is None:
            merged = (transit.node, name, set(nets))
        else:
            merged = None
            dest = f"transit{transit.node}_{index}_d"
            sets.setdefault(f"{dest}4", DestSetDecl(f"{dest}4", 4))
            elements.setdefault(f"{dest}4", set()).update(
                item
                for item in transit.dest
                if ipaddress.ip_network(item, strict=False).version == 4
            )
            to_sets = (f"{dest}4", f"{dest}6")
        head.append(
            ClassifyRule(
                -1,
                "transit",
                match,
                to_sets,
                exits[f"node:{transit.node}"],
                label=f"transit node:{transit.node}",
            )
        )
    return head


def falls_through(exit_: Exit) -> bool:
    """A down upstream without kill switch: its rules are skipped (spec 02)."""
    return exit_.kind == "upstream" and not exit_.up and not exit_.kill_switch


def _make_exit(via: Via, index: int, policy: EgressPolicy, facts: NodeFacts) -> Exit:
    tunnel = facts.tunnels.get(via.name)
    rules = [
        rule for rule in policy.egress if _resolved_via(rule.parsed_via, facts).name == via.name
    ]
    # One table per exit, so one kill-switch per exit: if any rule using it
    # wants fail-closed, the exit fails closed (D-24).
    administratively_disabled = via.kind == "upstream" and (
        via.target in facts.disabled_upstreams or via.target == "active"
    )
    kill_switch = administratively_disabled or any(rule.effective_kill_switch for rule in rules)
    return Exit(
        name=via.name,
        kind=via.kind,
        index=index,
        interface=tunnel.interface if tunnel else (facts.uplink if via.kind == "local" else None),
        up=(bool(tunnel and tunnel.up) and not administratively_disabled) or via.kind == "local",
        kill_switch=kill_switch and via.kind != "local",
        nat=via.kind in ("local", "upstream"),
    )


def _from_match(source: str, policy: EgressPolicy, facts: NodeFacts) -> tuple[str, ...]:
    if source == "clients":
        return (f"ip saddr {facts.client_pool}",)
    if source == "host":
        return ()
    if source == "interlink":
        return ("iifname @interlink_ifaces",)
    item = next(src for src in policy.sources if src.name == source)
    family = "ip" if ipaddress.ip_network(item.cidr).version == 4 else "ip6"
    return (f'iifname "{item.interface}"', f"{family} saddr {item.cidr}")


def _sysctls(exits: tuple[Exit, ...], policy: EgressPolicy, facts: NodeFacts) -> frozenset[Sysctl]:
    items = {
        Sysctl("net.ipv4.ip_forward", "1"),
        Sysctl("net.ipv4.conf.all.src_valid_mark", "1"),
    }
    # Kernel uses max(all, iface): lower a strict `all` to loose, never
    # tighten a host that is already looser (spec 03).
    if facts.all_rp_filter == "1":
        items.add(Sysctl("net.ipv4.conf.all.rp_filter", "2"))
    # Only interfaces that exist right now: a per-interface key for a down
    # tunnel cannot be written and would fail every pass until it is back
    # (the reconciler re-runs on RTM_NEWLINK, so it's set as soon as it is).
    ifaces = {
        exit_.interface for exit_ in exits if exit_.interface and exit_.up and exit_.kind != "local"
    }
    ifaces |= {
        source.interface
        for source in policy.sources
        if facts.sources.get(source.name, SourceFact(False)).present
    }
    for iface in ifaces:
        items.add(Sysctl(f"net.ipv4.conf.{iface}.rp_filter", "2"))
    return frozenset(items)


def _rules(exits: tuple[Exit, ...], facts: NodeFacts) -> frozenset[IpRule]:
    rules = {
        IpRule(priority=SUPPRESS_PRIORITY, table="main", suppress_prefixlength=0, family=family)
        for family in FAMILIES
    }
    for tunnel in facts.tunnels.values():
        for address in tunnel.carrier:
            carrier_family: Family = 4 if ipaddress.ip_address(address).version == 4 else 6
            rules.add(
                IpRule(priority=CARRIER_PRIORITY, table="main", to=address, family=carrier_family)
            )
    for exit_ in exits:
        if exit_.has_table:
            for family in FAMILIES:
                rules.add(
                    IpRule(
                        priority=EXIT_PRIORITY_BASE + exit_.index,
                        table=exit_.table,
                        fwmark=exit_.mark,
                        fwmask=MARK_MASK,
                        family=family,
                    )
                )
    return frozenset(rules)


def _routes(exits: tuple[Exit, ...], facts: NodeFacts) -> frozenset[Route]:
    routes: set[Route] = set()
    for prefix, dev in facts.session_routes:
        routes.add(
            Route(
                table=MAIN_TABLE,
                dst=str(prefix),
                dev=dev,
                proto=KORNODE_RTPROTO,
                family=4 if prefix.version == 4 else 6,
            )
        )
    for exit_ in exits:
        if not exit_.has_table:
            continue
        for family in FAMILIES:
            routes.add(
                Route(
                    table=exit_.table,
                    dst="default",
                    type="unreachable" if exit_.kill_switch else "throw",
                    metric=KILL_SWITCH_METRIC,
                    family=family,
                )
            )
        if not (exit_.up and exit_.interface):
            continue
        if exit_.kind == "interlink":
            # Agent: only interlink prefixes go through the hub tunnel. On the
            # hub (no interlink tunnel of its own) the per-session routes live in
            # main and rule 90 resolves them; the table only fails closed.
            for node, prefixes in sorted(facts.node_prefixes.items()):
                if node == facts.node_id:
                    continue
                for prefix in prefixes:
                    routes.add(
                        Route(
                            table=exit_.table,
                            dst=str(prefix),
                            dev=exit_.interface,
                            family=4 if prefix.version == 4 else 6,
                        )
                    )
        else:
            routes.add(Route(table=exit_.table, dst="default", dev=exit_.interface))
    return frozenset(routes)


def _elements(
    elements: dict[str, set[str]], policy: EgressPolicy, facts: NodeFacts
) -> frozenset[NftElements]:
    family, table = FILTER_TABLE
    items = {
        NftElements(family, table, name, frozenset(members)) for name, members in elements.items()
    }
    items.add(NftElements(family, table, "interlink_ifaces", frozenset(facts.interlink_ifaces)))
    nat_family, nat_table = NAT_TABLE
    items.add(
        NftElements(nat_family, nat_table, "interlink_ifaces", frozenset(facts.interlink_ifaces))
    )
    if facts.transit_exits:
        items.add(
            NftElements(
                family,
                table,
                "transit_ifaces",
                frozenset(t.exit_iface for t in facts.transit_exits if t.exit_iface),
            )
        )
    local4 = {str(net) for net in facts.local_networks if net.version == 4}
    local6 = {str(net) for net in facts.local_networks if net.version == 6}
    if facts.client_pool is not None:
        local4.add(str(facts.client_pool))
    # This node's own source subnets are local too: clients reaching an
    # attached access server's clients must not be marked/masqueraded.
    for source in policy.sources:
        (local4 if ":" not in source.cidr else local6).add(source.cidr)
    items.add(NftElements(family, table, "local_v4", frozenset(local4)))
    items.add(NftElements(family, table, "local_v6", frozenset(local6)))
    carrier4 = {
        f"{address}/32"
        for tunnel in facts.tunnels.values()
        for address in tunnel.carrier
        if ipaddress.ip_address(address).version == 4
    }
    carrier6 = {
        f"{address}/128"
        for tunnel in facts.tunnels.values()
        for address in tunnel.carrier
        if ipaddress.ip_address(address).version == 6
    }
    items.add(NftElements(family, table, "carrier_v4", frozenset(carrier4)))
    items.add(NftElements(family, table, "carrier_v6", frozenset(carrier6)))
    return frozenset(items)


def _docker_user_rules(policy: EgressPolicy, facts: NodeFacts) -> frozenset[ForeignNftRule]:
    """Accept forwarded client/source traffic in Docker's DOCKER-USER chain:
    on a Docker host its `ip filter` FORWARD policy is drop, and an accept in
    kornode's own table does not exempt a packet from another table's base
    chain. Only installed when that chain exists (kernel adapter)."""
    networks = [str(facts.client_pool)] if facts.client_pool is not None else []
    networks += [source.cidr for source in policy.sources if ":" not in source.cidr]
    return frozenset(
        ForeignNftRule("ip", "filter", "DOCKER-USER", f"ip {direction} {network} accept")
        for network in networks
        for direction in ("saddr", "daddr")
    )
