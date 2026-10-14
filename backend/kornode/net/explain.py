"""explain(src, dst) -> Decision (docs/spec/04-netcore-reconciler.md "Explain").

Walks the compiled policy the way the nft classify chains do (implicit
returns first, then first match wins), then optionally asks the kernel
where it would really send the packet with that mark and warns on a
mismatch (drift).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kornode.net.compile import Compiled, Exit, NodeFacts
from kornode.net.model import EgressPolicy, InlineDest, NodeRef, Rule, SetRef

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
RouteGetter = Callable[[str, int | None, str | None], str | None]


@dataclass(slots=True)
class Decision:
    from_class: str
    matched_rule: dict[str, Any] | None = None
    implicit: str | None = None
    mark: str | None = None
    table: int | None = None
    route: str | None = None
    nat: str | None = None
    kernel_check: str | None = None
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "from_class": self.from_class,
            "matched_rule": self.matched_rule,
            "implicit": self.implicit,
            "mark": self.mark,
            "table": self.table,
            "route": self.route,
            "nat": self.nat,
            "kernel_check": self.kernel_check,
            "warnings": list(self.warnings),
        }


def _within(address: Address, networks: frozenset[str] | tuple[Any, ...]) -> bool:
    for item in networks:
        network = ipaddress.ip_network(item, strict=False)
        if network.version == address.version and address in network:
            return True
    return False


def _set_members(compiled: Compiled, name: str) -> frozenset[str]:
    members: set[str] = set()
    for item in compiled.desired.elements:
        if item.set_name in (f"{name}_v4", f"{name}_v6"):
            members |= item.elements
    return frozenset(members)


def _classify_source(
    src: str, policy: EgressPolicy, facts: NodeFacts
) -> tuple[str, Address | None]:
    if src == "host":
        return "host", None
    address = ipaddress.ip_address(src)
    if facts.client_pool is not None and _within(address, (facts.client_pool,)):
        return "clients", address
    for source in policy.sources:
        if _within(address, (source.cidr,)):
            return source.name, address
    others = tuple(
        prefix
        for node, prefixes in facts.node_prefixes.items()
        if node != facts.node_id
        for prefix in prefixes
    )
    if _within(address, others):
        return "fabric", address
    return "host", address


def _rule_dest(rule: Rule, index: int) -> str | None:
    if rule.to == "any":
        return None
    if rule.to == "fabric":
        return "fabric"
    if isinstance(rule.to, SetRef):
        return rule.to.set
    if isinstance(rule.to, NodeRef):
        return f"node{rule.to.node}"
    assert isinstance(rule.to, InlineDest)
    return f"rule{index}"


def _rule_json(rule: Rule, index: int) -> dict[str, Any]:
    dumped = rule.model_dump(by_alias=True, exclude_none=True, exclude_defaults=True)
    return {"index": index, "id": rule.id, "to": dumped["to"], "via": rule.via}


def _route_for(exit_: Exit, compiled: Compiled, dst: Address) -> str:
    if exit_.kind == "local":
        return f"main table (uplink {exit_.interface})" if exit_.interface else "main table"
    routes = [route for route in compiled.desired.routes if route.table == exit_.table]
    for route in sorted(routes, key=lambda item: (item.type != "unicast", item.metric)):
        if route.family != dst.version:
            continue
        if route.dst != "default" and dst not in ipaddress.ip_network(route.dst):
            continue
        if route.type == "unicast":
            return f"{route.dst} dev {route.dev}"
        return (
            f"{route.type} {route.dst} (kill-switch)"
            if route.type == "unreachable"
            else (f"{route.type} {route.dst}")
        )
    return "no route"


def explain(
    compiled: Compiled,
    policy: EgressPolicy,
    facts: NodeFacts,
    src: str,
    dst: str,
    *,
    route_get: RouteGetter | None = None,
) -> Decision:
    from_class, _ = _classify_source(src, policy, facts)
    destination = ipaddress.ip_address(dst)
    decision = Decision(from_class=from_class)

    local = _set_members(compiled, "local")
    carrier = _set_members(compiled, "carrier")
    if _within(destination, local):
        decision.implicit = "destination is a connected network of this node (main table)"
    elif _within(destination, carrier):
        decision.implicit = "destination is a tunnel carrier address (main table)"
    if decision.implicit:
        decision.route = "main table"
        return decision

    for index, rule in enumerate(policy.egress):
        if from_class not in rule.from_:
            continue
        dest = _rule_dest(rule, index)
        if dest is not None and not _within(destination, _set_members(compiled, dest)):
            continue
        decision.matched_rule = _rule_json(rule, index)
        via = rule.parsed_via
        if via.kind == "drop":
            decision.route = "reject (admin-prohibited)"
            return decision
        exit_ = next(item for item in compiled.exits if item.name == via.name)
        decision.mark = f"0x{exit_.mark:08x}"
        decision.table = exit_.table if exit_.has_table else None
        decision.route = _route_for(exit_, compiled, destination)
        if exit_.nat and exit_.interface:
            decision.nat = f"masquerade to {exit_.interface}"
        if route_get is not None:
            _kernel_check(decision, exit_, route_get, dst)
        return decision

    if from_class == "host":
        decision.implicit = "host default: normal routing (main table)"
        decision.route = "main table"
    else:
        decision.implicit = "no rule matched: rejected (appended implicit drop)"
        decision.route = "reject (admin-prohibited)"
    return decision


def _kernel_check(
    decision: Decision,
    exit_: Exit,
    route_get: RouteGetter,
    dst: str,
) -> None:
    # Only the mark selects kornode's tables; passing the (usually non-local)
    # source would make the kernel reject the lookup.
    device = route_get(dst, exit_.mark, None)
    decision.kernel_check = (
        f"ip route get {dst} mark 0x{exit_.mark:08x} -> "
        f"{'dev ' + device if device else 'unreachable'}"
    )
    expected = exit_.interface if exit_.kind != "local" else None
    if exit_.kind == "local":
        return
    if expected is None or not exit_.up:
        if device is not None and exit_.kill_switch:
            decision.warnings.append(
                f"kernel routes it via {device} although exit {exit_.name} is down"
            )
        return
    if device != expected:
        decision.warnings.append(
            f"kernel routes it via {device or 'nothing'}, compiled policy expects {expected}"
        )
