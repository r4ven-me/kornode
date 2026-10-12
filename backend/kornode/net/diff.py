"""diff(actual, desired) -> Plan, and a pure simulator of applying a plan.

Order (docs/spec/04-netcore-reconciler.md): sysctl -> routes into exit
tables (non-unicast first, so the kill-switch route exists before the tunnel
route it backs) -> rules (new before old) -> nft -> stale routes last.
Only kornode-owned rules/routes/nft tables ever appear in a plan.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from kornode.net.state import (
    OWNED_NFT_TABLES,
    ActualState,
    DesiredState,
    IpRule,
    NftElements,
    NftRuleset,
    Route,
    Sysctl,
    owns_route,
    owns_rule,
)


@dataclass(frozen=True, slots=True)
class SetSysctl:
    sysctl: Sysctl


@dataclass(frozen=True, slots=True)
class AddRule:
    rule: IpRule


@dataclass(frozen=True, slots=True)
class DelRule:
    rule: IpRule


@dataclass(frozen=True, slots=True)
class ReplaceRoute:
    route: Route


@dataclass(frozen=True, slots=True)
class DelRoute:
    route: Route


@dataclass(frozen=True, slots=True)
class NftLoad:
    """Replace kornode's nft tables with `ruleset` in one transaction. Sets
    come back empty; the plan always follows it with UpdateElements."""

    ruleset: NftRuleset


@dataclass(frozen=True, slots=True)
class UpdateElements:
    family: str
    table: str
    set_name: str
    add: frozenset[str]
    delete: frozenset[str]


Op = SetSysctl | AddRule | DelRule | ReplaceRoute | DelRoute | NftLoad | UpdateElements


@dataclass(frozen=True, slots=True)
class Plan:
    ops: tuple[Op, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.ops


def _rule_sort_key(rule: IpRule) -> tuple[int, int, str]:
    return (rule.priority, rule.family, repr(rule))


def _route_sort_key(route: Route) -> tuple[int, int, int, str, int]:
    return (route.table, route.family, 0 if route.type != "unicast" else 1, route.dst, route.metric)


def diff(actual: ActualState, desired: DesiredState) -> Plan:
    ops: list[Op] = []

    actual_sysctls = {sysctl.key: sysctl.value for sysctl in actual.sysctls}
    for sysctl in sorted(desired.sysctls, key=lambda item: item.key):
        if actual_sysctls.get(sysctl.key) != sysctl.value:
            ops.append(SetSysctl(sysctl))

    actual_routes = {route for route in actual.routes if owns_route(route)}
    for route in sorted(desired.routes - actual_routes, key=_route_sort_key):
        ops.append(ReplaceRoute(route))

    actual_rules = {rule for rule in actual.rules if owns_rule(rule)}
    for rule in sorted(desired.rules - actual_rules, key=_rule_sort_key):
        ops.append(AddRule(rule))
    for rule in sorted(actual_rules - desired.rules, key=_rule_sort_key):
        ops.append(DelRule(rule))

    ops.extend(_nft_ops(actual, desired))

    desired_keys = {route.key for route in desired.routes}
    stale = [route for route in actual_routes if route.key not in desired_keys]
    for route in sorted(stale, key=_route_sort_key):
        ops.append(DelRoute(route))

    return Plan(tuple(ops))


def _nft_ops(actual: ActualState, desired: DesiredState) -> list[Op]:
    if desired.nft is None:
        # Not managed by this desired state: leave kornode's tables alone.
        return []
    ops: list[Op] = []
    reload = desired.nft.schema_hash != actual.nft_schema_hash
    current: dict[tuple[str, str, str], frozenset[str]] = {}
    if reload:
        ops.append(NftLoad(desired.nft))
    else:
        current = {item.set_key: item.elements for item in actual.elements}
    for item in sorted(desired.elements, key=lambda element: element.set_key):
        have = current.get(item.set_key, frozenset())
        add = item.elements - have
        delete = have - item.elements
        if add or delete:
            ops.append(UpdateElements(item.family, item.table, item.set_name, add, delete))
    return ops


def apply_to_state(state: ActualState, plan: Plan) -> ActualState:
    """What the kernel looks like after `plan` -- the same semantics the
    kernel adapter implements, used as the fake kernel in tests."""
    sysctls = {sysctl.key: sysctl for sysctl in state.sysctls}
    rules = set(state.rules)
    routes = {route.key: route for route in state.routes}
    schema_hash = state.nft_schema_hash
    elements = {item.set_key: item for item in state.elements}

    for op in plan.ops:
        if isinstance(op, SetSysctl):
            sysctls[op.sysctl.key] = op.sysctl
        elif isinstance(op, AddRule):
            rules.add(op.rule)
        elif isinstance(op, DelRule):
            rules.discard(op.rule)
        elif isinstance(op, ReplaceRoute):
            routes[op.route.key] = op.route
        elif isinstance(op, DelRoute):
            routes.pop(op.route.key, None)
        elif isinstance(op, NftLoad):
            schema_hash = op.ruleset.schema_hash
            elements = {
                key: item
                for key, item in elements.items()
                if (item.family, item.table) not in OWNED_NFT_TABLES
            }
        else:
            key = (op.family, op.table, op.set_name)
            have = elements[key].elements if key in elements else frozenset()
            new = (have - op.delete) | op.add
            elements[key] = NftElements(op.family, op.table, op.set_name, new)

    return replace(
        state,
        sysctls=frozenset(sysctls.values()),
        rules=frozenset(rules),
        routes=frozenset(routes.values()),
        nft_schema_hash=schema_hash,
        elements=frozenset(elements.values()),
    )
