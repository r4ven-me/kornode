"""diff(actual, desired) -> Plan, and a pure simulator of applying a plan.

Order (docs/spec/04-netcore-reconciler.md): fail-closed nft routing barrier
when needed (sets filled atomically) -> sysctl -> routes into exit tables
(non-unicast first) -> rules (new before old) -> stale routes -> final nft.
Without a compiled routing barrier, legacy unmanaged plans retain stale routes last.
Only kornode-owned rules/routes/nft tables ever appear in a plan.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from kornode.net.state import (
    OWNED_NFT_TABLES,
    ActualState,
    Address,
    DesiredState,
    ForeignNftRule,
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
class AddAddress:
    address: Address


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
    # Temporary fail-closed barrier before routing tables can be reassigned.
    guard: bool = False


@dataclass(frozen=True, slots=True)
class UpdateElements:
    """Bring one set to `target`. `add`/`delete` describe the change for
    display; the kernel adapter replaces the whole set content in one
    transaction (deleting a sub-range out of an auto-merged interval is not
    reliable in nft)."""

    family: str
    table: str
    set_name: str
    add: frozenset[str]
    delete: frozenset[str]
    target: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class InsertForeignRule:
    rule: ForeignNftRule


@dataclass(frozen=True, slots=True)
class DeleteForeignRule:
    rule: ForeignNftRule


Op = (
    SetSysctl
    | AddAddress
    | AddRule
    | DelRule
    | ReplaceRoute
    | DelRoute
    | NftLoad
    | UpdateElements
    | InsertForeignRule
    | DeleteForeignRule
)


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

    for address in sorted(desired.addresses - actual.addresses, key=repr):
        ops.append(AddAddress(address))

    actual_routes = {route for route in actual.routes if owns_route(route)}
    for route in sorted(desired.routes - actual_routes, key=_route_sort_key):
        ops.append(ReplaceRoute(route))

    actual_rules = {rule for rule in actual.rules if owns_rule(rule)}
    for rule in sorted(desired.rules - actual_rules, key=_rule_sort_key):
        ops.append(AddRule(rule))
    for rule in sorted(actual_rules - desired.rules, key=_rule_sort_key):
        ops.append(DelRule(rule))

    desired_keys = {route.key for route in desired.routes}
    stale = [route for route in actual_routes if route.key not in desired_keys]
    stale_routes = [DelRoute(route) for route in sorted(stale, key=_route_sort_key)]
    routing_changes = bool(stale_routes) or any(
        isinstance(op, (ReplaceRoute, AddRule, DelRule)) for op in ops
    )
    if (
        routing_changes
        and desired.nft is not None
        and "  chain validate_connection {" in desired.nft.script
    ):
        # Table indices are bounded kernel slots, not identities. Even with
        # stable marks, changing their contents under the old ruleset could
        # temporarily send a pinned flow into another exit's tunnel.
        script = desired.nft.script
        for chain in ("forward", "postrouting"):
            hook = f"    type filter hook {chain} priority filter; policy accept;"
            script = script.replace(
                hook,
                hook + "\n    meta mark & 0xff000000 == 0x0c000000 drop",
            )
        guard_ruleset = NftRuleset(script)
        guard = replace(desired, nft=guard_ruleset)
        guard_ops = _nft_ops(replace(actual, nft_schema_hash=None), guard)
        guard_ops[0] = NftLoad(guard_ruleset, guard=True)
        # Empty destination sets would let host-only split rules fall through
        # unmarked to main. Fill the guard's sets in its *same* nft transaction.
        ops = [*guard_ops, *ops, *stale_routes]
        stale_routes = []
        # A final reload is needed even when the original schema was unchanged.
        actual = replace(actual, nft_schema_hash=None)

    ops.extend(_nft_ops(actual, desired))

    for foreign in sorted(desired.foreign_rules - actual.foreign_rules, key=repr):
        if foreign.chain_key in actual.foreign_chains:
            ops.append(InsertForeignRule(foreign))
    for foreign in sorted(actual.foreign_rules - desired.foreign_rules, key=repr):
        ops.append(DeleteForeignRule(foreign))

    ops.extend(stale_routes)

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
            ops.append(
                UpdateElements(item.family, item.table, item.set_name, add, delete, item.elements)
            )
    return ops


def apply_to_state(state: ActualState, plan: Plan) -> ActualState:
    """What the kernel looks like after `plan` -- the same semantics the
    kernel adapter implements, used as the fake kernel in tests."""
    sysctls = {sysctl.key: sysctl for sysctl in state.sysctls}
    addresses = set(state.addresses)
    rules = set(state.rules)
    routes = {route.key: route for route in state.routes}
    schema_hash = state.nft_schema_hash
    elements = {item.set_key: item for item in state.elements}
    foreign = set(state.foreign_rules)

    for op in plan.ops:
        if isinstance(op, SetSysctl):
            sysctls[op.sysctl.key] = op.sysctl
        elif isinstance(op, AddAddress):
            addresses.add(op.address)
        elif isinstance(op, AddRule):
            rules.add(op.rule)
        elif isinstance(op, DelRule):
            rules.discard(op.rule)
        elif isinstance(op, ReplaceRoute):
            routes[op.route.key] = op.route
        elif isinstance(op, DelRoute):
            routes.pop(op.route.key, None)
        elif isinstance(op, InsertForeignRule):
            foreign.add(op.rule)
        elif isinstance(op, DeleteForeignRule):
            foreign.discard(op.rule)
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
        addresses=frozenset(addresses),
        rules=frozenset(rules),
        routes=frozenset(routes.values()),
        nft_schema_hash=schema_hash,
        elements=frozenset(elements.values()),
        foreign_rules=frozenset(foreign),
    )


def _rule_text(rule: IpRule) -> str:
    parts = [f"{rule.priority}:", "from all"]
    if rule.to:
        parts.append(f"to {rule.to}")
    if rule.fwmark is not None:
        mask = f"/0x{rule.fwmask:x}" if rule.fwmask is not None else ""
        parts.append(f"fwmark 0x{rule.fwmark:x}{mask}")
    parts.append(f"lookup {rule.table}")
    if rule.suppress_prefixlength is not None:
        parts.append(f"suppress_prefixlength {rule.suppress_prefixlength}")
    return f"ipv{rule.family} " + " ".join(parts)


def _route_text(route: Route) -> str:
    parts: list[str] = [route.type] if route.type != "unicast" else []
    parts.append(route.dst)
    if route.gateway:
        parts.append(f"via {route.gateway}")
    if route.dev:
        parts.append(f"dev {route.dev}")
    if route.metric:
        parts.append(f"metric {route.metric}")
    return f"ipv{route.family} table {route.table}: " + " ".join(parts)


def describe(op: Op) -> str:
    """One human-readable line per plan op (korctl net plan, the panel)."""
    if isinstance(op, SetSysctl):
        return f"sysctl {op.sysctl.key}={op.sysctl.value}"
    if isinstance(op, AddAddress):
        return f"add address {op.address.cidr} dev {op.address.dev}"
    if isinstance(op, AddRule):
        return f"add rule {_rule_text(op.rule)}"
    if isinstance(op, DelRule):
        return f"delete rule {_rule_text(op.rule)}"
    if isinstance(op, ReplaceRoute):
        return f"replace route {_route_text(op.route)}"
    if isinstance(op, DelRoute):
        return f"delete route {_route_text(op.route)}"
    if isinstance(op, NftLoad):
        return f"load nft ruleset (schema {op.ruleset.schema_hash[:12]})"
    if isinstance(op, InsertForeignRule):
        rule = op.rule
        return f"insert into {rule.family} {rule.table} {rule.chain}: {rule.expr}"
    if isinstance(op, DeleteForeignRule):
        rule = op.rule
        return f"delete from {rule.family} {rule.table} {rule.chain}: {rule.expr}"
    changes = [f"+{item}" for item in sorted(op.add)] + [f"-{item}" for item in sorted(op.delete)]
    return f"nft set {op.family} {op.table} {op.set_name}: {' '.join(changes)}"
