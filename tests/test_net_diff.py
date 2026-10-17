from __future__ import annotations

import pytest

from kornode.net.diff import (
    AddAddress,
    AddRule,
    DelRoute,
    DelRule,
    NftLoad,
    ReplaceRoute,
    SetSysctl,
    UpdateElements,
    apply_to_state,
    diff,
)
from kornode.net.errors import PolicyError
from kornode.net.state import (
    ActualState,
    Address,
    DesiredState,
    IpRule,
    NftElements,
    NftRuleset,
    Route,
    Sysctl,
)

SCRIPT = "table inet kornode {\n  set corp_v4 { type ipv4_addr; flags interval; }\n}\n"
SCRIPT_V2 = SCRIPT + "table ip kornode_nat {\n}\n"

SUPPRESS = IpRule(priority=90, table="main", suppress_prefixlength=0)
CARRIER = IpRule(priority=95, table="main", to="203.0.113.2")
EXIT_RULE = IpRule(priority=100, table=12001, fwmark=0x0C000100, fwmask=0xFFFFFF00)
TUN_DEFAULT = Route(table=12001, dst="default", dev="oc-office0")
KILL_SWITCH = Route(table=12001, dst="default", type="unreachable", metric=4096)
CORP = NftElements("inet", "kornode", "corp_v4", frozenset({"10.60.0.0/16"}))


def _desired(**overrides: object) -> DesiredState:
    values: dict[str, object] = {
        "sysctls": frozenset({Sysctl("net.ipv4.ip_forward", "1")}),
        "rules": frozenset({SUPPRESS, CARRIER, EXIT_RULE}),
        "routes": frozenset({TUN_DEFAULT, KILL_SWITCH}),
        "nft": NftRuleset(SCRIPT),
        "elements": frozenset({CORP}),
    }
    values.update(overrides)
    return DesiredState(**values)  # type: ignore[arg-type]


FOREIGN_RULE = IpRule(priority=32766, table="main")
FOREIGN_ROUTE = Route(table=254, dst="default", dev="eth0")


def test_empty_kernel_gets_everything_in_spec_order() -> None:
    plan = diff(ActualState(), _desired())

    kinds = [type(op) for op in plan.ops]
    assert kinds == [
        SetSysctl,
        ReplaceRoute,
        ReplaceRoute,
        AddRule,
        AddRule,
        AddRule,
        NftLoad,
        UpdateElements,
    ]
    routes = [op.route for op in plan.ops if isinstance(op, ReplaceRoute)]
    # The kill-switch route goes in before the tunnel route it backs.
    assert routes == [KILL_SWITCH, TUN_DEFAULT]
    rules = [op.rule.priority for op in plan.ops if isinstance(op, AddRule)]
    assert rules == [90, 95, 100]


def test_tunnel_default_and_unreachable_default_coexist() -> None:
    assert TUN_DEFAULT.key != KILL_SWITCH.key
    state = apply_to_state(ActualState(), diff(ActualState(), _desired()))

    assert {TUN_DEFAULT, KILL_SWITCH} <= state.routes


CASES = [
    ActualState(),
    ActualState(rules=frozenset({FOREIGN_RULE}), routes=frozenset({FOREIGN_ROUTE})),
    ActualState(
        sysctls=frozenset({Sysctl("net.ipv4.ip_forward", "0"), Sysctl("vm.swappiness", "60")}),
        rules=frozenset({SUPPRESS, IpRule(priority=100, table=12001, fwmark=0x0C000200)}),
        routes=frozenset({Route(table=12001, dst="default", dev="oc-old0")}),
        nft_schema_hash="stale",
    ),
    ActualState(
        rules=frozenset({SUPPRESS, CARRIER, EXIT_RULE, IpRule(priority=150, table=12009)}),
        routes=frozenset({TUN_DEFAULT, KILL_SWITCH, Route(table=12009, dst="10.0.0.0/8")}),
        nft_schema_hash=NftRuleset(SCRIPT).schema_hash,
        elements=frozenset({NftElements("inet", "kornode", "corp_v4", frozenset({"1.2.3.4"}))}),
    ),
]


@pytest.mark.parametrize("actual", CASES)
@pytest.mark.parametrize(
    "desired",
    [_desired(), _desired(nft=NftRuleset(SCRIPT_V2)), _desired(elements=frozenset())],
)
def test_applying_the_plan_converges(actual: ActualState, desired: DesiredState) -> None:
    after = apply_to_state(actual, diff(actual, desired))

    assert diff(after, desired).is_empty
    # Converging twice changes nothing.
    assert apply_to_state(after, diff(after, desired)) == after


def test_foreign_objects_are_never_touched() -> None:
    actual = ActualState(
        sysctls=frozenset({Sysctl("vm.swappiness", "60")}),
        rules=frozenset({FOREIGN_RULE, IpRule(priority=200, table=5)}),
        routes=frozenset({FOREIGN_ROUTE, Route(table=13000, dst="10.0.0.0/8")}),
    )
    after = apply_to_state(actual, diff(actual, _desired()))

    assert FOREIGN_RULE in after.rules
    assert IpRule(priority=200, table=5) in after.rules
    assert FOREIGN_ROUTE in after.routes
    assert Route(table=13000, dst="10.0.0.0/8") in after.routes
    assert Sysctl("vm.swappiness", "60") in after.sysctls


def test_changed_rule_is_added_before_the_old_one_is_removed() -> None:
    old = IpRule(priority=100, table=12001, fwmark=0x0C000200, fwmask=0xFFFFFF00)
    actual = apply_to_state(ActualState(), diff(ActualState(), _desired()))
    previous = _desired(rules=frozenset({SUPPRESS, CARRIER, old}))
    actual = apply_to_state(actual, diff(actual, previous))

    plan = diff(actual, _desired())

    rule_ops = [op for op in plan.ops if isinstance(op, (AddRule, DelRule))]
    assert rule_ops == [AddRule(EXIT_RULE), DelRule(old)]


def test_changed_route_device_is_a_replace_not_a_delete() -> None:
    old_tunnel = Route(table=12001, dst="default", dev="oc-old0")
    actual = ActualState(routes=frozenset({old_tunnel, KILL_SWITCH}))

    plan = diff(actual, _desired())

    assert ReplaceRoute(TUN_DEFAULT) in plan.ops
    assert not [op for op in plan.ops if isinstance(op, DelRoute)]


def test_unchanged_schema_with_new_elements_only_updates_elements() -> None:
    actual = apply_to_state(ActualState(), diff(ActualState(), _desired()))
    desired = _desired(
        elements=frozenset({NftElements("inet", "kornode", "corp_v4", frozenset({"10.61.0.0/16"}))})
    )

    plan = diff(actual, desired)

    assert plan.ops == (
        UpdateElements(
            "inet",
            "kornode",
            "corp_v4",
            frozenset({"10.61.0.0/16"}),
            frozenset({"10.60.0.0/16"}),
            frozenset({"10.61.0.0/16"}),
        ),
    )


def test_changed_schema_reloads_then_refills_sets() -> None:
    actual = apply_to_state(ActualState(), diff(ActualState(), _desired()))

    plan = diff(actual, _desired(nft=NftRuleset(SCRIPT_V2)))

    assert plan.ops == (
        NftLoad(NftRuleset(SCRIPT_V2)),
        UpdateElements(
            "inet",
            "kornode",
            "corp_v4",
            frozenset({"10.60.0.0/16"}),
            frozenset(),
            frozenset({"10.60.0.0/16"}),
        ),
    )


def test_stale_owned_routes_are_deleted_last() -> None:
    stale = Route(table=12009, dst="10.0.0.0/8", dev="oc-gone0")
    actual = apply_to_state(ActualState(), diff(ActualState(), _desired()))
    actual = ActualState(
        sysctls=actual.sysctls,
        rules=actual.rules | {IpRule(priority=150, table=12009)},
        routes=actual.routes | {stale},
        nft_schema_hash=actual.nft_schema_hash,
        elements=actual.elements,
    )

    plan = diff(actual, _desired())

    assert plan.ops == (DelRule(IpRule(priority=150, table=12009)), DelRoute(stale))


def test_unmanaged_nft_is_left_alone() -> None:
    plan = diff(ActualState(nft_schema_hash="whatever"), _desired(nft=None, elements=frozenset()))

    assert not [op for op in plan.ops if isinstance(op, (NftLoad, UpdateElements))]


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (lambda: _desired(rules=frozenset({FOREIGN_RULE})), "owned priorities"),
        (lambda: _desired(routes=frozenset({FOREIGN_ROUTE})), "owned tables"),
        (
            lambda: _desired(
                routes=frozenset({TUN_DEFAULT, Route(table=12001, dst="default", dev="x")})
            ),
            "same key",
        ),
        (
            lambda: _desired(elements=frozenset({NftElements("inet", "filter", "x", frozenset())})),
            "owned nft tables",
        ),
        (lambda: NftRuleset("table inet kornode { set s { elements = { 1.2.3.4 } } }"), "inline"),
        (lambda: Route(table=12001, dst="default", type="unreachable", dev="eth0"), "device"),
        (lambda: IpRule(priority=95, table="main", to="2001:db8::/32"), "family"),
    ],
)
def test_invalid_states_are_rejected(build: object, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        build()  # type: ignore[operator]


def test_prefixes_are_normalised() -> None:
    assert IpRule(priority=95, table="main", to="203.0.113.2").to == "203.0.113.2/32"
    assert Route(table=12001, dst="10.60.1.0/16").dst == "10.60.0.0/16"


def test_elements_are_compared_in_canonical_form() -> None:
    merged = NftElements(
        "inet", "kornode", "corp_v4", frozenset({"10.0.0.0/24", "10.0.1.0/24", "192.168.1.5"})
    )

    assert merged.elements == {"10.0.0.0/23", "192.168.1.5/32"}
    ifaces = NftElements("inet", "kornode", "fabric_ifaces", frozenset({"vpns0", "oc-hub0"}))
    assert ifaces.elements == {"vpns0", "oc-hub0"}


def test_missing_address_is_added_and_never_removed() -> None:
    hub = Address("lo", "10.99.0.1/32")
    desired = DesiredState(addresses=frozenset({hub}))

    plan = diff(ActualState(), desired)

    assert plan.ops == (AddAddress(hub),)
    after = apply_to_state(ActualState(), plan)
    assert diff(after, desired).is_empty
    stray = ActualState(addresses=frozenset({Address("lo", "10.99.0.9/32"), hub}))
    assert diff(stray, desired).is_empty
