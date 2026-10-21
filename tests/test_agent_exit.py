"""P4-06 (D-69): `via: exit:<node>` — management validation, bundles, hub transit facts."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

import pytest
from tests.test_agent_management import world as world  # noqa: F401
from tests.test_netinputs import FakeRunner

from kornode.bundle.errors import BundleError
from kornode.services.agent_models import AgentPatch, ManagementError
from kornode.services.command import CommandResult
from kornode.services.netinputs import HubNetInputs

OUT = {"id": "out", "from": ["clients"], "to": "any", "via": "exit:3"}


def make(world: Any) -> Any:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(2)
    env.add(3, roles=["exit"])
    for node in (2, 3):  # what AgentService.create registers for every agent
        env.registry.set_prefixes(
            node, [{"prefix": f"10.100.{node}.0/24", "kind": "pool", "export": True}]
        )
    return env, service


def refused(service: Any, name: str, rules: list[dict[str, Any]], **policy: Any) -> str:
    with pytest.raises(ManagementError) as raised:
        service.set_policy(name, {"egress": rules, **policy})
    return str(raised.value.error)


def test_an_exit_rule_is_accepted_for_an_active_agent_with_the_exit_role(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service = make(world)
    service.set_policy("node2", {"egress": [OUT]})
    own = env.check(env.registry.latest_bundle(2)).bundle
    assert [rule.id for rule in own.policy.egress] == ["to-fabric", "out"]
    assert own.policy.egress[1].via == "exit:3"


def test_the_exit_node_gets_the_nat_rule_for_what_the_hub_sends_it(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, _ = make(world)
    env.compile(3)
    rules = env.check(env.registry.latest_bundle(3)).bundle.policy.egress
    assert [(rule.id, rule.from_, rule.to, rule.via) for rule in rules] == [
        ("to-fabric", ("clients", "host"), "fabric", "fabric"),
        ("exit-local", ("fabric",), "any", "local"),
    ]


def test_an_operators_own_fabric_rule_is_not_duplicated(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service = make(world)
    own = {"id": "mine", "from": ["fabric"], "to": {"routes": ["198.51.100.0/24"]}, "via": "local"}
    service.set_policy("node3", {"egress": [own]})
    rules = env.check(env.registry.latest_bundle(3)).bundle.policy.egress
    assert [rule.id for rule in rules] == ["to-fabric", "mine"]


@pytest.mark.parametrize(
    ("rules", "code"),
    [
        ([{"from": ["clients"], "to": "any", "via": "exit:9"}], "exit_node"),
        ([{"from": ["clients"], "to": "any", "via": "exit:2"}], "exit_node"),
        ([{"from": ["host"], "to": "any", "via": "exit:3"}], "runtime_unsupported"),
        ([{"from": ["clients"], "to": "fabric", "via": "exit:3"}], "runtime_unsupported"),
        ([{"from": ["clients"], "to": {"node": 3}, "via": "exit:3"}], "runtime_unsupported"),
    ],
)
def test_bad_exit_rules_are_refused(world: Any, rules: list[dict[str, Any]], code: str) -> None:  # type: ignore[no-untyped-def]
    _, service = make(world)
    assert refused(service, "node2", rules, sets={"web": {"domains": ["example.org"]}}) == code


def test_a_node_without_the_exit_role_or_not_active_is_no_exit(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service = make(world)
    env.add(4)
    env.add(5, active=False, roles=["exit"])
    rule = {"from": ["clients"], "to": "any"}
    assert refused(service, "node2", [{**rule, "via": "exit:4"}]) == "role_required"
    assert refused(service, "node2", [{**rule, "via": "exit:5"}]) == "exit_node"


def test_a_source_must_be_exported_to_use_an_exit(world: Any) -> None:  # type: ignore[no-untyped-def]
    _, service = make(world)
    source = {"name": "wg", "interface": "wg0", "cidr": "10.8.2.0/24", "export": False}
    rule = {"from": ["wg"], "to": "any", "via": "exit:3"}
    assert refused(service, "node2", [rule], sources=[source]) == "source_export"
    service.set_policy("node2", {"sources": [{**source, "export": True}], "egress": [rule]})


def test_the_exit_role_cannot_be_dropped_while_an_agent_uses_it(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service = make(world)
    service.set_policy("node2", {"egress": [OUT]})
    with pytest.raises(ManagementError) as raised:
        service.update("node3", AgentPatch(roles=[]))
    assert raised.value.error == "exit_in_use" and "node2" in str(raised.value)
    assert env.registry.get_node(3).roles == ["exit"]
    service.set_policy("node2", {"egress": []})
    service.update("node3", AgentPatch(roles=[]))


def test_a_bundle_is_not_compiled_for_an_exit_that_lost_its_role_behind_our_back(
    world: Any,  # type: ignore[no-untyped-def]
) -> None:
    env, service = make(world)
    service.set_policy("node2", {"egress": [OUT]})
    env.registry.update_node(3, roles=[])  # bypassing the service
    with pytest.raises(BundleError):
        env.compile(2)


def test_the_hub_derives_transit_exits_from_the_agents_policies(
    world: Any,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    env, service = make(world)
    service.set_policy(
        "node2",
        {
            "sources": [{"name": "wg", "interface": "wg0", "cidr": "10.8.2.0/24"}],
            "egress": [
                {"from": ["clients", "wg"], "to": "any", "via": "exit:3"},
            ],
        },
    )

    class Runner(FakeRunner):
        def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
            if argv == ["ip", "-j", "-4", "route", "show", "table", "main"]:
                routes = [
                    {"dst": "10.99.0.2", "dev": "vpns0", "scope": "link"},
                    {"dst": "10.99.0.3", "dev": "vpns1", "scope": "link"},
                ]
                return CommandResult(tuple(argv), 0, json.dumps(routes), "")
            return super().run(argv, **kwargs)

    facts = HubNetInputs(env.config, runner=Runner(), proc_sys=tmp_path).facts()
    assert facts.fabric_guard and facts.fabric_ifaces == ("vpns0", "vpns1")
    (transit,) = facts.transit_exits
    assert transit.node == 3 and transit.exit_iface == "vpns1"
    assert set(transit.sources) == {
        ipaddress.ip_network("10.100.2.0/24"),
        ipaddress.ip_network("10.8.2.0/24"),
    }
    prefixes = {str(net) for nets in facts.node_prefixes.values() for net in nets}
    assert {"10.99.0.0/24", "10.100.2.0/24", "10.100.3.0/24"} <= prefixes

    # The exit node disconnects: the exit stays declared and fails closed.
    class Offline(Runner):
        def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
            if argv == ["ip", "-j", "-4", "route", "show", "table", "main"]:
                routes = [{"dst": "10.99.0.2", "dev": "vpns0", "scope": "link"}]
                return CommandResult(tuple(argv), 0, json.dumps(routes), "")
            return FakeRunner.run(self, argv, **kwargs)

    facts = HubNetInputs(env.config, runner=Offline(), proc_sys=tmp_path).facts()
    assert facts.transit_exits[0].exit_iface is None and facts.fabric_ifaces == ("vpns0",)


def test_the_hub_ignores_an_exit_whose_target_is_not_an_exit_node(
    world: Any,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    env, service = make(world)
    service.set_policy("node2", {"egress": [OUT]})
    env.registry.update_node(3, roles=[])
    facts = HubNetInputs(env.config, runner=FakeRunner(), proc_sys=tmp_path).facts()
    assert facts.transit_exits == ()


def test_the_hub_marks_a_set_exit_by_the_static_routes_and_the_addresses_the_agent_reported(
    world: Any,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    """D-79: the agent classifies by the addresses it resolved itself and reports them;
    the hub matches the same ones (no second resolution that could differ)."""
    env, service = make(world)
    service.set_policy(
        "node2",
        {
            "sets": {"web": {"routes": ["198.51.100.0/24"], "domains": ["example.org"]}},
            "egress": [
                {"from": ["clients"], "to": {"set": "web"}, "via": "exit:3"},
                {"from": ["clients"], "to": "any", "via": "exit:3"},
            ],
        },
    )
    runner = FakeRunner()

    before = HubNetInputs(env.config, runner=runner, proc_sys=tmp_path).facts()
    assert [t.dest for t in before.transit_exits] == [frozenset({"198.51.100.0/24"}), None]

    env.registry.add_report(
        2,
        {"applied_version": 1, "exit_sets": {"web": ["203.0.113.9", "not-an-address"]}},
    )
    facts = HubNetInputs(env.config, runner=runner, proc_sys=tmp_path).facts()
    assert [t.dest for t in facts.transit_exits] == [
        frozenset({"198.51.100.0/24", "203.0.113.9/32"}),
        None,
    ]


def test_the_agent_reports_the_addresses_behind_the_destinations_of_its_exit_rules() -> None:
    """D-79: keyed like NodeFacts.resolved (set name, `rule<N>` for an inline destination);
    rules that do not exit via another node contribute nothing."""
    from types import SimpleNamespace

    from kornode.net.model import EgressPolicy
    from kornode_agent.agent import Agent

    policy = EgressPolicy.model_validate(
        {
            "sets": {"web": {"domains": ["example.org"]}, "lan": {"routes": ["10.0.0.0/8"]}},
            "egress": [
                {"from": ["clients"], "to": {"set": "web"}, "via": "exit:3"},
                {"from": ["clients"], "to": {"domains": ["example.net"]}, "via": "exit:3"},
                {"from": ["clients"], "to": {"set": "lan"}, "via": "local"},
                {"from": ["clients"], "to": "any", "via": "exit:3"},
            ],
        }
    )
    stub = SimpleNamespace(
        inputs=SimpleNamespace(active=SimpleNamespace(bundle=SimpleNamespace(policy=policy))),
        set_resolver=SimpleNamespace(
            read=lambda: {
                "web": frozenset({"203.0.113.9", "198.51.100.1"}),
                "rule1": frozenset({"192.0.2.5"}),
                "lan": frozenset({"10.1.1.1"}),
            }
        ),
    )

    assert Agent._exit_sets(stub) == {  # type: ignore[arg-type]
        "web": ["198.51.100.1", "203.0.113.9"],
        "rule1": ["192.0.2.5"],
    }

    stub.inputs.active = None
    assert Agent._exit_sets(stub) == {}  # type: ignore[arg-type]


def test_the_hub_indexes_inline_destinations_like_the_agent_does_with_the_implicit_rules(
    world: Any,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    """The bundle gets `to-fabric` in front of the operator's rules, so the agent reports its
    inline destination as `rule1`; the hub must read the same key (D-79)."""
    env, service = make(world)
    service.set_policy(
        "node2",
        {"egress": [{"from": ["clients"], "to": {"domains": ["example.org"]}, "via": "exit:3"}]},
    )
    env.registry.add_report(2, {"applied_version": 1, "exit_sets": {"rule1": ["203.0.113.9"]}})

    facts = HubNetInputs(env.config, runner=FakeRunner(), proc_sys=tmp_path).facts()

    assert [t.dest for t in facts.transit_exits] == [frozenset({"203.0.113.9/32"})]
