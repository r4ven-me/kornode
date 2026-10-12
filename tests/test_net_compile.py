from __future__ import annotations

import dataclasses
import ipaddress
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kornode.net.compile import (
    Compiled,
    NodeFacts,
    SourceFact,
    TunnelFact,
    compile_policy,
    dead_rules,
)
from kornode.net.errors import PolicyError
from kornode.net.model import EgressPolicy, Via
from kornode.net.state import IpRule, Route, Sysctl

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "docs" / "spec" / "examples"
GOLDEN = Path(__file__).resolve().parent / "golden"


def n(text: str) -> Any:
    return ipaddress.ip_network(text)


def hub_case() -> tuple[EgressPolicy, NodeFacts]:
    cfg = yaml.safe_load((EXAMPLES / "hub.config.yaml").read_text(encoding="utf-8"))
    policy = EgressPolicy.model_validate({"sets": cfg["sets"], "egress": cfg["egress"]})
    facts = NodeFacts(
        node_id=1,
        client_pool=n("10.100.1.0/24"),
        tunnels={"upstream:office": TunnelFact("oc-office0", True, ("198.51.100.9",))},
        upstreams=("office",),
        node_prefixes={
            1: (n("10.99.0.0/24"), n("10.100.1.0/24")),
            2: (n("10.100.2.0/24"), n("192.168.2.0/24")),
        },
        fabric_ifaces=("vpns0",),
        local_networks=(n("172.17.0.0/16"),),
        resolved={"corp": frozenset({"10.60.5.5/32"})},
        uplink="eth0",
        all_rp_filter="1",
    )
    return policy, facts


def node3_case() -> tuple[EgressPolicy, NodeFacts]:
    bundle = json.loads((EXAMPLES / "bundle.node3.example.json").read_text(encoding="utf-8"))
    policy = EgressPolicy.model_validate(bundle["policy"])
    prefixes: dict[int, list[Any]] = {}
    for item in bundle["fabric"]["prefixes"]:
        prefixes.setdefault(item["node_id"], []).append(n(item["prefix"]))
    prefixes.setdefault(3, []).append(n(bundle["node"]["client_pool"]))
    fabric = bundle["tunnels"]["fabric"]
    office = bundle["tunnels"]["upstreams"][0]
    facts = NodeFacts(
        node_id=3,
        client_pool=n(bundle["node"]["client_pool"]),
        tunnels={
            "fabric": TunnelFact(fabric["interface"], True, ("203.0.113.2",)),
            "upstream:office": TunnelFact(office["interface"], True, ("198.51.100.9",)),
        },
        sources={"amnezia": SourceFact(present=True)},
        upstreams=("office",),
        node_prefixes={node: tuple(items) for node, items in prefixes.items()},
        fabric_ifaces=(fabric["interface"],),
        local_networks=(n("192.168.3.0/24"),),
        uplink="ens3",
        all_rp_filter="0",
    )
    return policy, facts


def _render(compiled: Compiled) -> dict[str, str]:
    state = compiled.desired
    return {
        "nft": compiled.script,
        "rules": "".join(f"{rule}\n" for rule in sorted(state.rules, key=repr)),
        "routes": "".join(f"{route}\n" for route in sorted(state.routes, key=repr)),
        "elements": "".join(
            f"{item.set_key}: {sorted(item.elements)}\n"
            for item in sorted(state.elements, key=lambda item: item.set_key)
        ),
        "sysctls": "".join(f"{s.key}={s.value}\n" for s in sorted(state.sysctls, key=repr)),
        "foreign": "".join(f"{rule}\n" for rule in sorted(state.foreign_rules, key=repr)),
    }


@pytest.mark.parametrize("name,case", [("hub", hub_case), ("node3", node3_case)])
def test_examples_match_golden(name: str, case: Any, update_golden: bool) -> None:
    rendered = _render(compile_policy(*case()))
    for kind, text in rendered.items():
        path = GOLDEN / f"{name}.{kind}"
        if update_golden:
            path.write_text(text, encoding="utf-8")
        assert text == path.read_text(encoding="utf-8"), f"{path.name} differs"


def test_compile_is_deterministic_regardless_of_input_order() -> None:
    policy, facts = node3_case()
    shuffled = dataclasses.replace(
        facts,
        tunnels=dict(reversed(list(facts.tunnels.items()))),
        node_prefixes=dict(reversed(list(facts.node_prefixes.items()))),
    )

    assert compile_policy(policy, facts) == compile_policy(policy, shuffled)


def test_marks_and_tables_follow_first_appearance() -> None:
    compiled = compile_policy(*hub_case())

    exits = {exit_.name: (exit_.mark, exit_.table) for exit_ in compiled.exits}
    # Matches the spec 04 explain example: upstream:office -> 0x0c000200 / 12002.
    assert exits["upstream:office"] == (0x0C000200, 12002)
    assert exits["fabric"] == (0x0C000100, 12001)
    assert exits["local"][0] == 0x0C000300


def test_local_exit_has_no_rule_or_table_but_is_masqueraded() -> None:
    compiled = compile_policy(*hub_case())

    assert not [rule for rule in compiled.desired.rules if rule.table == 12003]
    assert "== 0x0c000300 oifname != \"lo\" masquerade" in compiled.script


def test_implicit_returns_come_before_every_rule() -> None:
    script = compile_policy(*hub_case()).script
    chain = script.split("chain egress_classify {", 1)[1].split("}", 1)[0]

    first_mark = chain.index("meta mark set")
    for line in ("fib daddr type local return", "ip daddr @local_v4 return",
                 "ip daddr @carrier_v4 return"):
        assert chain.index(line) < first_mark


def test_unrouted_clients_and_sources_are_rejected_last() -> None:
    script = compile_policy(*node3_case()).script
    chain = script.split("chain egress_classify {", 1)[1].split("}", 1)[0].strip().splitlines()

    assert chain[-2:] == [
        '    ip saddr 10.100.3.0/24 reject with icmpx admin-prohibited comment "egress rule 3"',
        '    iifname "awg0" ip saddr 10.8.3.0/24 reject with icmpx admin-prohibited '
        'comment "egress rule 3"',
    ]


def test_kill_switch_blocks_the_uplink_only() -> None:
    script = compile_policy(*hub_case()).script

    assert (
        'meta mark & 0xffffff00 { 0x0c000100, 0x0c000200 } oifname "eth0" '
        "reject with icmpx admin-prohibited"
    ) in script
    assert "oifname !=" not in script.split("chain forward", 1)[1].split("}", 1)[0]


def test_kill_switch_is_strict_when_uplink_unknown() -> None:
    policy, facts = hub_case()
    facts = dataclasses.replace(facts, uplink=None)

    script = compile_policy(policy, facts).script

    assert (
        'meta mark & 0xffffff00 == 0x0c000200 oifname != "oc-office0" '
        "reject with icmpx admin-prohibited"
    ) in script


def test_exit_without_kill_switch_throws_instead_of_unreachable() -> None:
    policy, facts = hub_case()
    rules = [rule.model_dump(by_alias=True, exclude_none=True) for rule in policy.egress]
    rules[1]["kill_switch"] = False
    policy = EgressPolicy.model_validate({"sets": policy.model_dump()["sets"], "egress": rules})

    routes = compile_policy(policy, facts).desired.routes

    assert Route(table=12002, dst="default", type="throw", metric=4096) in routes


def test_down_tunnel_keeps_only_the_kill_switch_route() -> None:
    policy, facts = hub_case()
    facts = dataclasses.replace(
        facts, tunnels={"upstream:office": TunnelFact("oc-office0", False)}
    )

    routes = {r for r in compile_policy(policy, facts).desired.routes if r.table == 12002}

    assert routes == {
        Route(table=12002, dst="default", type="unreachable", metric=4096, family=4),
        Route(table=12002, dst="default", type="unreachable", metric=4096, family=6),
    }


def test_agent_fabric_exit_routes_only_other_nodes_prefixes() -> None:
    routes = compile_policy(*node3_case()).desired.routes

    fabric = {r.dst for r in routes if r.table == 12001 and r.type == "unicast"}
    assert fabric == {"10.99.0.0/24", "10.100.1.0/24", "10.100.2.0/24", "192.168.2.0/24"}


def test_carrier_rules_and_elements() -> None:
    compiled = compile_policy(*node3_case())

    assert IpRule(priority=95, table="main", to="203.0.113.2") in compiled.desired.rules
    carrier = next(e for e in compiled.desired.elements if e.set_name == "carrier_v4")
    assert carrier.elements == {"203.0.113.2/32", "198.51.100.9/32"}


def test_sysctls_lower_strict_rp_filter_only() -> None:
    hub = compile_policy(*hub_case()).desired.sysctls
    node3 = compile_policy(*node3_case()).desired.sysctls

    assert Sysctl("net.ipv4.conf.all.rp_filter", "2") in hub
    assert not [s for s in node3 if s.key == "net.ipv4.conf.all.rp_filter"]
    assert {
        Sysctl("net.ipv4.conf.oc-hub0.rp_filter", "2"),
        Sysctl("net.ipv4.conf.awg0.rp_filter", "2"),
    } <= node3


def test_missing_source_interface_is_a_warning_not_an_error() -> None:
    policy, facts = node3_case()
    facts = dataclasses.replace(facts, sources={"amnezia": SourceFact(present=False)})

    compiled = compile_policy(policy, facts)

    assert "source 'amnezia': interface awg0 is missing" in compiled.warnings
    assert 'iifname "awg0"' in compiled.script


@pytest.mark.parametrize(
    ("egress", "message"),
    [
        ([{"from": ["clients"], "to": "any", "via": "upstream:nope"}], "unknown upstream"),
        ([{"from": ["clients"], "to": "any", "via": "exit:1"}], "is this node"),
        ([{"from": ["clients"], "to": "any", "via": "exit:9"}], "unknown node 9"),
        ([{"from": ["clients"], "to": {"node": 9}, "via": "local"}], "unknown node 9"),
    ],
)
def test_invalid_references_are_rejected(egress: list[dict[str, Any]], message: str) -> None:
    _, facts = hub_case()

    with pytest.raises(PolicyError, match=message):
        compile_policy(EgressPolicy.model_validate({"egress": egress}), facts)


def test_clients_without_a_pool_are_rejected() -> None:
    _, facts = hub_case()
    facts = dataclasses.replace(facts, client_pool=None)
    policy = EgressPolicy.model_validate({"egress": [{"from": ["clients"], "to": "any",
                                                      "via": "local"}]})

    with pytest.raises(PolicyError, match="no client pool"):
        compile_policy(policy, facts)


def test_dead_rules() -> None:
    policy = EgressPolicy.model_validate(
        {
            "sets": {"corp": {"routes": ["10.60.0.0/16"]}, "web": {"domains": ["a.example.com"]}},
            "egress": [
                {"from": ["clients", "host"], "to": {"routes": ["10.0.0.0/8"]}, "via": "local"},
                {"from": ["clients"], "to": {"routes": ["10.60.0.0/16"]}, "via": "local"},
                {"from": ["clients"], "to": {"set": "web"}, "via": "local"},
                {"from": ["clients"], "to": {"set": "web"}, "via": "local"},
                {"from": ["clients"], "to": "any", "via": "local"},
                {"from": ["clients"], "to": {"set": "corp"}, "via": "local"},
                {"from": ["host"], "to": {"routes": ["192.168.0.0/16"]}, "via": "local"},
            ],
        }
    )

    # 1 is inside rule 0; 3 repeats a domain set (never shadowed); 5 follows
    # a clients->any rule; 6 is host-only and not covered.
    assert dead_rules(policy) == [(1, 0), (5, 4)]


@pytest.mark.parametrize(
    "bad",
    [
        {"egress": [{"from": ["clients"], "to": "any", "via": "upstream:"}]},
        {"egress": [{"from": ["clients"], "to": {"set": "missing"}, "via": "local"}]},
        {"egress": [{"from": ["nobody"], "to": "any", "via": "local"}]},
        {"sources": [{"name": "host", "interface": "eth9", "cidr": "10.8.1.0/24"}]},
        {"egress": [{"from": ["clients", "clients"], "to": "any", "via": "local"}]},
        {"egress": [{"from": ["clients"], "to": {}, "via": "local"}]},
    ],
)
def test_policy_model_rejects_invalid_input(bad: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        EgressPolicy.model_validate(bad)


def test_via_parsing() -> None:
    assert Via.parse("exit:12") == Via("exit", "12")
    assert Via.parse("upstream:office").name == "upstream:office"
    with pytest.raises(ValueError):
        Via.parse("exit:0")


def test_no_per_interface_sysctl_for_a_down_tunnel() -> None:
    policy, facts = hub_case()
    facts = dataclasses.replace(
        facts, tunnels={"upstream:office": TunnelFact("oc-office0", False)}
    )

    keys = {sysctl.key for sysctl in compile_policy(policy, facts).desired.sysctls}

    assert "net.ipv4.conf.oc-office0.rp_filter" not in keys
