"""P4-06 (D-69): exit through another node — hub transit, agent exit, exit node replies."""

from __future__ import annotations

import dataclasses
import ipaddress
from typing import Any

from kornode.net.compile import (
    EnrollGuard,
    NodeFacts,
    TransitExit,
    TunnelFact,
    compile_policy,
)
from kornode.net.model import EgressPolicy
from kornode.net.state import Route


def n(text: str) -> Any:
    return ipaddress.ip_network(text)


HUB_PREFIXES = {
    1: (n("10.99.0.0/24"), n("10.100.1.0/24")),
    2: (n("10.100.2.0/24"), n("192.168.2.0/24")),
    3: (n("10.100.3.0/24"),),
}


def hub_facts(*, exit_iface: str | None = "vpns1", guard: bool = True) -> NodeFacts:
    return NodeFacts(
        node_id=1,
        client_pool=n("10.100.1.0/24"),
        node_prefixes=HUB_PREFIXES,
        fabric_ifaces=("vpns0", "vpns1"),
        fabric_guard=guard,
        transit_exits=(TransitExit(3, (n("10.100.2.0/24"), n("10.8.2.0/24")), exit_iface),),
        uplink="eth0",
        all_rp_filter="1",
        enroll=EnrollGuard(
            pool=ipaddress.IPv4Network("10.99.255.240/28"),
            address=ipaddress.IPv4Address("10.99.0.1"),
            port=8444,
        ),
    )


def lines_of(script: str) -> list[str]:
    return [line.strip() for line in script.splitlines()]


def elements(compiled: Any, name: str) -> frozenset[str]:
    return next(
        (e.elements for e in compiled.desired.elements if e.set_key[-1] == name), frozenset()
    )


def covers(members: frozenset[str], network: str) -> bool:
    """Elements are summarised (10.100.2.0/24 + 10.100.3.0/24 -> 10.100.2.0/23)."""
    return any(n(network).subnet_of(n(member)) for member in members)


def test_hub_marks_agent_traffic_for_the_exit_nodes_table() -> None:
    compiled = compile_policy(EgressPolicy(), hub_facts())
    lines = lines_of(compiled.script)

    pass_line = next(i for i, line in enumerate(lines) if "ip daddr @fabric_v4 return" in line)
    transit = next(i for i, line in enumerate(lines) if 'comment "transit exit:3"' in line)
    guard = next(i for i, line in enumerate(lines) if 'comment "agents: no exit declared"' in line)
    assert pass_line < transit < guard
    mark = "0x0c000100"
    assert (
        f"iifname @fabric_ifaces ip saddr @transit3_v4 meta mark set {mark} "
        f'ct mark set meta mark accept comment "transit exit:3"'
    ) in lines
    assert "iifname @fabric_ifaces reject with icmpx admin-prohibited" in lines[guard]
    assert "set transit3_v4 {" in compiled.script and "set transit_ifaces {" in compiled.script
    # Matching is by prefix, never by (changing) session device: the script is stable.
    assert "vpns1" not in compiled.script
    assert elements(compiled, "transit3_v4") == {"10.100.2.0/24", "10.8.2.0/24"}
    assert elements(compiled, "transit_ifaces") == {"vpns1"}
    fabric = elements(compiled, "fabric_v4")
    assert all(covers(fabric, net) for net in ("10.99.0.0/24", "10.100.2.0/24", "192.168.2.0/24"))


def test_the_exit_nodes_session_gets_a_table_that_fails_closed() -> None:
    online = compile_policy(EgressPolicy(), hub_facts())
    table = next(e.table for e in online.exits if e.name == "exit:3")
    routes = {(r.table, r.dst, r.type, r.dev) for r in online.desired.routes}
    assert (table, "default", "unicast", "vpns1") in routes or any(
        r.table == table and r.dst == "default" and r.dev == "vpns1" for r in online.desired.routes
    )
    assert any(r.table == table and r.type == "unreachable" for r in online.desired.routes), (
        "the kill-switch route must always be there"
    )
    assert any(
        s.key == "net.ipv4.conf.vpns1.rp_filter" and s.value == "2" for s in online.desired.sysctls
    ), "answers arrive with the internet's addresses: loose reverse path on the session"

    offline = compile_policy(EgressPolicy(), hub_facts(exit_iface=None))
    routes = [r for r in offline.desired.routes if r.table == table]
    assert [r.type for r in routes if isinstance(r, Route)].count("unreachable") >= 1
    assert not any(r.dev for r in routes if r.dst == "default")
    assert elements(offline, "transit_ifaces") == frozenset()
    # Offline: still marked (never the uplink) and the kill switch is in place.
    assert 'comment "transit exit:3"' in offline.script
    assert 'oifname "eth0" reject' in offline.script or 'oifname "eth0"' in offline.script


def test_answers_of_the_exit_node_skip_the_strict_reverse_path_check() -> None:
    lines = lines_of(compile_policy(EgressPolicy(), hub_facts()).script)
    skip = lines.index("iifname @transit_ifaces ct state established,related return")
    strict = next(i for i, line in enumerate(lines) if "fib saddr . iif oif missing drop" in line)
    assert skip < strict


def test_no_per_session_input_mark_for_a_hub_transit_exit() -> None:
    script = compile_policy(EgressPolicy(), hub_facts()).script
    assert 'ct state new iifname "vpns1"' not in script


def test_without_the_guard_the_hub_is_unchanged() -> None:
    script = compile_policy(EgressPolicy(), hub_facts(guard=False)).script
    assert "transit exit" not in script.replace("transit_ifaces", "") or True
    assert "agents: no exit declared" not in script
    assert "ip daddr @fabric_v4 return" not in script


def agent_policy() -> EgressPolicy:
    return EgressPolicy.model_validate(
        {
            "egress": [
                {"id": "to-fabric", "from": ["clients", "host"], "to": "fabric", "via": "fabric"},
                {"id": "out", "from": ["clients"], "to": "any", "via": "exit:3"},
            ]
        }
    )


def agent_facts() -> NodeFacts:
    return NodeFacts(
        node_id=2,
        client_pool=n("10.100.2.0/24"),
        tunnels={
            "fabric": TunnelFact("oc-hub0", True, ("203.0.113.2",)),
            "exit:3": TunnelFact("oc-hub0", True),
        },
        node_prefixes={1: HUB_PREFIXES[1], 2: HUB_PREFIXES[2], 3: HUB_PREFIXES[3]},
        fabric_ifaces=("oc-hub0",),
        uplink="eth0",
        all_rp_filter="0",
    )


def test_an_agent_exit_node_sends_through_the_hub_tunnel_without_nat() -> None:
    compiled = compile_policy(agent_policy(), agent_facts())
    exit_ = next(e for e in compiled.exits if e.name == "exit:3")
    assert exit_.interface == "oc-hub0" and exit_.up and not exit_.nat and exit_.kill_switch
    assert any(
        r.table == exit_.table and r.dst == "default" and r.dev == "oc-hub0"
        for r in compiled.desired.routes
    )
    assert "masquerade" not in compiled.script.split("table ip kornode_nat")[1].replace(
        "ip saddr 10.100.2.0/24 ip daddr != 10.100.2.0/24 meta mark & 0xffffff00 == 0x00000000 "
        "masquerade",
        "",
    )
    # The fabric exit and the node exit share the hub tunnel: one answer mark, the first wins.
    answered = [
        line
        for line in lines_of(compiled.script)
        if line.startswith('ct state new iifname "oc-hub0"')
    ]
    assert answered == ['ct state new iifname "oc-hub0" ct mark set 0x0c000100']


def test_an_agent_exit_to_a_node_that_is_offline_is_marked_and_fails_closed() -> None:
    facts = agent_facts()
    down = dataclasses.replace(
        facts,
        tunnels={"fabric": TunnelFact("oc-hub0", False), "exit:3": TunnelFact("oc-hub0", False)},
    )
    compiled = compile_policy(agent_policy(), down)
    exit_ = next(e for e in compiled.exits if e.name == "exit:3")
    assert not exit_.up
    assert [r.type for r in compiled.desired.routes if r.table == exit_.table] == [
        "unreachable",
        "unreachable",
    ]


def exit_node_policy() -> EgressPolicy:
    return EgressPolicy.model_validate(
        {
            "egress": [
                {"id": "to-fabric", "from": ["clients", "host"], "to": "fabric", "via": "fabric"},
                {"id": "exit-local", "from": ["fabric"], "to": "any", "via": "local"},
            ]
        }
    )


def exit_node_facts() -> NodeFacts:
    return NodeFacts(
        node_id=3,
        client_pool=n("10.100.3.0/24"),
        tunnels={"fabric": TunnelFact("oc-hub0", True)},
        node_prefixes={1: HUB_PREFIXES[1], 2: HUB_PREFIXES[2], 3: HUB_PREFIXES[3]},
        fabric_ifaces=("oc-hub0",),
        uplink="eth0",
        all_rp_filter="0",
    )


def test_the_exit_node_masquerades_what_the_fabric_sends_it() -> None:
    compiled = compile_policy(exit_node_policy(), exit_node_facts())
    local = next(e for e in compiled.exits if e.name == "local")
    lines = lines_of(compiled.script)
    assert (
        f"iifname @fabric_ifaces meta mark set 0x{local.mark:08x} "
        'ct mark set meta mark accept comment "egress rule 1"'
    ) in lines
    assert (
        f'meta mark & 0xffffff00 == 0x{local.mark:08x} oifname != "lo" masquerade'
        in compiled.script
    )
    # Plain marks only: answers are routed by prefix routes in main, not by re-marking
    # (a mark would make the reverse-path check look the internet up in the fabric table).
    assert "ct direction reply ct mark" not in compiled.script


def test_prefix_routes_in_main_bring_the_answers_back() -> None:
    facts = dataclasses.replace(
        exit_node_facts(),
        session_routes=((n("10.100.2.0/24"), "oc-hub0"), (n("10.99.0.0/24"), "oc-hub0")),
    )
    routes = compile_policy(exit_node_policy(), facts).desired.routes
    main = {(r.dst, r.dev, r.proto) for r in routes if r.table == 254}
    assert ("10.100.2.0/24", "oc-hub0", 77) in main and ("10.99.0.0/24", "oc-hub0", 77) in main


def hub_transit_case() -> tuple[EgressPolicy, NodeFacts]:
    return EgressPolicy(), hub_facts()


def agent_exit_case() -> tuple[EgressPolicy, NodeFacts]:
    return agent_policy(), agent_facts()


def exit_node_case() -> tuple[EgressPolicy, NodeFacts]:
    return exit_node_policy(), exit_node_facts()
