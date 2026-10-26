"""Direct agent<->agent peer links in the kernel model (D-101, spec 07 "Peer links").

An agent reaches a peer's prefixes through a direct tunnel device preferred over the hub
path; no NAT, a peer guard, and a per-link switch "fallback via hub" decide what happens
when the direct link is down.
"""

from __future__ import annotations

import dataclasses
from ipaddress import ip_network
from typing import Any

from tests.test_net_compile import node3_case

from kornode.net.compile import NodeFacts, PeerFact, compile_policy
from kornode.net.state import Route

HUB_DEV = "oc-hub0"
PEER_DEV = "oc-p2"
PEER_PREFIXES = ("10.100.2.0/24", "192.168.2.0/24")  # node 2 in the example bundle


def _case(**peer: Any) -> tuple[Any, NodeFacts]:
    policy, facts = node3_case()
    fact = PeerFact(node_id=2, interface=PEER_DEV, up=True, carrier=("203.0.113.77",), **peer)
    return policy, dataclasses.replace(facts, peers=(fact,))


def _routes(compiled: Any) -> list[Route]:
    return sorted(compiled.desired.routes, key=repr)


def _by(compiled: Any, *, table: Any, dev: str) -> set[str]:
    return {r.dst for r in compiled.desired.routes if r.table == table and r.dev == dev}


def _interlink_table(compiled: Any) -> int:
    return next(e.table for e in compiled.exits if e.name == "interlink")


def test_no_peers_changes_nothing() -> None:
    policy, facts = node3_case()
    plain = compile_policy(policy, facts)
    assert compile_policy(policy, dataclasses.replace(facts, peers=())) == plain
    assert "peer_ifaces" not in plain.script


def test_direct_route_in_main_preferred_and_hub_route_kept_as_fallback() -> None:
    compiled = compile_policy(*_case())
    direct = {r.dst for r in compiled.desired.routes if r.table == 254 and r.dev == PEER_DEV}
    assert direct == set(PEER_PREFIXES)
    assert all(
        r.metric == 0 and r.proto != 0
        for r in compiled.desired.routes
        if r.table == 254 and r.dev == PEER_DEV
    )
    # The hub route stays in the interlink exit table (fallback via hub, the default).
    table = _interlink_table(compiled)
    assert _by(compiled, table=table, dev=HUB_DEV) >= set(PEER_PREFIXES)


def test_fallback_off_removes_the_hub_route_and_fails_closed() -> None:
    compiled = compile_policy(*_case(fallback_hub=False))
    table = _interlink_table(compiled)
    assert not (_by(compiled, table=table, dev=HUB_DEV) & set(PEER_PREFIXES))
    # Other nodes' prefixes (the hub's) still go through the hub.
    assert _by(compiled, table=table, dev=HUB_DEV)
    # The permanent kill-switch route of the exit table is untouched.
    assert any(
        r.table == table and r.dst == "default" and r.type == "unreachable"
        for r in compiled.desired.routes
    )
    # Direct up: reachable directly.
    assert _by(compiled, table=254, dev=PEER_DEV) == set(PEER_PREFIXES)

    # Direct down: nothing left for those prefixes -> unreachable default (no leak).
    policy, facts = node3_case()
    down = dataclasses.replace(
        facts,
        peers=(PeerFact(node_id=2, interface=PEER_DEV, up=False, fallback_hub=False),),
    )
    gone = compile_policy(policy, down)
    assert not _by(gone, table=254, dev=PEER_DEV)
    assert not (_by(gone, table=table, dev=HUB_DEV) & set(PEER_PREFIXES))


def test_direct_down_with_fallback_uses_only_the_hub_route() -> None:
    policy, facts = node3_case()
    down = dataclasses.replace(facts, peers=(PeerFact(node_id=2, interface=PEER_DEV, up=False),))
    compiled = compile_policy(policy, down)
    assert not _by(compiled, table=254, dev=PEER_DEV)
    assert _by(compiled, table=_interlink_table(compiled), dev=HUB_DEV) >= set(PEER_PREFIXES)


def test_gateway_hub_routes_in_main_lose_to_the_direct_route() -> None:
    """A gateway agent keeps every node prefix in main via the hub (from: interlink): the
    peer's prefixes get a worse metric there, so the direct route wins while it is up."""
    policy, facts = node3_case()
    hub_routes = tuple((ip_network(p), HUB_DEV) for p in PEER_PREFIXES + ("10.99.0.0/24",))
    peer = PeerFact(node_id=2, interface=PEER_DEV, up=True)
    compiled = compile_policy(
        policy, dataclasses.replace(facts, session_routes=hub_routes, peers=(peer,))
    )
    main = [r for r in compiled.desired.routes if r.table == 254]
    by_dst = {(r.dst, r.dev): r.metric for r in main}
    for prefix in PEER_PREFIXES:
        assert by_dst[(prefix, PEER_DEV)] < by_dst[(prefix, HUB_DEV)]
    assert by_dst[("10.99.0.0/24", HUB_DEV)] == 0  # not a peer prefix: unchanged

    # Fallback off: the hub route for the peer's prefixes disappears from main as well.
    off = dataclasses.replace(peer, fallback_hub=False)
    strict = compile_policy(
        policy, dataclasses.replace(facts, session_routes=hub_routes, peers=(off,))
    )
    assert not {r.dst for r in strict.desired.routes if r.table == 254 and r.dev == HUB_DEV} & set(
        PEER_PREFIXES
    )


def test_peer_devices_are_interlink_devices_without_nat_and_with_a_guard() -> None:
    compiled = compile_policy(*_case())
    script = compiled.script
    elements = {(e.table, e.set_name): e.elements for e in compiled.desired.elements}
    assert PEER_DEV in elements[("kornode", "interlink_ifaces")]
    assert PEER_DEV in elements[("kornode_nat", "interlink_ifaces")]  # NAT skips it
    assert elements[("kornode", "peer_ifaces")] == frozenset({PEER_DEV})
    # Peers may reach this node only: anything left after the implicit returns is refused,
    # so a peer can neither use this node as an exit nor as a relay to other nodes.
    chain = script.split("chain egress_classify {", 1)[1].split("\n  }", 1)[0].splitlines()
    guard = next(i for i, line in enumerate(chain) if "@peer_ifaces" in line)
    last_implicit = max(
        i for i, line in enumerate(chain) if line.strip().endswith("@carrier_v6 return")
    )
    first_rule = next(i for i, line in enumerate(chain) if "meta mark set" in line)
    assert last_implicit < guard < first_rule
    assert "reject with icmpx admin-prohibited" in chain[guard]


def test_peer_connections_are_answered_through_the_interlink_exit() -> None:
    compiled = compile_policy(*_case())
    interlink = next(e for e in compiled.exits if e.name == "interlink")
    lines = [line.strip() for line in compiled.script.splitlines()]
    answer = [
        line for line in lines if line.startswith(f'ct state new iifname "{PEER_DEV}" ct mark set')
    ]
    assert len(answer) == 1 and f"0x{interlink.mark:08x}" in answer[0]


def test_peer_endpoint_is_a_carrier_and_peer_device_is_loose_rp_filtered() -> None:
    compiled = compile_policy(*_case())
    assert any(r.priority == 95 and r.to == "203.0.113.77/32" for r in compiled.desired.rules)
    elements = {(e.table, e.set_name): e.elements for e in compiled.desired.elements}
    assert "203.0.113.77/32" in elements[("kornode", "carrier_v4")]
    assert any(
        s.key == f"net.ipv4.conf.{PEER_DEV}.rp_filter" and s.value == "2"
        for s in compiled.desired.sysctls
    )


def test_listener_sessions_get_a_strict_reverse_path_check() -> None:
    policy, facts = node3_case()
    listener = dataclasses.replace(
        facts,
        peers=(PeerFact(node_id=2, interface="vpns0", up=True),),
        peer_session_iface="vpns*",
    )
    compiled = compile_policy(policy, listener)
    assert 'iifname "vpns*" meta nfproto ipv4 fib saddr . iif oif missing drop' in compiled.script


def test_peer_compile_is_deterministic() -> None:
    policy, facts = _case()
    shuffled = dataclasses.replace(
        facts, node_prefixes=dict(reversed(list(facts.node_prefixes.items())))
    )
    assert compile_policy(policy, facts) == compile_policy(policy, shuffled)


def test_agent_with_a_dialed_and_a_listening_peer_matches_golden(update_golden: bool) -> None:
    from tests.test_net_compile import GOLDEN, _render

    policy, facts = node3_case()
    facts = dataclasses.replace(
        facts,
        peers=(
            PeerFact(node_id=2, interface=PEER_DEV, up=True, carrier=("203.0.113.77",)),
            PeerFact(node_id=4, interface="vpns1", up=True, fallback_hub=False),
        ),
        node_prefixes={**facts.node_prefixes, 4: (ip_network("10.100.4.0/24"),)},
        peer_session_iface="vpns*",
    )
    for kind, text in _render(compile_policy(policy, facts)).items():
        path = GOLDEN / f"agent_peers.{kind}"
        if update_golden:
            path.write_text(text, encoding="utf-8")
        assert text == path.read_text(encoding="utf-8"), f"{path.name} differs"
