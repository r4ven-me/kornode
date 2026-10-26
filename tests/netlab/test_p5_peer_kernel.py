"""Direct agent<->agent links in a real kernel (D-101, phase 1): the compiled routes prefer
the peer device, fall back to the hub tunnel when the direct link is down, and fail closed
when the link has "fallback via hub" switched off. Converges with the real `kornode.net`."""

from __future__ import annotations

import pytest
from tests.netlab.lab import Lab, Namespace
from tests.netlab.test_net_kernel import drive

pytestmark = pytest.mark.netlab

PEER_PREFIX_HOST = "10.100.2.5"  # a host in node 2's pool (the example's node_prefixes)
INTERLINK_MARK = "0x0c800100"  # exit_mark("interlink"), see tests/golden/node3.nft


@pytest.fixture
def agent(lab: Lab) -> Namespace:
    ns = lab.add_namespace("agent")
    for name in ("ktun0", "ktun1", "kup0", "kpeer0"):
        ns.run(["ip", "link", "add", name, "type", "dummy"])
        ns.run(["ip", "link", "set", name, "up"])
    ns.run(["ip", "addr", "add", "192.168.3.1/24", "dev", "kup0"])
    return ns


def _route_dev(ns: Namespace, *, marked: bool) -> str:
    args = ["ip", "-4", "route", "get", PEER_PREFIX_HOST]
    if marked:
        args += ["mark", INTERLINK_MARK]
    result = ns.run(args, check=False)
    if not result.ok:
        return "unreachable"
    return result.stdout.split(" dev ")[1].split()[0]


def test_direct_route_wins_and_the_hub_route_takes_over_when_the_link_is_down(
    agent: Namespace,
) -> None:
    assert drive(agent, "converge", "--peer", "2=kpeer0")["after"] == []
    # Both an unmarked packet (main) and an interlink-marked one prefer the direct device.
    assert _route_dev(agent, marked=False) == "kpeer0"
    assert _route_dev(agent, marked=True) == "kpeer0"
    # The peer's endpoint is a carrier: never routed into a tunnel.
    assert "to 203.0.113.77 lookup main" in agent.run(["ip", "rule", "show"]).stdout

    # Direct link down: the main route goes with the compiled state, the hub route remains.
    assert drive(agent, "converge", "--peer", "2=kpeer0", "--peer-down")["after"] == []
    assert _route_dev(agent, marked=True) == "ktun0"
    # Back up: direct again, no leftovers.
    assert drive(agent, "converge", "--peer", "2=kpeer0")["after"] == []
    assert _route_dev(agent, marked=True) == "kpeer0"
    assert "10.100.2.0/24" in agent.run(["ip", "route", "show", "proto", "77"]).stdout


def test_without_fallback_a_dead_direct_link_fails_closed(agent: Namespace) -> None:
    flags = ["--peer", "2=kpeer0", "--no-fallback"]
    assert drive(agent, "converge", *flags)["after"] == []
    assert _route_dev(agent, marked=True) == "kpeer0"

    assert drive(agent, "converge", *flags, "--peer-down")["after"] == []
    # No hub route for the peer's prefixes: the exit table's unreachable default answers.
    assert _route_dev(agent, marked=True) == "unreachable"
    # Other prefixes still go through the hub (node 1's pool in the example).
    out = agent.run(["ip", "-4", "route", "get", "10.100.1.5", "mark", INTERLINK_MARK])
    assert " dev ktun0 " in out.stdout


def test_peer_traffic_is_not_natted_and_refused_beyond_this_node(agent: Namespace) -> None:
    assert drive(agent, "converge", "--peer", "2=kpeer0")["after"] == []
    nft = agent.run(["nft", "list", "ruleset"]).stdout
    # The peer device is in both interlink sets: the masquerade skips it.
    assert nft.count("kpeer0") >= 3  # interlink_ifaces (filter + nat) and peer_ifaces
    assert (
        'iifname @peer_ifaces reject with icmpx admin-prohibited comment "peers: this node only"'
        in nft
    )
