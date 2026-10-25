"""Runs inside a netlab namespace (as root): converge the kernel of the hub or of the
exit node of NL-17/NL-18 (hub source leaves through node 2).

Usage: exit_set_driver.py hub|node2 set|full|local [--offline]
Prints the leftover plan (must be empty) as JSON.
"""

from __future__ import annotations

import ipaddress
import json
import sys

from kornode.net.compile import NodeFacts, SourceFact, TunnelFact, compile_policy
from kornode.net.diff import diff
from kornode.net.kernel import Kernel
from kornode.net.model import EgressPolicy

n = ipaddress.ip_network
LISTED = "198.51.100.0/24"
SOURCE = "10.8.1.0/24"
PREFIXES = {1: (n("10.99.0.0/24"), n("10.100.1.0/24"), n(SOURCE)), 2: (n("10.100.2.0/24"),)}


def hub(scenario: str, offline: bool) -> tuple[EgressPolicy, NodeFacts]:
    rules: list[dict[str, object]] = (
        [
            {"from": ["wgusers"], "to": {"set": "listed"}, "via": "node:2"},
            {"from": ["wgusers"], "to": "any", "via": "local"},
        ]
        if scenario == "set"
        else [{"from": ["wgusers"], "to": "any", "via": "local"}]
        if scenario == "local"
        else [{"from": ["wgusers"], "to": "any", "via": "node:2"}]
    )
    policy = EgressPolicy.model_validate(
        {
            "sources": [{"name": "wgusers", "interface": "wg0", "cidr": SOURCE}],
            "sets": {"listed": {"routes": [LISTED]}},
            "egress": rules,
        }
    )
    facts = NodeFacts(
        node_id=1,
        client_pool=n("10.100.1.0/24"),
        tunnels={} if offline else {"node:2": TunnelFact("vpns1", True)},
        sources={"wgusers": SourceFact(present=True)},
        node_prefixes=PREFIXES,
        interlink_ifaces=() if offline else ("vpns1",),
        interlink_guard=True,
        # The hub routes node 2's prefixes into its session (proto-77 routes in main).
        session_routes=() if offline else ((n("10.100.2.0/24"), "vpns1"),),
        uplink="eth0",
        all_rp_filter="1",
    )
    return policy, facts


def node2() -> tuple[EgressPolicy, NodeFacts]:
    policy = EgressPolicy.model_validate(
        {"egress": [{"from": ["interlink"], "to": "any", "via": "local"}]}
    )
    facts = NodeFacts(
        node_id=2,
        client_pool=n("10.100.2.0/24"),
        tunnels={"interlink": TunnelFact("oc-hub0", True)},
        node_prefixes=PREFIXES,
        interlink_ifaces=("oc-hub0",),
        session_routes=((n("10.99.0.0/24"), "oc-hub0"), (n(SOURCE), "oc-hub0")),
        uplink="eth0",
        all_rp_filter="1",
    )
    return policy, facts


def main() -> None:
    role, scenario = sys.argv[1], sys.argv[2]
    policy, facts = hub(scenario, "--offline" in sys.argv) if role == "hub" else node2()
    want = compile_policy(policy, facts).desired
    kernel = Kernel()
    keys = [sysctl.key for sysctl in want.sysctls]
    chains = sorted({rule.chain_key for rule in want.foreign_rules})
    devs = sorted({address.dev for address in want.addresses})  # like the reconciler
    kernel.apply(diff(kernel.read(keys, chains, devs), want))
    left = diff(kernel.read(keys, chains, devs), want)
    print(json.dumps({"after": [repr(op) for op in left.ops]}))


if __name__ == "__main__":
    main()
