"""Runs inside a netlab namespace (as root): compile a fixed node policy,
converge the real kernel with kornode.net.kernel, print what happened as JSON.

Usage: net_kernel_driver.py converge|plan [--corp CIDR,...]
"""

from __future__ import annotations

import ipaddress
import json
import sys

from kornode.net.compile import NodeFacts, TunnelFact, compile_policy
from kornode.net.diff import diff
from kornode.net.kernel import Kernel
from kornode.net.model import EgressPolicy


def desired(corp: list[str]):  # type: ignore[no-untyped-def]
    policy = EgressPolicy.model_validate(
        {
            "sets": {"corp": {"routes": corp}},
            "egress": [
                {"from": ["clients", "host"], "to": "fabric", "via": "fabric"},
                {"from": ["clients", "host"], "to": {"set": "corp"}, "via": "upstream:office"},
                {"from": ["clients"], "to": "any", "via": "local"},
            ],
        }
    )
    net = ipaddress.ip_network
    facts = NodeFacts(
        node_id=3,
        client_pool=ipaddress.IPv4Network("10.100.3.0/24"),
        tunnels={
            "fabric": TunnelFact("ktun0", True, ("203.0.113.2",)),
            "upstream:office": TunnelFact("ktun1", True, ("198.51.100.9",)),
        },
        sources={},
        upstreams=("office",),
        node_prefixes={1: (net("10.100.1.0/24"),), 2: (net("10.100.2.0/24"),)},
        fabric_ifaces=("ktun0",),
        local_networks=(net("192.168.3.0/24"),),
        uplink="kup0",
        all_rp_filter="1",
    )
    return compile_policy(policy, facts).desired


def main() -> None:
    corp = ["10.60.0.0/16"]
    if "--corp" in sys.argv:
        corp = sys.argv[sys.argv.index("--corp") + 1].split(",")
    want = desired(corp)
    kernel = Kernel()
    keys = [sysctl.key for sysctl in want.sysctls]
    first = diff(kernel.read(keys), want)
    out: dict[str, object] = {"plan": [type(op).__name__ for op in first.ops]}
    if sys.argv[1] == "converge":
        kernel.apply(first)
        second = diff(kernel.read(keys), want)
        out["after"] = [repr(op) for op in second.ops]
    print(json.dumps(out))


if __name__ == "__main__":
    main()
