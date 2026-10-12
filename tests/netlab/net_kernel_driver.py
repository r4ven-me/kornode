"""Runs inside a netlab namespace (as root): compile a fixed node policy,
converge the real kernel with kornode.net.kernel, print what happened as JSON.

Usage: net_kernel_driver.py converge|plan [--corp CIDR,...]
       net_kernel_driver.py run SOCKET_PATH   (reconciler until SIGTERM)
"""

from __future__ import annotations

import ipaddress
import json
import signal
import sys
import threading
from pathlib import Path

from kornode.net.compile import NodeFacts, TunnelFact, compile_policy
from kornode.net.diff import diff
from kornode.net.kernel import Kernel
from kornode.net.model import EgressPolicy
from kornode.net.reconciler import Reconciler, serve_control, watch_netlink


def build(corp: list[str]):  # type: ignore[no-untyped-def]
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
    return compile_policy(policy, facts), policy, facts


def desired(corp: list[str]):  # type: ignore[no-untyped-def]
    return build(corp)[0].desired


def run(socket_path: Path) -> None:
    reconciler = Reconciler(lambda: desired(["10.60.0.0/16"]), Kernel())
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: (stop.set(), reconciler.stop()))
    server = serve_control(reconciler, socket_path)
    threading.Thread(target=watch_netlink, args=(reconciler, stop), daemon=True).start()
    try:
        reconciler.run_forever()
    finally:
        server.shutdown()
        server.server_close()


def main() -> None:
    if sys.argv[1] == "explain":
        from kornode.net.explain import explain

        compiled, policy, facts = build(["10.60.0.0/16"])
        decision = explain(
            compiled, policy, facts, sys.argv[2], sys.argv[3], route_get=Kernel().route_get
        )
        print(json.dumps(decision.as_dict()))
        return
    if sys.argv[1] == "run":
        run(Path(sys.argv[2]))
        return
    corp = ["10.60.0.0/16"]
    if "--corp" in sys.argv:
        corp = sys.argv[sys.argv.index("--corp") + 1].split(",")
    if sys.argv[1] == "cleanup":
        Kernel().remove_v1_state(
            filter_table="kornode_filter",
            route_tables=[1201, 1202],
            docker_exprs=["ip saddr 10.100.3.0/24 accept", "ip daddr 10.100.3.0/24 accept"],
        )
        print(json.dumps({"ok": True}))
        return
    want = desired(corp)
    kernel = Kernel()
    keys = [sysctl.key for sysctl in want.sysctls]
    chains = sorted({rule.chain_key for rule in want.foreign_rules})
    first = diff(kernel.read(keys, chains), want)
    out: dict[str, object] = {"plan": [type(op).__name__ for op in first.ops]}
    if sys.argv[1] == "converge":
        kernel.apply(first)
        second = diff(kernel.read(keys, chains), want)
        out["after"] = [repr(op) for op in second.ops]
    print(json.dumps(out))


if __name__ == "__main__":
    main()
