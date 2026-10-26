"""Runs inside a netlab namespace (as root): compile a fixed node policy,
converge the real kernel with kornode.net.kernel, print what happened as JSON.

Usage: net_kernel_driver.py converge|plan [--corp CIDR,...] [--session CIDR=DEV]
                            [--peer NODE=DEV [--peer-down] [--no-fallback]]  (direct link, D-101)
       net_kernel_driver.py run SOCKET_PATH   (reconciler until SIGTERM)
"""

from __future__ import annotations

import ipaddress
import json
import signal
import sys
import threading
from pathlib import Path

from kornode.net.compile import NodeFacts, PeerFact, TunnelFact, compile_policy
from kornode.net.diff import diff
from kornode.net.kernel import Kernel
from kornode.net.model import EgressPolicy
from kornode.net.reconciler import Reconciler, serve_control, watch_netlink


def build(  # type: ignore[no-untyped-def]
    corp: list[str],
    session: tuple[str, str] | None = None,
    peer: PeerFact | None = None,
):
    policy = EgressPolicy.model_validate(
        {
            "sets": {"corp": {"routes": corp}},
            "egress": [
                {"from": ["clients", "host"], "to": "interlink", "via": "interlink"},
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
            "interlink": TunnelFact("ktun0", True, ("203.0.113.2",)),
            "upstream:office": TunnelFact("ktun1", True, ("198.51.100.9",)),
        },
        sources={},
        upstreams=("office",),
        node_prefixes={1: (net("10.100.1.0/24"),), 2: (net("10.100.2.0/24"),)},
        interlink_ifaces=("ktun0",),
        local_networks=(net("192.168.3.0/24"),),
        session_routes=((net(session[0]), session[1]),) if session else (),
        peers=(peer,) if peer else (),
        uplink="kup0",
        all_rp_filter="1",
    )
    return compile_policy(policy, facts), policy, facts


def desired(  # type: ignore[no-untyped-def]
    corp: list[str],
    session: tuple[str, str] | None = None,
    peer: PeerFact | None = None,
):
    return build(corp, session, peer)[0].desired


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
    session = None
    if "--session" in sys.argv:
        cidr, dev = sys.argv[sys.argv.index("--session") + 1].split("=")
        session = (cidr, dev)
    peer = None
    if "--peer" in sys.argv:
        node, dev = sys.argv[sys.argv.index("--peer") + 1].split("=")
        peer = PeerFact(
            node_id=int(node),
            interface=dev,
            up="--peer-down" not in sys.argv,
            carrier=("203.0.113.77",),
            fallback_hub="--no-fallback" not in sys.argv,
        )
    want = desired(corp, session, peer)
    kernel = Kernel()
    keys = [sysctl.key for sysctl in want.sysctls]
    chains = sorted({rule.chain_key for rule in want.foreign_rules})
    devs = sorted({address.dev for address in want.addresses})  # like the reconciler
    first = diff(kernel.read(keys, chains, devs), want)
    out: dict[str, object] = {"plan": [type(op).__name__ for op in first.ops]}
    if sys.argv[1] == "converge":
        kernel.apply(first)
        second = diff(kernel.read(keys, chains, devs), want)
        out["after"] = [repr(op) for op in second.ops]
    print(json.dumps(out))


if __name__ == "__main__":
    main()
