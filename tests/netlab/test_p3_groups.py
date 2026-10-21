"""P3-02: ocserv groups `clients`/`agents`/`enroll` rendered by kornode from the registry.

Same assertions as the spikes (test_spike_p3_groups.py), but the hub runs the
configuration `korctl config render` produced and the enroll restriction that
`korctl net apply` compiled (D-42..D-44).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import pytest
from tests.netlab.helpers import tcp_check
from tests.netlab.kornode_nodes import (
    KornodeRoot,
    _popen_in_namespace,
    _terminate_process,
    _wait_until,
    initialize_runtime,
    korctl,
    write_kornode_config,
)
from tests.netlab.lab import Lab, Namespace
from tests.netlab.ocserv_peers import LISTENER, Peer, issue_client_cert, read_env

from kornode.tunnels.pin import certificate_file_pin

pytestmark = pytest.mark.netlab

FABRIC_HOST = "fabric.kornode.internal"  # vhost of agents and enrollment (S-07, D-71)
HUB_FABRIC_ADDR = "10.99.0.1"
HUB_LAN_ADDR = "172.30.1.1"
INET_ADDR = "198.51.100.2"
CONTROL_PORT = 8444
CLIENT_POOL = "10.100.1.0/24"  # derived from fabric.client_pool for node 1
FABRIC_CIDR = "10.99.0.0/24"
ENROLL_POOL = "10.99.255.240/28"
CLIENT_ROUTE = "172.30.1.0/24"  # hub LAN via server.routes: not for agents/enroll
AGENT_ID = 3
CLIENT_USER = "alice"
CLIENT_PASSWORD = "alice-password"
ENROLL_USER = "enroll-3-k2f9"
ENROLL_PASSWORD = "enroll-secret"

REGISTER_AGENT = """
import sys
from pathlib import Path
from kornode.registry.db import migrate, open_registry
from kornode.registry.repository import Registry
conn = open_registry(Path(sys.argv[1]))
migrate(conn)
registry = Registry(conn)
registry.create_node(id=int(sys.argv[2]), name=sys.argv[3])
registry.set_state(int(sys.argv[2]), "active")
"""


@dataclass(repr=False)
class RenderedHub:
    hub: Namespace
    root: KornodeRoot
    pin: str
    fabric_pin: str
    client: Peer
    agent: Peer
    enroll: Peer
    rogue: Peer
    agent_cert: tuple[Path, Path]
    client_cert: tuple[Path, Path]
    processes: list[subprocess.Popen[bytes]]

    def connect_fabric(self, peer: Peer, **kwargs: Any) -> bool:
        """Dial the hub the way an agent does: its address, the fabric vhost name as SNI."""
        return peer.connect(self.fabric_pin, sni=FABRIC_HOST, **kwargs)

    def stop(self) -> None:
        for peer in (self.client, self.agent, self.enroll, self.rogue):
            peer.stop()
        for process in self.processes:
            _terminate_process(process)


@pytest.fixture
def node_tmp() -> Iterator[Path]:
    # World-readable: ocserv workers drop privileges (see test_p0_upstream).
    path = Path(tempfile.mkdtemp(prefix="kornode-netlab-"))
    path.chmod(0o755)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def rendered_hub(lab: Lab, node_tmp: Path) -> Iterator[RenderedHub]:
    hub = lab.add_namespace("hub")
    inet = lab.add_namespace("inet")
    hub.run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    lab.add_veth(hub, inet, addr_a="198.51.100.1/24", addr_b=f"{INET_ADDR}/24")
    inet.run(["ip", "route", "add", "10.0.0.0/8", "via", "198.51.100.1"])
    # The hub fabric address is bound to lo by the reconciler (control.enabled).
    hub.run(["ip", "link", "add", "lan0", "type", "dummy"])
    hub.run(["ip", "addr", "add", f"{HUB_LAN_ADDR}/24", "dev", "lan0"])
    hub.run(["ip", "link", "set", "lan0", "up"])
    peers: dict[str, Peer] = {}
    for index, name in enumerate(("client", "agent", "enroll", "rogue")):
        ns = lab.add_namespace(name)
        base = 4 * index
        lab.add_veth(hub, ns, addr_a=f"192.0.2.{base + 1}/30", addr_b=f"192.0.2.{base + 2}/30")
        peers[name] = Peer(ns=ns, hub_addr=f"192.0.2.{base + 1}", iface=f"oc-{name}", tmp=node_tmp)

    generated = node_tmp / "hub" / "generated"
    root = write_kornode_config(
        lab,
        "hub",
        node_tmp,
        {
            "node": {"id": 1},
            "control": {"enabled": True, "port": CONTROL_PORT},
            "server": {
                "enabled": True,
                "port": 443,
                "udp_enabled": False,
                "device": "vpns",
                "cn": "hub",
                "dns": [],
                "routes": [CLIENT_ROUTE],
                "debug_level": 3,
                "connect_script": str(generated / "ocserv-connect-script-kornode"),
            },
            "auth": {
                "password": {"enabled": True},
                "certificate": {"enabled": False},
                "otp": {"enabled": False},
                "oidc": {"enabled": False},
            },
            "egress": [],
        },
    )
    initialize_runtime(hub, root.config_path)
    korctl(hub, root.config_path, "user", "create", CLIENT_USER, "--password", CLIENT_PASSWORD)
    hub.run(
        [
            sys.executable,
            "-c",
            REGISTER_AGENT,
            str(root.data_dir / "registry.db"),
            str(AGENT_ID),
            f"agent-{AGENT_ID}",
        ]
    )
    korctl(hub, root.config_path, "config", "render")
    # Enroll users are created by P3-03; until then straight into ocpasswd.
    hub.run(
        ["ocpasswd", "-c", str(root.secrets_dir / "ocpasswd-enroll"), "-g", "enroll", ENROLL_USER],
        input_text=f"{ENROLL_PASSWORD}\n{ENROLL_PASSWORD}\n",
    )
    korctl(hub, root.config_path, "net", "apply")

    certs = root.data_dir / "certs"
    out = node_tmp / "peer-certs"
    out.mkdir()
    ca = (certs / "ca.crt", certs / "ca.key")
    agent_cert = issue_client_cert(hub, *ca, out, f"agent-{AGENT_ID}", unit="agents")
    client_cert = issue_client_cert(hub, *ca, out, CLIENT_USER, unit=None)
    pin = json.loads(korctl(hub, root.config_path, "certificates", "pin").stdout)["pin"]
    fabric_pin = certificate_file_pin(certs / "fabric.crt").pin

    processes: list[subprocess.Popen[bytes]] = []
    handle = RenderedHub(
        hub=hub,
        root=root,
        pin=pin,
        fabric_pin=fabric_pin,
        client=peers["client"],
        agent=peers["agent"],
        enroll=peers["enroll"],
        rogue=peers["rogue"],
        agent_cert=agent_cert,
        client_cert=client_cert,
        processes=processes,
    )
    try:
        (node_tmp / "listener.py").write_text(LISTENER, encoding="utf-8")
        processes.append(
            _popen_in_namespace(
                hub,
                [
                    "python3",
                    str(node_tmp / "listener.py"),
                    f"{HUB_FABRIC_ADDR}:22",
                    f"{HUB_LAN_ADDR}:{CONTROL_PORT}",
                ],
                root.log_dir / "hub-listener.log",
            )
        )
        processes.append(
            _popen_in_namespace(
                inet,
                ["python3", str(node_tmp / "listener.py"), f"{INET_ADDR}:80"],
                root.log_dir / "inet-listener.log",
            )
        )
        control = _popen_in_namespace(
            hub,
            [
                "env",
                f"KORNODE_CONFIG={root.config_path}",
                f"PATH={Path(sys.executable).absolute().parent}{os.pathsep}{os.environ['PATH']}",
                sys.executable,
                "-m",
                "kornode.control",
            ],
            root.log_dir / "control-api.log",
        )
        processes.append(control)
        _wait_until(
            lambda: control.poll() is None and tcp_check(hub, HUB_FABRIC_ADDR, CONTROL_PORT),
            "control API on the hub fabric address",
        )
        ocserv = _popen_in_namespace(
            hub,
            ["ocserv", "-f", "--log-stderr", "-c", str(root.generated_dir / "ocserv.conf")],
            root.log_dir / "ocserv.log",
        )
        processes.append(ocserv)
        _wait_until(
            lambda: (
                ocserv.poll() is None
                and tcp_check(peers["client"].ns, peers["client"].hub_addr, 443)
            ),
            "ocserv on 443",
        )
        yield handle
    finally:
        handle.stop()


def test_rendered_groups_lease_from_their_pools(rendered_hub: RenderedHub) -> None:
    hub = rendered_hub
    assert hub.client.connect(hub.pin, user=CLIENT_USER, password=CLIENT_PASSWORD)
    assert hub.connect_fabric(hub.agent, cert=hub.agent_cert)

    client_addr = hub.client.address()
    assert client_addr is not None and ip_address(client_addr) in ip_network(CLIENT_POOL)
    assert hub.client.pushed_routes() == [CLIENT_ROUTE]
    assert hub.agent.address() == f"10.99.0.{AGENT_ID}"
    assert hub.agent.pushed_routes() == [FABRIC_CIDR]
    agent_env = read_env(hub.agent.tmp / f"{hub.agent.iface}.env.connect")
    print(agent_env.get("INTERNAL_IP4_DNS"))  # noqa: T201 - agents ignore pushed DNS

    assert tcp_check(hub.agent.ns, HUB_FABRIC_ADDR, CONTROL_PORT)
    assert tcp_check(hub.client.ns, HUB_LAN_ADDR, CONTROL_PORT)


def test_client_certificate_without_password_is_refused(rendered_hub: RenderedHub) -> None:
    assert not rendered_hub.connect_fabric(rendered_hub.rogue, cert=rendered_hub.client_cert)
    assert rendered_hub.rogue.address() is None


def test_agent_certificate_and_enroll_password_are_refused_on_the_client_host(
    rendered_hub: RenderedHub,
) -> None:
    """D-71, the other direction: agents and enrollment exist only on the fabric vhost."""
    hub = rendered_hub
    assert not hub.rogue.connect(hub.pin, cert=hub.agent_cert)
    assert not hub.rogue.connect(hub.pin, user=ENROLL_USER, password=ENROLL_PASSWORD)
    assert hub.rogue.address() is None
    assert not hub.connect_fabric(hub.rogue, user=CLIENT_USER, password=CLIENT_PASSWORD)
    assert hub.rogue.address() is None


def test_enroll_session_reaches_only_the_control_api(rendered_hub: RenderedHub) -> None:
    hub = rendered_hub
    assert hub.connect_fabric(
        hub.enroll,
        user=ENROLL_USER,
        password=ENROLL_PASSWORD,
        extra_routes=(f"{HUB_LAN_ADDR}/32", f"{INET_ADDR}/32"),
    )
    addr = hub.enroll.address()
    assert addr is not None and ip_address(addr) in ip_network(ENROLL_POOL), addr
    assert hub.enroll.pushed_routes() == [f"{HUB_FABRIC_ADDR}/32"]
    reach = {
        "control api": tcp_check(hub.enroll.ns, HUB_FABRIC_ADDR, CONTROL_PORT),
        "hub fabric :22": tcp_check(hub.enroll.ns, HUB_FABRIC_ADDR, 22),
        "hub lan": tcp_check(hub.enroll.ns, HUB_LAN_ADDR, CONTROL_PORT),
        "internet": tcp_check(hub.enroll.ns, INET_ADDR, 80),
    }
    assert reach == {
        "control api": True,
        "hub fabric :22": False,
        "hub lan": False,
        "internet": False,
    }
