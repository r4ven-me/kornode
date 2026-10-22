"""NL-17 / NL-18 (spec 09): a source of the hub leaves through node 2.

Namespaces: `src` (client of the hub source `wgusers`) -> `hub` -> `node2` -> `inet`;
the hub has its own uplink to `inet` as well, so a leak is visible there. Both kernels
are converged with the real `kornode.net` compiler and writer (facts are built by hand:
no ocserv here, the veth between hub and node2 stands for the session).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from tests.netlab.lab import Lab, Namespace

pytestmark = pytest.mark.netlab

DRIVER = Path(__file__).with_name("exit_set_driver.py")
ROOT = Path(__file__).resolve().parents[2]
LISTED_HOST = "198.51.100.7"
OTHER_HOST = "192.0.2.5"
HUB_UPLINK = "203.0.113.1"
NODE2_UPLINK = "198.18.0.2"
NODE2_FABRIC = "10.99.0.2"

SERVER = textwrap.dedent(
    """
    import socket, sys, threading
    log = open(sys.argv[1], "a", buffering=1)
    def serve(addr, port):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port)); s.listen(16)
        while True:
            c, peer = s.accept()
            log.write(f"{addr} {peer[0]}\\n")
            c.sendall(peer[0].encode()); c.close()
    for spec in sys.argv[2:]:
        addr, port = spec.split(":")
        threading.Thread(target=serve, args=(addr, int(port)), daemon=True).start()
    threading.Event().wait()
    """
)


@dataclass
class ExitLab:
    src: Namespace
    hub: Namespace
    node2: Namespace
    inet: Namespace
    log: Path

    def drive(self, ns: Namespace, role: str, scenario: str, *extra: str) -> None:
        env = {**os.environ, "PYTHONPATH": f"{ROOT / 'backend'}:{ROOT}"}
        out = ns.run([sys.executable, str(DRIVER), role, scenario, *extra], env=env, timeout=60)
        assert json.loads(out.stdout)["after"] == [], out.stdout

    def fetch(
        self, ns: Namespace, host: str, *, port: int = 8080, timeout: float = 3.0
    ) -> str | None:
        code = (
            "import socket,sys\n"
            "try:\n"
            f"    s=socket.create_connection(({host!r},{port}),timeout={timeout});"
            "print(s.recv(64).decode())\n"
            "except OSError as e:\n"
            "    print('ERR', e.errno)\n"
        )
        out = ns.run(["python3", "-c", code], timeout=timeout + 5, check=False).stdout.strip()
        return None if out.startswith("ERR") else out

    def reached_from(self, peer: str, dst: str) -> bool:
        lines = self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []
        return f"{dst} {peer}" in lines


def _wire(
    lab: Lab, a: Namespace, b: Namespace, name_a: str, name_b: str, ip_a: str, ip_b: str
) -> None:
    lab.add_veth(a, b)
    iface_a, iface_b = lab.veths[-1]
    for ns, old, new, ip in ((a, iface_a, name_a, ip_a), (b, iface_b, name_b, ip_b)):
        ns.run(["ip", "link", "set", old, "down"])
        ns.run(["ip", "link", "set", old, "name", new])
        ns.run(["ip", "addr", "add", ip, "dev", new])
        ns.run(["ip", "link", "set", new, "up"])


@pytest.fixture
def exit_lab(lab: Lab, tmp_path: Path) -> Iterator[ExitLab]:
    src, hub, node2, inet = (lab.add_namespace(x) for x in ("src", "hub", "node2", "inet"))
    _wire(lab, src, hub, "eth0", "wg0", "10.8.1.2/24", "10.8.1.1/24")
    # The fabric session is a layer-3 tunnel like ocserv's tun device: a veth would need ARP
    # answers for every internet address behind it.
    _wire(lab, hub, node2, "c0", "c0", "172.31.0.1/30", "172.31.0.2/30")
    for ns, name, local, remote, address in (
        (hub, "vpns1", "172.31.0.1", "172.31.0.2", "10.99.0.1/24"),
        (node2, "oc-hub0", "172.31.0.2", "172.31.0.1", f"{NODE2_FABRIC}/24"),
    ):
        ns.run(["ip", "tunnel", "add", name, "mode", "ipip", "local", local, "remote", remote])
        ns.run(["ip", "addr", "add", address, "dev", name])
        ns.run(["ip", "link", "set", name, "up"])
    _wire(lab, hub, inet, "eth0", "h0", f"{HUB_UPLINK}/24", "203.0.113.2/24")
    _wire(lab, node2, inet, "eth0", "n0", f"{NODE2_UPLINK}/24", "198.18.0.1/24")
    src.run(["ip", "route", "add", "default", "via", "10.8.1.1"])
    hub.run(["ip", "route", "add", "default", "via", "203.0.113.2"])
    node2.run(["ip", "route", "add", "default", "via", "198.18.0.1"])
    # The internet answers each uplink: the listed range and the rest live on `inet`.
    for host in (LISTED_HOST, OTHER_HOST):
        inet.run(["ip", "addr", "add", f"{host}/32", "dev", "lo"])
    inet.run(["sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0"])
    log = tmp_path / "inet.log"
    server = subprocess.Popen(  # noqa: S603 - explicit argv
        [
            "ip", "netns", "exec", inet.full_name, sys.executable, "-c", SERVER,
            str(log), f"{LISTED_HOST}:8080", f"{OTHER_HOST}:8080",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )  # fmt: skip
    handle = ExitLab(src, hub, node2, inet, log)
    time.sleep(0.5)
    try:
        yield handle
    finally:
        server.terminate()
        server.wait(timeout=10)


def test_nl17_listed_destinations_leave_through_node2_the_rest_through_the_hub(
    exit_lab: ExitLab,
) -> None:
    exit_lab.drive(exit_lab.node2, "node2", "set")
    exit_lab.drive(exit_lab.hub, "hub", "set")

    assert exit_lab.fetch(exit_lab.src, LISTED_HOST) == NODE2_UPLINK
    assert exit_lab.fetch(exit_lab.src, OTHER_HOST) == HUB_UPLINK


def test_nl17_node2_offline_listed_destinations_fail_closed_never_on_the_hub_uplink(
    exit_lab: ExitLab,
) -> None:
    exit_lab.drive(exit_lab.node2, "node2", "set")
    exit_lab.hub.run(["ip", "link", "set", "vpns1", "down"])
    exit_lab.drive(exit_lab.hub, "hub", "set", "--offline")

    started = time.monotonic()
    assert exit_lab.fetch(exit_lab.src, LISTED_HOST) is None
    assert time.monotonic() - started < 3, "ICMP unreachable expected, not a timeout"
    assert not exit_lab.reached_from(HUB_UPLINK, LISTED_HOST)
    assert exit_lab.fetch(exit_lab.src, OTHER_HOST) == HUB_UPLINK  # unlisted stay local


def test_nl18_full_tunnel_exits_node2_and_the_hub_reaches_node2_by_its_fabric_address(
    exit_lab: ExitLab,
) -> None:
    exit_lab.drive(exit_lab.node2, "node2", "full")
    exit_lab.drive(exit_lab.hub, "hub", "full")

    assert exit_lab.fetch(exit_lab.src, LISTED_HOST) == NODE2_UPLINK
    assert exit_lab.fetch(exit_lab.src, OTHER_HOST) == NODE2_UPLINK
    assert not exit_lab.reached_from(HUB_UPLINK, LISTED_HOST)
    assert not exit_lab.reached_from(HUB_UPLINK, OTHER_HOST)
    # The "scrape": the hub talks to the agent by its real fabric address (no NAT in the fabric).
    agent = subprocess.Popen(  # noqa: S603 - explicit argv
        [
            "ip", "netns", "exec", exit_lab.node2.full_name, sys.executable, "-c", SERVER,
            str(exit_lab.log.with_name("node2.log")), f"{NODE2_FABRIC}:9100",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        time.sleep(0.5)
        assert exit_lab.fetch(exit_lab.hub, NODE2_FABRIC, port=9100) == "10.99.0.1"
    finally:
        agent.terminate()
        agent.wait(timeout=10)
