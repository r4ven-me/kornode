"""One small dataplane topology per example, not an examples × VM-scenarios matrix.

The original egress/sets and real HubNetInputs are used unchanged. IPIP stands
in for upstream transports; synthetic resolver output exercises the resolved-set
input, NOT DNS or certificate/authentication acceptance for those examples.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from tests.netlab.example_driver import load
from tests.netlab.lab import Lab
from tests.netlab.test_examples_kernel import DRIVER, EXAMPLES, ROOT
from tests.netlab.test_p4_exit_set import SERVER, ExitLab, _wire

pytestmark = pytest.mark.netlab

# source class, destination, profile name (None means the local uplink).
PROBES: dict[str, list[tuple[str, str, str | None]]] = {
    "config.minimal.yaml": [("clients", "192.0.2.5", None)],
    "config.client.yaml": [
        ("host", "10.60.0.7", "office"),
        ("host", "198.51.100.9", "office"),
        ("host", "192.0.2.5", None),
    ],
    "config.middle-server.yaml": [
        ("clients", "192.168.25.7", "private-main"),
        ("clients", "198.51.100.9", "private-main"),
        ("clients", "192.0.2.5", None),
        ("host", "192.168.25.7", "private-main"),
    ],
    "config.full.yaml": [
        ("host", "10.30.0.7", "site-b-wireguard"),
        ("clients", "192.168.25.7", "private-main"),
        ("clients", "198.51.100.9", "private-main"),
        ("clients", "192.0.2.5", None),
    ],
}


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_example_forwards_selected_and_unselected_traffic_and_fails_closed(
    lab: Lab,
    path: Path,
    tmp_path: Path,
) -> None:
    assert {p.name for p in EXAMPLES} == set(PROBES), "new example needs forwarding expectations"
    config = load(path)
    hub, client, inet = (lab.add_namespace(name) for name in ("hub", "client", "inet"))
    pool = ipaddress.IPv4Network(config.server.ipv4_network)
    gateway, address = str(pool[1]), str(pool[2])
    _wire(lab, client, hub, "eth0", "vpns0", f"{address}/24", f"{gateway}/24")
    _wire(lab, hub, inet, "uplink0", "h0", "203.0.113.1/24", "203.0.113.2/24")
    client.run(["ip", "route", "add", "default", "via", gateway])
    hub.run(["ip", "route", "add", "default", "via", "203.0.113.2"])
    inet.run(["sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0"])
    tunnels: dict[str, tuple[str, str]] = {}
    if config.upstream.enabled:
        for index, profile in enumerate(config.upstream.profiles, 1):
            interface = config.upstream.profile_interface(profile)
            local, remote = f"172.31.{index}.1", f"172.31.{index}.2"
            _wire(lab, hub, inet, f"c{index}", f"p{index}", f"{local}/30", f"{remote}/30")
            for ns, name, src, dst, ip in (
                (hub, interface, local, remote, f"172.20.{index}.1/30"),
                (inet, f"tun{index}", remote, local, f"172.20.{index}.2/30"),
            ):
                ns.run(["ip", "tunnel", "add", name, "mode", "ipip", "local", src, "remote", dst])
                ns.run(["ip", "addr", "add", ip, "dev", name])
                ns.run(["ip", "link", "set", name, "up"])
            tunnels[profile.name] = (interface, f"172.20.{index}.1")
    resolved = tmp_path / "generated" / "resolved"
    resolved.mkdir(parents=True)
    for name in config.sets:
        (resolved / f"{name}.txt").write_text("198.51.100.9\n")
    env = {**os.environ, "PYTHONPATH": f"{ROOT / 'backend'}:{ROOT}"}

    def converge() -> None:
        out = hub.run(
            [sys.executable, str(DRIVER), str(path), "--state-dir", str(tmp_path)],
            env=env,
            timeout=60,
        )
        assert json.loads(out.stdout)["after"] == [], out.stdout

    probes = PROBES[path.name]
    for host in sorted({host for _, host, _ in probes}):
        inet.run(["ip", "addr", "add", f"{host}/32", "dev", "lo"])
    server = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            inet.full_name,
            sys.executable,
            "-c",
            SERVER,
            str(tmp_path / "peers.log"),
            *[f"{host}:8080" for host in sorted({p[1] for p in probes})],
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    handle = ExitLab(client, hub, inet, inet, tmp_path / "peers.log")
    bridge_server: subprocess.Popen[bytes] | None = None
    bridge = None
    try:
        if path.name == "config.middle-server.yaml":
            # NL-07's exact forwarded path: this connected Docker-like subnet
            # also matches the example's private -> upstream rule. Main-table
            # local delivery must win. D-26 NATs clients toward connected LANs
            # so services without a route back to the VPN pool can answer.
            bridge = lab.add_namespace("docker")
            _wire(lab, hub, bridge, "docker0", "eth0", "10.20.99.1/24", "10.20.99.2/24")
            bridge.run(["ip", "route", "add", "default", "via", "10.20.99.1"])
            bridge_server = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    bridge.full_name,
                    sys.executable,
                    "-c",
                    SERVER,
                    str(tmp_path / "bridge.log"),
                    "10.20.99.2:8080",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        time.sleep(0.5)
        assert server.poll() is None
        converge()
        for source, host, profile_name in probes:
            ns = client if source == "clients" else hub
            expected = tunnels[profile_name][1] if profile_name else "203.0.113.1"
            assert handle.fetch(ns, host) == expected, (path.name, source, host, profile_name)
        if bridge is not None:
            assert handle.fetch(client, "10.20.99.2") == "10.20.99.1", (
                            "NL-07 must deliver locally using D-26 connected-LAN NAT"
                        )
        for interface, _ in tunnels.values():
            hub.run(["ip", "link", "set", interface, "down"])
        converge()
        for source, host, profile_name in probes:
            ns = client if source == "clients" else hub
            if profile_name:
                started = time.monotonic()
                assert handle.fetch(ns, host) is None
                # D-28: forwarded clients get ICMP reject; host packets are
                # dropped in postrouting, where nft cannot issue a reject.
                if source == "clients":
                    assert time.monotonic() - started < 3, (
                        "forwarded clients must receive unreachable, not a silent timeout"
                    )
                assert not handle.reached_from("203.0.113.1", host), (
                    "upstream traffic leaked locally"
                )
            else:
                assert handle.fetch(ns, host) == "203.0.113.1", "unlisted traffic must remain local"
        if bridge is not None:
            assert handle.fetch(client, "10.20.99.2") == "10.20.99.1", (
                            "NL-07 local delivery must survive upstream loss"
                        )
    finally:
        if bridge_server is not None:
            bridge_server.terminate()
            bridge_server.wait(timeout=10)
        server.terminate()
        server.wait(timeout=10)
