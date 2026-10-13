from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.netlab.helpers import http_get, tcp_check
from tests.netlab.kornode_nodes import (
    UPSTREAM_INTERFACE,
    HubServerHandle,
    UpstreamHandle,
    connect_node_upstream,
    korctl,
    start_hub_server,
)
from tests.netlab.lab import Namespace
from tests.netlab.topology import (
    CLI3_ADDR,
    HTTP_PORT,
    HUB_ADDR,
    HUB_LAN_ADDR,
    HUB_STUB_PORT,
    INET_HTTP_ADDR,
    NODE3_LAN_ADDR,
    Topology,
)


@pytest.fixture
def node_tmp() -> Iterator[Path]:
    # Not pytest's tmp_path: /tmp/pytest-of-root is 0700, and ocserv workers
    # drop privileges, so they could not reach the sec-mod socket that
    # kornode places in generated_dir.
    path = Path(tempfile.mkdtemp(prefix="kornode-netlab-"))
    path.chmod(0o755)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def hub_server(topology: Topology, node_tmp: Path) -> Iterator[HubServerHandle]:
    handle = start_hub_server(topology.lab, topology, node_tmp)
    try:
        yield handle
    finally:
        handle.stop()


@pytest.fixture
def connected_node3(
    topology: Topology,
    node_tmp: Path,
    hub_server: HubServerHandle,
) -> Iterator[UpstreamHandle]:
    handle = connect_node_upstream(
        topology.lab,
        topology.node3,
        node_tmp,
        server_addr=hub_server.server_addr,
        server_cert_pin=hub_server.server_cert_pin,
        host_policy="full",
        client_policy="off",
    )
    try:
        yield handle
    finally:
        handle.stop()


@pytest.mark.netlab
def test_carrier_exclusion_keeps_full_host_tunnel_alive(
    topology: Topology,
    connected_node3: UpstreamHandle,
) -> None:
    body = http_get(topology.node3, f"http://{HUB_LAN_ADDR}:{HUB_STUB_PORT}/", timeout=3.0)
    rules = topology.node3.run(["ip", "rule"]).stdout
    route = topology.node3.run(
        ["ip", "route", "get", HUB_ADDR, "mark", connected_node3.fwmark],
        check=False,
    ).stdout

    assert body.startswith("echo from 10.250.0.")
    assert f"95:\tfrom all to {HUB_ADDR} lookup main" in rules
    assert UPSTREAM_INTERFACE not in route


@pytest.mark.netlab
def test_kill_switch_keeps_unreachable_default_and_blocks_uplink_leak(
    topology: Topology,
    connected_node3: UpstreamHandle,
) -> None:
    uplink = _default_route_device(topology.node3)
    traffic = _start_connect_loop(topology.node3.full_name, INET_HTTP_ADDR, HTTP_PORT)
    try:
        topology.node3.run(["ip", "link", "delete", UPSTREAM_INTERFACE])
        packets = _capture_packets(topology.node3.full_name, uplink, f"host {INET_HTTP_ADDR}")
    finally:
        _terminate(traffic)

    routes = topology.node3.run(["ip", "route", "show", "table", connected_node3.table]).stdout

    # The reconciler installs it via netlink (`proto static`).
    assert re.search(r"unreachable default .*metric 4096", routes)
    assert not tcp_check(topology.node3, INET_HTTP_ADDR, HTTP_PORT, timeout=1.0)
    assert packets == 0


@pytest.mark.netlab
def test_kernel_after_connect_matches_the_plan(
    topology: Topology,
    connected_node3: UpstreamHandle,
) -> None:
    # connect() converges through the reconciler (carrier written, pass,
    # dial, pass): nothing is left for the next pass to change.
    plan = json.loads(
        korctl(
            topology.node3, connected_node3.config_path, "net", "plan", "--json"
        ).stdout
    )

    assert [op["text"] for op in plan["ops"]] == []
    exit_ = next(item for item in plan["exits"] if item["name"] == "upstream:hub")
    assert exit_["up"] is True
    assert exit_["mark"] == connected_node3.fwmark
    assert str(exit_["table"]) == connected_node3.table


@pytest.mark.netlab
def test_suppress_rule_keeps_connected_routes_ahead_of_policy_table(
    topology: Topology,
    connected_node3: UpstreamHandle,
) -> None:
    lan_body = http_get(
        topology.node3,
        f"http://{NODE3_LAN_ADDR}:9100/",
        timeout=2.0,
    )
    cli3_ping = topology.node3.run(["ping", "-c", "1", "-W", "1", CLI3_ADDR], check=False)
    inet_body = http_get(topology.node3, f"http://{INET_HTTP_ADDR}:{HTTP_PORT}/", timeout=3.0)

    assert lan_body == f"echo from {NODE3_LAN_ADDR}\n"
    assert cli3_ping.ok
    # Tunneled: the hub masquerades VPN clients toward the internet, so inet
    # sees the hub's address. A leak would show node3's own uplink address.
    assert inet_body == f"echo from {HUB_ADDR}\n"


@pytest.mark.netlab
def test_sysctls_are_applied_for_global_and_tunnel_interface(
    topology: Topology,
    connected_node3: UpstreamHandle,
) -> None:
    rp_filter = _sysctl(topology.node3, f"net.ipv4.conf.{connected_node3.interface}.rp_filter")
    ip_forward = _sysctl(topology.node3, "net.ipv4.ip_forward")
    src_valid_mark = _sysctl(topology.node3, "net.ipv4.conf.all.src_valid_mark")

    assert rp_filter == "2"
    assert ip_forward == "1"
    assert src_valid_mark == "1"


@pytest.mark.netlab
def test_mss_clamp_rule_covers_host_traffic_leaving_the_tunnel(
    topology: Topology,
    connected_node3: UpstreamHandle,
) -> None:
    # Host traffic leaves through the inet kornode table's postrouting chain
    # (the host kill-switch lives there too); the forward-chain clamp for
    # client traffic is covered by the golden ruleset tests.
    table = topology.node3.run(["nft", "list", "table", "inet", "kornode"]).stdout
    postrouting = table.split("chain postrouting {", 1)[1].split("\n\t}", 1)[0]

    assert "tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu" in postrouting
    assert f"meta mark & 0xffffff00 == {connected_node3.fwmark}" in postrouting


def _default_route_device(ns: Namespace) -> str:
    result = ns.run(["ip", "route", "show", "default"])
    tokens = result.stdout.split()
    return tokens[tokens.index("dev") + 1]


def _sysctl(ns: Namespace, key: str) -> str:
    return ns.run(["sysctl", "-n", key]).stdout.strip()


def _start_connect_loop(full_namespace: str, host: str, port: int) -> subprocess.Popen[bytes]:
    code = textwrap.dedent(
        """
        import socket
        import time

        host = HOST
        port = PORT
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                socket.create_connection((host, port), timeout=0.2).close()
            except OSError:
                pass
            time.sleep(0.05)
        """
    ).replace("HOST", repr(host)).replace("PORT", repr(port))
    return subprocess.Popen(  # noqa: S603 - explicit argv, no shell
        ["ip", "netns", "exec", full_namespace, "python3", "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _capture_packets(full_namespace: str, iface: str, bpf_filter: str) -> int:
    process = subprocess.Popen(  # noqa: S603 - explicit argv, no shell
        [
            "ip",
            "netns",
            "exec",
            full_namespace,
            "tcpdump",
            "-i",
            iface,
            "-n",
            "-q",
            "-l",
            "-c",
            "100000",
            *bpf_filter.split(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        stdout, _ = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            stdout, _ = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, _ = process.communicate()
    return sum(1 for line in stdout.splitlines() if line and not line.startswith("tcpdump:"))


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
