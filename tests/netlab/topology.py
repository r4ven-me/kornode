"""Default netlab topology for P1 fabric scenarios.

Address plan:

| Link / network | inet side | node side | Purpose |
| --- | --- | --- | --- |
| 203.0.113.0/28 | 203.0.113.1 | 203.0.113.2 (hub) | hub uplink to internet router |
| 203.0.113.16/28 | 203.0.113.17 | 203.0.113.18 (node2) | node2 uplink to internet router |
| 203.0.113.32/28 | 203.0.113.33 | 203.0.113.34 (node3) | node3 uplink to internet router |
| 203.0.113.48/28 | 203.0.113.49 | 203.0.113.50 (ext) | external ocserv placeholder uplink |
| 10.100.3.0/24 | 10.100.3.1 (node3) | 10.100.3.15 (cli3) | node3 client pool |
| 172.30.1.0/24 | - | 172.30.1.1 (hub) | hub docker/exported LAN |
| 192.168.2.0/24 | - | 192.168.2.1 (node2) | node2 exported LAN |
| 192.168.3.0/24 | - | 192.168.3.1 (node3) | node3 exported LAN |
"""

from __future__ import annotations

import subprocess
import textwrap
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from tests.netlab.helpers import dns_query, tcp_check
from tests.netlab.lab import Lab, Namespace

INET_HTTP_ADDR = "203.0.113.1"
INET_HUB_ADDR = "203.0.113.1"
HUB_ADDR = "203.0.113.2"
INET_NODE2_ADDR = "203.0.113.17"
NODE2_ADDR = "203.0.113.18"
INET_NODE3_ADDR = "203.0.113.33"
NODE3_ADDR = "203.0.113.34"
INET_EXT_ADDR = "203.0.113.49"
EXT_ADDR = "203.0.113.50"

NODE3_CLIENT_GATEWAY = "10.100.3.1"
CLI3_ADDR = "10.100.3.15"

HUB_LAN_ADDR = "172.30.1.1"
NODE2_LAN_ADDR = "192.168.2.1"
NODE3_LAN_ADDR = "192.168.3.1"

HTTP_PORT = 80
HUB_STUB_PORT = 9090
NODE_STUB_PORT = 9100
DNS_NAME_ECHO = "echo.test"
DNS_NAME_MONITORING = "monitoring.kornode.internal"


@dataclass
class Topology:
    lab: Lab
    inet: Namespace
    hub: Namespace
    node2: Namespace
    node3: Namespace
    cli3: Namespace
    ext: Namespace
    stub_processes: list[subprocess.Popen[bytes]] = field(default_factory=list)
    _stopped: bool = False

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        for process in self.stub_processes:
            if process.poll() is None:
                process.terminate()
        for process in self.stub_processes:
            if process.poll() is not None:
                continue
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def build_default_topology(lab: Lab) -> Topology:
    inet = lab.add_namespace("inet")
    hub = lab.add_namespace("hub")
    node2 = lab.add_namespace("node2")
    node3 = lab.add_namespace("node3")
    cli3 = lab.add_namespace("cli3")
    ext = lab.add_namespace("ext")
    topology = Topology(
        lab=lab,
        inet=inet,
        hub=hub,
        node2=node2,
        node3=node3,
        cli3=cli3,
        ext=ext,
    )

    try:
        _wire_inet_spoke(lab, inet, hub, f"{INET_HUB_ADDR}/28", f"{HUB_ADDR}/28")
        _wire_inet_spoke(lab, inet, node2, f"{INET_NODE2_ADDR}/28", f"{NODE2_ADDR}/28")
        _wire_inet_spoke(lab, inet, node3, f"{INET_NODE3_ADDR}/28", f"{NODE3_ADDR}/28")
        _wire_inet_spoke(lab, inet, ext, f"{INET_EXT_ADDR}/28", f"{EXT_ADDR}/28")
        lab.add_veth(
            node3,
            cli3,
            addr_a=f"{NODE3_CLIENT_GATEWAY}/24",
            addr_b=f"{CLI3_ADDR}/24",
        )

        _enable_ip_forward(inet)
        _enable_ip_forward(node3)
        cli3.run(["ip", "route", "add", "default", "via", NODE3_CLIENT_GATEWAY])
        _add_inet_return_routes(inet)
        _add_dummy_lan(hub, "hub-lan0", f"{HUB_LAN_ADDR}/24")
        _add_dummy_lan(node2, "node2-lan0", f"{NODE2_LAN_ADDR}/24")
        _add_dummy_lan(node3, "node3-lan0", f"{NODE3_LAN_ADDR}/24")

        topology.stub_processes.extend(
            [
                _start_http_echo(inet, INET_HTTP_ADDR, HTTP_PORT),
                _start_dns_stub(inet),
                _start_http_echo(hub, HUB_LAN_ADDR, HUB_STUB_PORT),
                _start_http_echo(node2, NODE2_LAN_ADDR, NODE_STUB_PORT),
                _start_http_echo(node3, NODE3_LAN_ADDR, NODE_STUB_PORT),
            ]
        )
        _wait_for_tcp(cli3, INET_HTTP_ADDR, HTTP_PORT)
        _wait_for_tcp(node3, HUB_LAN_ADDR, HUB_STUB_PORT)
        _wait_for_tcp(hub, NODE2_LAN_ADDR, NODE_STUB_PORT)
        _wait_for_tcp(hub, NODE3_LAN_ADDR, NODE_STUB_PORT)
        _wait_for_dns(node3, DNS_NAME_MONITORING, INET_HTTP_ADDR, HUB_LAN_ADDR)
    except BaseException:
        topology.stop()
        raise

    return topology


def _wire_inet_spoke(
    lab: Lab,
    inet: Namespace,
    spoke: Namespace,
    inet_addr: str,
    spoke_addr: str,
) -> None:
    lab.add_veth(inet, spoke, addr_a=inet_addr, addr_b=spoke_addr)
    spoke.run(["ip", "route", "add", "default", "via", inet_addr.split("/", maxsplit=1)[0]])


def _enable_ip_forward(ns: Namespace) -> None:
    ns.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])


def _add_inet_return_routes(inet: Namespace) -> None:
    inet.run(["ip", "route", "add", "10.100.3.0/24", "via", NODE3_ADDR])
    inet.run(["ip", "route", "add", "172.30.1.0/24", "via", HUB_ADDR])
    inet.run(["ip", "route", "add", "192.168.2.0/24", "via", NODE2_ADDR])
    inet.run(["ip", "route", "add", "192.168.3.0/24", "via", NODE3_ADDR])


def _add_dummy_lan(ns: Namespace, name: str, cidr: str) -> None:
    ns.run(["ip", "link", "add", name, "type", "dummy"])
    ns.run(["ip", "addr", "add", cidr, "dev", name])
    ns.run(["ip", "link", "set", name, "up"])


def _start_http_echo(ns: Namespace, bind: str, port: int) -> subprocess.Popen[bytes]:
    code = (
        textwrap.dedent(
            """
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = f"echo from {self.client_address[0]}\\n".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                return

        ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
        """
        )
        .replace("BIND", repr(bind))
        .replace("PORT", repr(port))
    )
    return _popen_in_namespace(ns, ["python3", "-c", code])


def _start_dns_stub(ns: Namespace) -> subprocess.Popen[bytes]:
    code = textwrap.dedent(
        """
        import ipaddress
        import socket
        import struct

        ANSWERS = {
            "echo.test": "203.0.113.1",
            "monitoring.kornode.internal": "172.30.1.1",
        }

        def parse_name(data, offset):
            labels = []
            while offset < len(data):
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                labels.append(data[offset:offset + length].decode("ascii").lower())
                offset += length
            return ".".join(labels), offset

        def handle_query(data):
            if len(data) < 12:
                return b""
            query_id, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
            if qdcount != 1:
                return struct.pack("!HHHHHH", query_id, 0x8183, qdcount, 0, 0, 0) + data[12:]
            name, offset = parse_name(data, 12)
            question = data[12:offset + 4]
            qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
            answer = ANSWERS.get(name.rstrip("."))
            is_a_query = qtype == 1 and qclass == 1
            if answer is None or not is_a_query:
                return struct.pack("!HHHHHH", query_id, 0x8183, 1, 0, 0, 0) + question
            response = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + question
            response += b"\\xc0\\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
            response += ipaddress.IPv4Address(answer).packed
            return response

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("203.0.113.1", 53))
        while True:
            data, client = sock.recvfrom(512)
            response = handle_query(data)
            if response:
                sock.sendto(response, client)
        """
    )
    return _popen_in_namespace(ns, ["python3", "-c", code])


def _popen_in_namespace(ns: Namespace, argv: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - explicit argv, no shell
        ["ip", "netns", "exec", ns.full_name, *argv],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _wait_for_tcp(ns: Namespace, host: str, port: int, *, timeout: float = 5.0) -> None:
    _wait_until(lambda: tcp_check(ns, host, port, timeout=1.0), f"TCP {host}:{port}", timeout)


def _wait_for_dns(
    ns: Namespace,
    name: str,
    server: str,
    expected: str,
    *,
    timeout: float = 5.0,
) -> None:
    _wait_until(
        lambda: dns_query(ns, name, server, timeout=1.0) == expected,
        f"DNS {name} via {server}",
        timeout,
    )


def _wait_until(check: Callable[[], bool], description: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {description}")
