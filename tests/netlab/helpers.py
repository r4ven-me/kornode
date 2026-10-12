from __future__ import annotations

import json
import textwrap

from tests.netlab.lab import Namespace

from kornode.services.command import CommandResult


class NetlabCommandError(RuntimeError):
    def __init__(self, message: str, result: CommandResult) -> None:
        super().__init__(message)
        self.result = result


def tcp_check(ns: Namespace, host: str, port: int, *, timeout: float = 2.0) -> bool:
    code = (
        "import socket, sys\n"
        f"try:\n"
        f"    socket.create_connection(({host!r}, {port}), timeout={timeout!r}).close()\n"
        "except (ConnectionRefusedError, OSError, TimeoutError):\n"
        "    print('TCP_CHECK_UNREACHABLE')\n"
        "    sys.exit(1)\n"
    )
    result = ns.run(["python3", "-c", code], timeout=_ceil_timeout(timeout), check=False)
    if result.returncode == 1 and result.stdout.strip() == "TCP_CHECK_UNREACHABLE":
        return False
    _raise_for_failure(result, "tcp check failed")
    return result.ok


def http_get(ns: Namespace, url: str, *, timeout: float = 2.0) -> str:
    code = (
        "import urllib.request\n"
        f"with urllib.request.urlopen({url!r}, timeout={timeout!r}) as response:\n"
        "    print(response.read().decode(), end='')\n"
    )
    result = ns.run(["python3", "-c", code], timeout=_ceil_timeout(timeout), check=False)
    _raise_for_failure(result, "HTTP GET failed")
    return result.stdout


def dns_query(ns: Namespace, name: str, server: str, *, timeout: float = 2.0) -> str | None:
    code = _dns_query_code()
    result = ns.run(
        ["python3", "-c", code, json.dumps(name), json.dumps(server), str(timeout)],
        timeout=_ceil_timeout(timeout),
        check=False,
    )
    _raise_for_exec_failure(result, "DNS query")
    if result.returncode == 2:
        return None
    _raise_for_failure(result, "DNS query failed")
    answer = result.stdout.strip()
    return answer or None


def capture(ns: Namespace, iface: str, bpf_filter: str, *, duration: float = 2.0) -> int:
    result = ns.run(
        [
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
        timeout=_ceil_timeout(duration),
        check=False,
        graceful_timeout=0.2,
    )
    _raise_for_exec_failure(result, "packet capture")
    if result.returncode not in {0, 124}:
        raise NetlabCommandError("packet capture failed", result)
    return sum(1 for line in result.stdout.splitlines() if line and not line.startswith("tcpdump:"))


def netem(
    ns: Namespace,
    iface: str,
    *,
    loss: float | None = None,
    delay_ms: float | None = None,
) -> None:
    argv = ["tc", "qdisc", "add", "dev", iface, "root", "netem"]
    if loss is not None:
        argv.extend(["loss", f"{loss}%"])
    if delay_ms is not None:
        argv.extend(["delay", f"{delay_ms}ms"])
    result = ns.run(argv, check=False)
    _raise_for_failure(result, "netem setup failed")


def _dns_query_code() -> str:
    return textwrap.dedent(
        """
        import ipaddress
        import json
        import random
        import socket
        import struct
        import sys

        name = json.loads(sys.argv[1])
        server = json.loads(sys.argv[2])
        timeout = float(sys.argv[3])

        def labels(value):
            encoded = bytearray()
            for label in value.rstrip(".").split("."):
                part = label.encode("ascii")
                encoded.append(len(part))
                encoded.extend(part)
            encoded.append(0)
            return bytes(encoded)

        query_id = random.randrange(0, 65536)
        packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        packet += labels(name) + struct.pack("!HH", 1, 1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(512)
        except socket.timeout:
            sys.exit(2)

        if len(data) < 12:
            sys.exit(3)
        response_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if response_id != query_id:
            sys.exit(3)
        rcode = flags & 0x000F
        if rcode == 3:
            sys.exit(2)
        if rcode != 0:
            sys.exit(3)

        offset = 12
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 5

        def skip_name(position):
            while position < len(data):
                length = data[position]
                if length & 0xC0 == 0xC0:
                    return position + 2
                if length == 0:
                    return position + 1
                position += length + 1
            return position

        for _ in range(ancount):
            offset = skip_name(offset)
            if offset + 10 > len(data):
                sys.exit(3)
            rtype, rclass, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            if rtype == 1 and rclass == 1 and rdlength == 4:
                print(str(ipaddress.IPv4Address(rdata)))
                sys.exit(0)
        sys.exit(2)
        """
    ).strip()


def _ceil_timeout(timeout: float) -> int:
    return max(1, int(timeout) + 1)


def _raise_for_exec_failure(result: CommandResult, operation: str) -> None:
    if result.returncode == 127:
        raise NetlabCommandError(f"{operation} could not execute", result)


def _raise_for_failure(result: CommandResult, message: str) -> None:
    _raise_for_exec_failure(result, message)
    if not result.ok:
        raise NetlabCommandError(message, result)
