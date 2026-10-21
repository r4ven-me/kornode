"""Resolve the domain-based sets of the active bundle's policy (D-78).

The bundle carries only the policy; the node pre-resolves its domain sets itself and
records the addresses per set in `<root>/resolved/<set>.txt` -- the same layout the hub
uses (D-25), read back into NodeFacts.resolved by AgentNetInputs. Lookups go to the hub
resolver over the fabric (the one the node's own dnsmasq forwards to), so the answers
match what the node's clients get; without it the node falls back to /etc/resolv.conf.
Stdlib only: the agent image carries no DNS library. Until a set is resolved it is empty,
so traffic assigned to it matches nothing (fail closed).
"""

from __future__ import annotations

import ipaddress
import logging
import random
import socket
import struct
import threading
from collections.abc import Callable, Sequence
from pathlib import Path

from kornode.net.lists import (
    DynamicSet,
    UrlListCache,
    atomic_write_lines,
    dynamic_sets,
    normalize_domain,
    normalize_route,
)
from kornode.net.model import EgressPolicy

log = logging.getLogger(__name__)

MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 3600
QUERY_TIMEOUT_SECONDS = 3.0
TYPE_A, TYPE_AAAA = 1, 28

Lookup = Callable[[str, Sequence[str], int], tuple[list[str], int | None]]


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not 0 < len(raw) < 64:
            raise ValueError(f"bad label in {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def _skip_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def parse_answers(data: bytes, query_id: int, rdtype: int) -> tuple[list[str], int | None]:
    """Addresses (and the lowest TTL) of the `rdtype` records in a DNS response."""
    if len(data) < 12:
        return [], None
    ident, flags, questions, answers = struct.unpack("!HHHH", data[:8])
    if ident != query_id or flags & 0x000F:  # not ours / error rcode (NXDOMAIN, SERVFAIL...)
        return [], None
    offset = 12
    for _ in range(questions):
        offset = _skip_name(data, offset) + 4
    found: list[str] = []
    ttl: int | None = None
    for _ in range(answers):
        offset = _skip_name(data, offset)
        kind, _cls, record_ttl, length = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + length]
        offset += length
        if kind != rdtype or length not in (4, 16):
            continue
        found.append(str(ipaddress.ip_address(rdata)))
        ttl = record_ttl if ttl is None else min(ttl, record_ttl)
    return found, ttl


def udp_lookup(
    domain: str,
    nameservers: Sequence[str],
    rdtype: int,
    timeout: float = QUERY_TIMEOUT_SECONDS,
    port: int = 53,
    source: str | None = None,
) -> tuple[list[str], int | None]:
    """One A/AAAA query, tried against each nameserver in turn. `source` pins the local
    address: the hub's strict reverse path drops fabric traffic from any other one (D-47)."""
    query_id = random.SystemRandom().randrange(1 << 16)
    try:
        question = _encode_name(domain) + struct.pack("!HH", rdtype, 1)
    except (ValueError, UnicodeError):
        return [], None
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    for server in nameservers:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                if source and family == socket.AF_INET and ":" not in source:
                    sock.bind((source, 0))
                sock.sendto(packet, (server, port))
                data, _ = sock.recvfrom(4096)
            return parse_answers(data, query_id, rdtype)
        except (OSError, struct.error, IndexError, ValueError) as exc:
            log.warning("dns %s via %s failed: %s", domain, server, exc)
    return [], None


def system_nameservers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [
        fields[1]
        for fields in (line.split() for line in lines)
        if len(fields) >= 2 and fields[0] == "nameserver"
    ]


def hub_nameservers(policy_dns_servers: Sequence[str]) -> list[str]:
    """The hub resolver from the bundle's forward zone, else the system resolvers."""
    return list(policy_dns_servers) or system_nameservers()


class AgentSetResolver:
    def __init__(
        self,
        root: Path,
        *,
        nameservers: Callable[[], Sequence[str]],
        policy: Callable[[], EgressPolicy | None],
        lookup: Lookup | None = None,
        lists: UrlListCache | None = None,
        source: Callable[[], str | None] = lambda: None,
    ) -> None:
        self.directory = root / "resolved"
        self.nameservers = nameservers
        self.policy = policy
        self.source = source
        self.lookup: Lookup = lookup or self._udp
        self.lists = lists or UrlListCache(root / "url-lists")
        self.changed = threading.Event()  # set when the active bundle changes

    def _udp(
        self, domain: str, nameservers: Sequence[str], rdtype: int
    ) -> tuple[list[str], int | None]:
        return udp_lookup(domain, nameservers, rdtype, source=self.source())

    def refresh(self) -> int:
        """Resolve every dynamic set, record the result and return seconds until the next cycle."""
        policy = self.policy()
        targets = dynamic_sets(policy) if policy is not None else {}
        servers = list(self.nameservers())
        min_ttl: int | None = None
        current: dict[str, list[str]] = {}
        incomplete = False
        for name, target in targets.items():
            addresses, ttl = self._resolve(target, servers)
            current[name] = sorted(dict.fromkeys(addresses))
            # A set that has domains but no address yet (resolver or tunnel not reachable at
            # that moment) must not wait out a whole hour: retry on the short interval.
            incomplete = incomplete or (
                bool(target.domains or target.domain_urls) and not addresses
            )
            if ttl is not None:
                min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        self._record(current)
        if incomplete:
            return MIN_INTERVAL_SECONDS
        if min_ttl is None:
            return MAX_INTERVAL_SECONDS
        return max(MIN_INTERVAL_SECONDS, min(min_ttl, MAX_INTERVAL_SECONDS))

    def _resolve(self, target: DynamicSet, servers: list[str]) -> tuple[list[str], int | None]:
        domains = list(target.domains)
        for url in target.domain_urls:
            domains += self.lists.items(url, normalize_domain)
        addresses: list[str] = []
        min_ttl: int | None = None
        for domain in dict.fromkeys(domains):
            for rdtype in (TYPE_A, TYPE_AAAA):
                found, ttl = self.lookup(domain, servers, rdtype)
                addresses += found
                if ttl is not None:
                    min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        for url in target.route_urls:
            addresses += self.lists.items(url, normalize_route)
        return addresses, min_ttl

    def _record(self, current: dict[str, list[str]]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        previous = {path.stem: path for path in self.directory.glob("*.txt")}
        for name, addresses in current.items():
            path = self.directory / f"{name}.txt"
            old = path.read_text(encoding="utf-8").split() if path.exists() else None
            if old != addresses:
                atomic_write_lines(path, addresses)
        for name, path in previous.items():
            if name not in current:
                path.unlink(missing_ok=True)

    def read(self) -> dict[str, frozenset[str]]:
        """Recorded addresses per set (what NodeFacts.resolved is made of)."""
        result: dict[str, frozenset[str]] = {}
        for path in self.directory.glob("*.txt"):
            try:
                result[path.stem] = frozenset(path.read_text(encoding="utf-8").split())
            except OSError:
                continue
        return result

    def run(self, stop: threading.Event, on_change: Callable[[], None]) -> None:
        """Resolve until `stop`; a new bundle restarts the cycle at once."""
        while not stop.is_set():
            before = self.read()
            try:
                interval = self.refresh()
            except Exception:  # noqa: BLE001 - the loop must outlive any one failure
                log.exception("set resolution failed")
                interval = MIN_INTERVAL_SECONDS
            if self.read() != before:
                on_change()
            waited = 0.0
            while waited < interval and not stop.is_set() and not self.changed.is_set():
                self.changed.wait(1.0)  # short slices: shutdown must not wait out a cycle
                waited += 1.0
            self.changed.clear()
