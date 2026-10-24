"""D-78: the node resolves the domain-based sets of its policy itself."""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from kornode.net.lists import UrlListCache
from kornode.net.model import EgressPolicy, InlineDest
from kornode_agent.resolver import (
    MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    TYPE_A,
    TYPE_AAAA,
    AgentSetResolver,
    parse_answers,
    system_nameservers,
    udp_lookup,
)

POLICY = EgressPolicy.model_validate(
    {
        "sets": {
            "web": {"domains": ["example.org"], "route_urls": ["https://lists.example/r.txt"]},
            "feed": {"domain_urls": ["https://lists.example/d.txt"]},
            "static": {"routes": ["10.0.0.0/8"]},
        },
        "egress": [
            {"from": ["clients"], "to": {"set": "web"}, "via": "local"},
            {"from": ["clients"], "to": {"domains": ["inline.example"]}, "via": "local"},
        ],
    }
)


def response(query: bytes, answers: list[tuple[int, bytes, int]], rcode: int = 0) -> bytes:
    ident = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    out = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1, len(answers), 0, 0) + question
    for rdtype, rdata, ttl in answers:
        out += b"\xc0\x0c" + struct.pack("!HHIH", rdtype, 1, ttl, len(rdata)) + rdata
    return out


@pytest.fixture
def dns_server() -> Iterator[tuple[int, dict[str, list[tuple[int, bytes, int]]]]]:
    table: dict[str, list[tuple[int, bytes, int]]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                data, peer = sock.recvfrom(512)
            except OSError:
                continue
            labels, offset = [], 12
            while data[offset]:
                labels.append(data[offset + 1 : offset + 1 + data[offset]].decode())
                offset += 1 + data[offset]
            kind = struct.unpack("!H", data[offset + 1 : offset + 3])[0]
            name = ".".join(labels)
            if name not in table:
                sock.sendto(response(data, [], rcode=3), peer)
                continue
            sock.sendto(response(data, [a for a in table[name] if a[0] == kind]), peer)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield sock.getsockname()[1], table
    stop.set()
    thread.join()
    sock.close()


def test_udp_lookup_returns_a_and_aaaa_with_the_lowest_ttl(dns_server) -> None:  # type: ignore[no-untyped-def]
    port, table = dns_server
    v6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    table["example.org"] = [
        (TYPE_A, socket.inet_aton("203.0.113.5"), 300),
        (TYPE_A, socket.inet_aton("203.0.113.6"), 60),
        (TYPE_AAAA, v6, 120),
    ]
    assert udp_lookup("example.org", ["127.0.0.1"], TYPE_A, port=port) == (
        ["203.0.113.5", "203.0.113.6"],
        60,
    )
    assert udp_lookup("example.org", ["127.0.0.1"], TYPE_AAAA, port=port) == (["2001:db8::1"], 120)


def test_nxdomain_timeout_and_garbage_give_nothing(dns_server) -> None:  # type: ignore[no-untyped-def]
    port, _ = dns_server
    assert udp_lookup("missing.example", ["127.0.0.1"], TYPE_A, port=port) == ([], None)
    assert udp_lookup("example.org", ["127.0.0.1"], TYPE_A, timeout=0.2, port=1) == ([], None)
    assert parse_answers(b"short", 1, TYPE_A) == ([], None)
    assert udp_lookup("bad..name", ["127.0.0.1"], TYPE_A, port=port) == ([], None)


def test_system_nameservers_reads_resolv_conf(tmp_path: Path) -> None:
    path = tmp_path / "resolv.conf"
    path.write_text("# c\nsearch x\nnameserver 10.100.1.1\nnameserver 2001:db8::53\n")
    assert system_nameservers(path) == ["10.100.1.1", "2001:db8::53"]
    assert system_nameservers(tmp_path / "none") == []


class Lookup:
    def __init__(self, table: dict[str, tuple[list[str], list[str], int | None]]) -> None:
        self.table = table
        self.servers: list[Sequence[str]] = []

    def __call__(
        self, domain: str, servers: Sequence[str], rdtype: int
    ) -> tuple[list[str], int | None]:
        self.servers.append(servers)
        v4, v6, ttl = self.table.get(domain, ([], [], None))
        return (v4 if rdtype == TYPE_A else v6), ttl


def make(tmp_path: Path, lookup: Lookup, policy: EgressPolicy | None = POLICY) -> AgentSetResolver:
    texts = {
        "https://lists.example/r.txt": "192.0.2.0/24\n",
        "https://lists.example/d.txt": "feed.example\n",
    }
    return AgentSetResolver(
        tmp_path,
        nameservers=lambda: ["10.100.1.1"],
        policy=lambda: policy,
        lookup=lookup,
        lists=UrlListCache(tmp_path / "lists", fetch=lambda url: texts[url]),
    )


def test_refresh_records_every_dynamic_set_by_the_name_facts_read(tmp_path: Path) -> None:
    lookup = Lookup(
        {
            "example.org": (["203.0.113.5"], ["2001:db8::1"], 120),
            "feed.example": (["198.51.100.7"], [], 90),
            "inline.example": (["203.0.113.9"], [], 600),
        }
    )
    resolver = make(tmp_path, lookup)

    assert resolver.refresh() == 90
    assert resolver.read() == {
        "web": frozenset({"203.0.113.5", "2001:db8::1", "192.0.2.0/24"}),
        "feed": frozenset({"198.51.100.7"}),
        InlineDest(domains=("inline.example",)).resolved_key(): frozenset({"203.0.113.9"}),
    }
    assert all(servers == ["10.100.1.1"] for servers in lookup.servers)  # via the hub resolver


def test_unresolvable_set_is_recorded_empty_and_stale_sets_are_removed(tmp_path: Path) -> None:
    resolver = make(tmp_path, Lookup({"example.org": (["203.0.113.5"], [], 5000)}))
    # `feed` has domains but resolved to nothing: retry soon, not after an hour (D-79).
    assert resolver.refresh() == MIN_INTERVAL_SECONDS
    assert resolver.read()["feed"] == frozenset()
    resolver.policy = lambda: None  # no active bundle
    resolver.refresh()
    assert resolver.read() == {}


def test_resolved_sets_keep_the_long_interval(tmp_path: Path) -> None:
    lookup = Lookup(
        {
            "example.org": (["203.0.113.5"], [], 5000),
            "feed.example": (["198.51.100.7"], [], 5000),
            "inline.example": (["203.0.113.9"], [], 5000),
        }
    )

    assert make(tmp_path, lookup).refresh() == MAX_INTERVAL_SECONDS


def test_interval_is_clamped_to_the_floor(tmp_path: Path) -> None:
    assert (
        make(tmp_path, Lookup({"example.org": (["203.0.113.5"], [], 1)})).refresh()
        == MIN_INTERVAL_SECONDS
    )


def test_run_wakes_the_reconciler_only_when_addresses_change(tmp_path: Path) -> None:
    resolver = make(tmp_path, Lookup({"example.org": (["203.0.113.5"], [], 30)}))
    stop, woken = threading.Event(), threading.Event()
    thread = threading.Thread(target=resolver.run, args=(stop, woken.set), daemon=True)
    thread.start()
    assert woken.wait(5)
    woken.clear()
    resolver.changed.set()  # a new bundle: resolved again, nothing differs -> no wake
    threading.Event().wait(1.5)
    assert not woken.is_set()
    stop.set()
    thread.join(5)
    assert not thread.is_alive()


def test_udp_lookup_queries_from_the_pinned_source_address() -> None:
    """The hub drops interlink queries from any address but the node's interlink address (D-47,
    D-66), so the resolver must pin it; 127.0.0.2 stands in for that address."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(2)
    port = server.getsockname()[1]
    peers: list[str] = []

    def serve() -> None:
        data, peer = server.recvfrom(512)
        peers.append(peer[0])
        server.sendto(response(data, [(TYPE_A, socket.inet_aton("203.0.113.5"), 60)]), peer)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        found = udp_lookup("example.org", ["127.0.0.1"], TYPE_A, port=port, source="127.0.0.2")
    finally:
        thread.join()
        server.close()

    assert found == (["203.0.113.5"], 60)
    assert peers == ["127.0.0.2"]
