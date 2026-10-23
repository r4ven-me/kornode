from __future__ import annotations

import pytest
from tests.netlab.helpers import dns_query, http_get
from tests.netlab.topology import (
    CLI3_ADDR,
    DNS_NAME_MONITORING,
    HTTP_PORT,
    HUB_ADDR,
    HUB_LAN_ADDR,
    INET_HTTP_ADDR,
    NODE3_LAN_ADDR,
    NODE_STUB_PORT,
    Topology,
)


@pytest.mark.netlab
def test_cli3_reaches_inet_http_echo_without_nat(topology: Topology) -> None:
    body = http_get(topology.cli3, f"http://{INET_HTTP_ADDR}:{HTTP_PORT}/", timeout=2.0)

    assert body == f"echo from {CLI3_ADDR}\n"


@pytest.mark.netlab
def test_hub_reaches_node3_stub_across_inet_without_nat(topology: Topology) -> None:
    body = http_get(topology.hub, f"http://{NODE3_LAN_ADDR}:{NODE_STUB_PORT}/", timeout=2.0)

    assert body == f"echo from {HUB_ADDR}\n"


@pytest.mark.netlab
def test_node3_resolves_monitoring_name_via_inet_dns(topology: Topology) -> None:
    answer = dns_query(topology.node3, DNS_NAME_MONITORING, INET_HTTP_ADDR, timeout=2.0)

    assert answer == HUB_LAN_ADDR


@pytest.mark.netlab
def test_unknown_name_returns_none(topology: Topology) -> None:
    answer = dns_query(topology.node3, "missing.kornode.lan", INET_HTTP_ADDR, timeout=2.0)

    assert answer is None
