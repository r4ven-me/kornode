"""Unimplemented P4 expectations are explicit blockers, never fabricated success.

The P3 cache/upgrade probes exercise fabric/upstream connectivity, not client
throughput, no-NAT routed prefixes or wg-easy access/exit runtime.
"""

import pytest
from tests.e2e.fleet import Cluster, wait_for

pytestmark = pytest.mark.e2e

BLOCKED = {
    "E2E-07": "P4 access/exit, source routing and domain resolution are not implemented",
    "NL-02": "P4 fabric internal DNS",
    "NL-03": "P4 agent access server and client forwarding/MSS",
    "NL-05": "P4 attached wg-easy source and fail-closed packet capture",
    "NL-06": "P4 source-prefix export to hub monitoring",
    "NL-07": "P4 local delivery with the new egress model",
    "NL-08": "VM client leak capture requires the P4 client data path",
    "NL-09": "VM client loss/MTU transfer requires the P4 client data path",
    "NL-13-forwarding": "cache/upstream connectivity covered; client continuity requires P4",
    "E2E-06-clients": "fabric probes covered; upgrade with access-client traffic requires P4",
}


@pytest.mark.parametrize("scenario,reason", BLOCKED.items(), ids=BLOCKED)
def test_pending_runtime_contract(scenario: str, reason: str) -> None:
    pytest.skip(f"{scenario} blocked: {reason}")


HUB_FABRIC_ADDRESS = "10.99.0.1"
AGENT_B_LAN = "192.168.30.0/24"
AGENT_B_LAN_HOST = "192.168.30.1"


@pytest.mark.e2e_case("routed")
def test_nl_01_hub_reaches_an_agent_over_the_fabric_without_nat(cluster: Cluster) -> None:
    address = cluster.call("agent-a", "fabric_address")["address"]

    peer = cluster.tcp_peer("agent-a", "hub", address)

    assert peer == HUB_FABRIC_ADDRESS


@pytest.mark.e2e_case("routed")
def test_nl_04_agent_reaches_a_service_in_another_agents_lan_via_the_hub_without_nat(
    cluster: Cluster,
) -> None:
    cluster.call("agent-b", "lan_setup", cidr=f"{AGENT_B_LAN_HOST}/24")
    before = cluster.status("agent-a")["applied_version"]
    cluster.call("hub", "export_prefix", name="agent-b", cidr=AGENT_B_LAN)
    # A bundle lists the other nodes' prefixes, so only agent-a's changes.
    wait_for(
        lambda: cluster.status("agent-a")["applied_version"] > before,
        60,
        "agent-a did not apply the bundle with the exported prefix",
    )
    source = cluster.call("agent-a", "fabric_address")["address"]

    # Host traffic of an agent uses its fabric address as the source (strict RPF on the hub).
    peer = cluster.tcp_peer("agent-b", "agent-a", AGENT_B_LAN_HOST, source=source)

    assert peer == source
