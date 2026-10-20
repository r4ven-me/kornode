"""Unimplemented P4 expectations are explicit blockers, never fabricated success.

The P3 cache/upgrade probes exercise fabric/upstream connectivity, not client
throughput, no-NAT routed prefixes or wg-easy access/exit runtime.
"""

import secrets

import pytest
from tests.e2e.fleet import Cluster, wait_for
from tests.e2e.inventory import E2EError

pytestmark = pytest.mark.e2e

BLOCKED = {
    "E2E-07": "P4 access/exit, source routing and domain resolution are not implemented",
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
HUB_RESOLVER = "10.100.1.1"
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


def _service_address(fabric_address: str) -> str:
    # 10.99.0.<id> -> 10.100.<id>.1 (default fabric templates, spec 01).
    return f"10.100.{fabric_address.rsplit('.', 1)[1]}.1"


@pytest.mark.e2e_case("routed")
def test_nl_02_agent_reaches_hub_monitoring_by_fabric_name(cluster: Cluster) -> None:
    """The agent resolves its own zone locally and the rest of the fabric zone
    through the hub resolver over the fabric; TCP to the resolved address works
    and keeps the agent's fabric address (no NAT)."""
    source = cluster.call("agent-a", "fabric_address")["address"]
    resolver = _service_address(source)
    node = f"node{source.rsplit('.', 1)[1]}.kornode.internal"
    cluster.call("hub", "dns_record", name="monitoring", type="A", value=HUB_FABRIC_ADDRESS)

    def resolves(name: str, expected: str) -> bool:
        answer = cluster.call("agent-a", "dns_resolve", name=name, server=resolver)
        return bool(answer["address"] == expected)

    wait_for(lambda: resolves(node, resolver), 60, f"agent-a resolver does not answer {node}")
    try:
        wait_for(
            lambda: resolves("monitoring.kornode.internal", HUB_FABRIC_ADDRESS),
            60,
            "monitoring.kornode.internal is not resolved through the hub",
        )
    except E2EError as exc:
        name = "monitoring.kornode.internal"
        probes = {
            "agent->agent": cluster.call("agent-a", "dns_resolve", name=name, server=resolver),
            "agent->hub": cluster.call("agent-a", "dns_resolve", name=name, server=HUB_RESOLVER),
            "hub->hub": cluster.call("hub", "dns_resolve", name=name, server=HUB_RESOLVER),
            "hub-node": cluster.call("hub", "dns_resolve", name=node, server=HUB_RESOLVER),
        }
        raise E2EError(f"{exc}: {probes}; agent-a {cluster.call('agent-a', 'net_dump')}") from None

    peer = cluster.tcp_peer("hub", "agent-a", HUB_FABRIC_ADDRESS, source=source)

    assert peer == source


ACCESS_PORT = 8443  # published by the harness on agent-a (worker.ACCESS_PORT)


@pytest.mark.e2e_case("routed")
def test_nl_03_access_client_of_an_agent_reaches_the_fabric_and_leaves_through_the_node(
    cluster: Cluster,
) -> None:
    """A VPN client of agent-a (role access): reaches the hub across the fabric
    without NAT, leaves through the node with NAT, and a *new* login works while
    the hub is down (users travel in the bundle as hashes). A throwaway openconnect
    client runs in its own container on the agent-b VM (outside the node's policy)
    and routes only the hub addresses through the tunnel. MSS clamping is covered by the
    golden/netlab suites, not here."""
    inventory = cluster.fleet.inventory
    agent_a, hub_lan = inventory.host("agent-a").address, inventory.host("hub").address
    node_id = cluster.call("agent-a", "fabric_address")["address"].rsplit(".", 1)[1]
    password = secrets.token_hex(12)
    before = cluster.status("agent-a")["applied_version"]
    access = cluster.call(
        "hub", "access_setup", name="agent-a", host=agent_a, port=ACCESS_PORT,
        user="alice", password=password,
    )  # fmt: skip
    pin = access["certificate"]["pin"]
    cluster.call("hub", "access_policy")
    wait_for(
        lambda: cluster.status("agent-a")["applied_version"] > before,
        60,
        "agent-a did not apply the bundle with the access listener",
    )

    # Only these destinations go through the tunnel of the throwaway client.
    routes = [f"{HUB_FABRIC_ADDRESS}/32", f"{hub_lan}/32"]

    def connect() -> dict[str, str] | None:
        try:
            return dict(
                cluster.call(
                    "agent-b", "access_client", host=agent_a, port=ACCESS_PORT, pin=pin,
                    user="alice", password=password, routes=routes,
                )
            )  # fmt: skip
        except E2EError:
            return None

    def login() -> str:
        result: dict[str, str] = {}

        def attempt() -> bool:
            found = connect()
            if found is not None:
                result.update(found)
            return found is not None

        try:
            wait_for(attempt, 90, "VPN login to the access server of agent-a failed")
        except E2EError as exc:
            diag = {role: cluster.call(role, "access_diag") for role in ("agent-a", "agent-b")}
            raise E2EError(f"{exc}: {diag}") from None
        return result["address"]

    try:
        client = login()
        assert client.startswith(f"10.100.{node_id}."), client
        # Across the fabric: the hub sees the client's own address (no NAT).
        assert cluster.tcp_peer("hub", "agent-b", HUB_FABRIC_ADDRESS, client=True) == client
        # Outside the fabric: leaves through agent-a with its address (masquerade).
        assert cluster.tcp_peer("hub", "agent-b", hub_lan, client=True) == agent_a
        cluster.call("agent-b", "access_client_stop")

        cluster.call("hub", "stop")
        try:
            wait_for(lambda: cluster.ping("agent-a") == 0, 20, "hub stop did not interrupt control")
            assert login().startswith(f"10.100.{node_id}."), "no login while the hub is down"
        finally:
            cluster.call("agent-b", "access_client_stop")
            cluster.call("hub", "restart")
        wait_for(
            lambda: cluster.ping("agent-a") == 204, 120, "agent did not reconnect after hub outage"
        )
    finally:
        cluster.call("agent-b", "access_client_stop")
