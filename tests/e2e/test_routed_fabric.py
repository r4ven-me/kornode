"""Unimplemented P4 expectations are explicit blockers, never fabricated success.

The P3 cache/upgrade probes exercise fabric/upstream connectivity, not client
throughput, no-NAT routed prefixes or wg-easy access/exit runtime.
"""

import secrets
import time

import pytest
from tests.e2e.fleet import Cluster, wait_for
from tests.e2e.inventory import E2EError

pytestmark = pytest.mark.e2e

BLOCKED = {
    "NL-07": "covered by the netlab suppress-rule test (D-80)",
    "NL-08": "covered by netlab tunnel-bounce leak tests and the E2E-07 fail-closed checks (D-80)",
    "E2E-06-clients": "an upgrade restarts the agent's ocserv: client continuity is a re-login "
    "and needs its own contract (D-80)",
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


SOURCE_CLIENT = "10.8.3.20"


@pytest.mark.e2e_case("routed")
def test_nl_06_source_prefix_is_exported_and_reachable_in_both_directions_without_nat(
    cluster: Cluster,
) -> None:
    """A client behind a source of agent-b (a docker network standing in for the wg-easy
    interface): its subnet is exported into the fabric, it reaches the hub, and the hub
    and agent-a reach it, all with real addresses (no NAT inside the fabric)."""
    # The source network of agent-b is 10.8.<node id>.0/24 with node id 3 (second enrolled agent).
    assert cluster.call("agent-b", "fabric_address")["address"].endswith(".3"), (
        "agent-b is not node 3"
    )
    interface = cluster.call("agent-b", "source_iface")["interface"]
    before = {role: cluster.status(role)["applied_version"] for role in ("agent-a", "agent-b")}
    cluster.call("hub", "source_add", interface=interface)
    for role in ("agent-a", "agent-b"):

        def applied(role: str = role) -> bool:
            return bool(cluster.status(role)["applied_version"] > before[role])

        wait_for(applied, 60, f"{role} did not apply the bundle with the source")
    cluster.call("agent-b", "client_route", routes=["10.99.0.0/24"])
    agent_a = cluster.call("agent-a", "fabric_address")["address"]

    # Source client -> hub: forwarded by agent-b as class `source`, no NAT.
    assert cluster.tcp_peer("hub", "agent-b", HUB_FABRIC_ADDRESS, client=True) == SOURCE_CLIENT
    # Hub -> source client: the exported prefix is routed through agent-b's session.
    assert (
        cluster.tcp_peer("agent-b", "hub", SOURCE_CLIENT, listener_client=True)
        == HUB_FABRIC_ADDRESS
    )
    # agent-a -> source client: the prefix reached its bundle (host traffic, fabric address).
    assert (
        cluster.tcp_peer("agent-b", "agent-a", SOURCE_CLIENT, source=agent_a, listener_client=True)
        == agent_a
    )


@pytest.mark.e2e_case("routed")
def test_e2e_07_client_of_agent_a_leaves_through_agent_b_and_fails_closed_when_it_is_gone(
    cluster: Cluster,
) -> None:
    """Exit via another node (D-69). A VPN client of agent-a (role access) has the policy
    `clients -> any via exit:3`: its internet traffic crosses the fabric, the hub steers it
    into agent-b's session and agent-b (role exit) masquerades it. With agent-b gone the
    traffic is never sent out of agent-a or the hub: it gets nowhere."""
    inventory = cluster.fleet.inventory
    agent_a, agent_b = inventory.host("agent-a").address, inventory.host("agent-b").address
    ext = inventory.host("ext").address
    assert cluster.call("agent-b", "fabric_address")["address"].endswith(".3"), "agent-b is not 3"
    password = secrets.token_hex(12)
    before = {role: cluster.status(role)["applied_version"] for role in ("agent-a", "agent-b")}
    cluster.call("hub", "exit_role")
    access = cluster.call(
        "hub", "access_setup", name="agent-a", host=agent_a, port=ACCESS_PORT,
        user="alice", password=password,
    )  # fmt: skip
    pin = access["certificate"]["pin"]
    cluster.call("hub", "access_policy", via="exit:3")
    for role in ("agent-a", "agent-b"):

        def applied(role: str = role) -> bool:
            return bool(cluster.status(role)["applied_version"] > before[role])

        wait_for(applied, 60, f"{role} did not apply its bundle")

    def login() -> None:
        def attempt() -> bool:
            try:
                # Full tunnel: the client's own namespace, the VPN server stays reachable
                # through the original gateway (as openconnect's own script does).
                cluster.call(
                    "agent-b", "access_client", host=agent_a, port=ACCESS_PORT, pin=pin,
                    user="alice", password=password, routes=[], full=True,
                )  # fmt: skip
            except E2EError:
                return False
            return True

        try:
            wait_for(attempt, 90, "VPN login to the access server of agent-a failed")
        except E2EError as exc:
            diag = {role: cluster.call(role, "access_diag") for role in ("agent-a", "agent-b")}
            raise E2EError(f"{exc}: {diag}") from None

    try:
        login()
        # Out through agent-b: ext, the "internet", sees agent-b's address. (Neither the hub's
        # address, the tunnel's carrier that no policy touches, nor agent-a's, the VPN server
        # the client reaches around the tunnel, can be the target. The client container shares
        # agent-b's VM, so the proof that this goes through the tunnel is the next check.)
        assert cluster.tcp_peer("ext", "agent-b", ext, client=True) == agent_b
        # Inside the fabric nothing changed: no NAT, the client keeps its own address.
        peer = cluster.tcp_peer("hub", "agent-b", HUB_FABRIC_ADDRESS, client=True)
        assert peer.startswith("10.100.2.")

        cluster.call("agent-b", "stop")
        time.sleep(15)  # the hub notices the session going away
        assert cluster.tcp_unreachable("ext", "agent-b", ext, client=True), (
            "traffic reached the internet while the exit node was down"
        )

        cluster.call("agent-b", "restart")
        wait_for(lambda: cluster.ping("agent-b") == 204, 120, "agent-b did not reconnect")
        assert cluster.tcp_peer("ext", "agent-b", ext, client=True) == agent_b
    finally:
        cluster.call("agent-b", "access_client_stop")


HUB_SOURCE_CLIENT = "10.8.1.20"


@pytest.mark.e2e_case("routed")
def test_e2e_07_hub_source_leaves_through_agent_b_and_fails_closed_when_it_is_gone(
    cluster: Cluster,
) -> None:
    """Spec E2E-07, full-tunnel half: a source attached to the hub (a docker network standing
    in for wg-easy) has the hub rule `source -> any via exit:3`. Its internet traffic crosses
    the fabric and agent-b (role exit) masquerades it; the hub's own uplink never carries it,
    and with agent-b gone it gets nowhere."""
    inventory = cluster.fleet.inventory
    agent_b, ext = inventory.host("agent-b").address, inventory.host("ext").address
    assert cluster.call("agent-b", "fabric_address")["address"].endswith(".3"), "agent-b is not 3"
    before = {role: cluster.status(role)["applied_version"] for role in ("agent-b",)}
    cluster.call("hub", "exit_role")
    interface = cluster.call("hub", "source_iface")["interface"]
    cluster.call("hub", "hub_source_add", interface=interface)
    cluster.call("hub", "hub_source_policy", interface=interface)
    wait_for(
        lambda: cluster.status("agent-b")["applied_version"] > before["agent-b"],
        60,
        "agent-b did not apply the bundle with the exit role and the hub source prefix",
    )
    cluster.call("hub", "client_route", routes=[f"{ext}/32"])

    # Out through agent-b: ext sees agent-b's address, not the hub's and not the source's.
    wait_for(
        lambda: _peer_or_none(cluster, "ext", "hub", ext) == agent_b,
        60,
        "hub source traffic did not leave through agent-b",
    )

    cluster.call("agent-b", "stop")
    time.sleep(15)  # the hub notices the session going away
    try:
        assert cluster.tcp_unreachable("ext", "hub", ext, client=True), (
            "hub source traffic reached the internet while the exit node was down"
        )
    finally:
        cluster.call("agent-b", "restart")
    wait_for(lambda: cluster.ping("agent-b") == 204, 120, "agent-b did not reconnect")
    wait_for(
        lambda: _peer_or_none(cluster, "ext", "hub", ext) == agent_b,
        60,
        "hub source traffic did not recover through agent-b",
    )


def _peer_or_none(cluster: Cluster, listener: str, connector: str, host: str) -> str | None:
    try:
        return cluster.tcp_peer(listener, connector, host, client=True)
    except E2EError:
        return None


@pytest.mark.e2e_case("routed")
def test_e2e_07_domain_exit_of_a_client_leaves_through_agent_b_and_fails_closed(
    cluster: Cluster,
) -> None:
    """Spec E2E-07, domain half (D-79). The client of agent-a has `clients -> {domains: [x]}
    via exit:3`, x being a name in the fabric zone that points at ext, the "internet". Agent-a
    resolves x itself and reports the address; the hub marks the transit traffic by source
    and destination, agent-b masquerades it. With agent-b gone nothing leaves."""
    inventory = cluster.fleet.inventory
    agent_a, agent_b = inventory.host("agent-a").address, inventory.host("agent-b").address
    ext = inventory.host("ext").address
    assert cluster.call("agent-b", "fabric_address")["address"].endswith(".3"), "agent-b is not 3"
    password = secrets.token_hex(12)
    cluster.call("hub", "dns_record", name="webdest", type="A", value=ext)
    before = {role: cluster.status(role)["applied_version"] for role in ("agent-a", "agent-b")}
    cluster.call("hub", "exit_role")
    access = cluster.call(
        "hub", "access_setup", name="agent-a", host=agent_a, port=ACCESS_PORT,
        user="alice", password=password,
    )  # fmt: skip
    pin = access["certificate"]["pin"]
    cluster.call("hub", "access_policy", via="exit:3", domain="webdest.kornode.internal")
    for role in ("agent-a", "agent-b"):

        def applied(role: str = role) -> bool:
            return bool(cluster.status(role)["applied_version"] > before[role])

        wait_for(applied, 60, f"{role} did not apply its bundle")

    def login() -> None:
        def attempt() -> bool:
            try:
                cluster.call(
                    "agent-b", "access_client", host=agent_a, port=ACCESS_PORT, pin=pin,
                    user="alice", password=password, routes=[], full=True,
                )  # fmt: skip
            except E2EError:
                return False
            return True

        try:
            wait_for(attempt, 90, "VPN login to the access server of agent-a failed")
        except E2EError as exc:
            diag = {role: cluster.call(role, "access_diag") for role in ("agent-a", "agent-b")}
            raise E2EError(f"{exc}: {diag}") from None

    try:
        login()
        # The agent resolves the name, reports the address, the hub matches it: ext sees agent-b.
        try:
            wait_for(
                lambda: _peer_or_none(cluster, "ext", "agent-b", ext) == agent_b,
                120,
                "domain exit traffic did not leave through agent-b",
            )
        except E2EError as exc:
            dumps = {role: cluster.call(role, "net_dump") for role in ("hub", "agent-a")}
            dumps["resolved"] = cluster.call("agent-a", "resolved_sets")
            dumps["dns"] = cluster.call(
                "agent-a", "dns_resolve", name="webdest.kornode.internal", server=HUB_RESOLVER
            )
            raise E2EError(f"{exc}: {dumps}") from None
        cluster.call("agent-b", "stop")
        time.sleep(15)
        assert cluster.tcp_unreachable("ext", "agent-b", ext, client=True), (
            "traffic reached the internet while the exit node was down"
        )
    finally:
        cluster.call("agent-b", "access_client_stop")
        cluster.call("agent-b", "restart")


@pytest.mark.e2e_case("routed")
def test_nl_13_forwarding_access_client_keeps_the_internet_while_the_hub_is_down(
    cluster: Cluster,
) -> None:
    """NL-13, forwarding half: a VPN client of agent-a (role access, policy `clients -> any via
    local`) keeps reaching the "internet" (ext) with the hub stopped, and after agent-a itself
    restarts (boot from the cached bundle, hub still down) a new login works again."""
    inventory = cluster.fleet.inventory
    agent_a, ext = inventory.host("agent-a").address, inventory.host("ext").address
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

    def login() -> None:
        def attempt() -> bool:
            try:
                cluster.call(
                    "agent-b", "access_client", host=agent_a, port=ACCESS_PORT, pin=pin,
                    user="alice", password=password, routes=[f"{ext}/32"],
                )  # fmt: skip
            except E2EError:
                return False
            return True

        try:
            wait_for(attempt, 90, "VPN login to the access server of agent-a failed")
        except E2EError as exc:
            diag = {role: cluster.call(role, "access_diag") for role in ("agent-a", "agent-b")}
            raise E2EError(f"{exc}: {diag}") from None

    try:
        login()
        assert cluster.tcp_peer("ext", "agent-b", ext, client=True) == agent_a
        cluster.call("hub", "stop")
        try:
            wait_for(lambda: cluster.ping("agent-a") == 0, 20, "hub stop did not interrupt control")
            # The session was established before the outage and keeps forwarding.
            assert cluster.tcp_peer("ext", "agent-b", ext, client=True) == agent_a
            cluster.call("agent-b", "access_client_stop")
            before_restart = cluster.status("agent-a")["applied_version"]
            cluster.call("agent-a", "restart")
            wait_for(
                lambda: cluster.status("agent-a")["applied_version"] == before_restart,
                45,
                "agent-a did not boot from the cached bundle without the hub",
            )
            login()
            assert cluster.tcp_peer("ext", "agent-b", ext, client=True) == agent_a
        finally:
            cluster.call("agent-b", "access_client_stop")
            cluster.call("hub", "restart")
        wait_for(
            lambda: cluster.ping("agent-a") == 204, 120, "agent did not reconnect after hub outage"
        )
    finally:
        cluster.call("agent-b", "access_client_stop")


@pytest.mark.e2e_case("routed")
def test_fabric_recovers_after_a_60_second_hub_outage_without_operator_action(
    cluster: Cluster,
) -> None:
    """Phase 4 "done when": after the fabric channel is cut for 60 s, the hub reaches the
    agents again by their real fabric addresses, with nobody touching anything."""
    cluster.call("hub", "stop")
    try:
        wait_for(lambda: cluster.ping("agent-a") == 0, 20, "hub stop did not interrupt control")
        time.sleep(60)
    finally:
        cluster.call("hub", "restart")
    for role in ("agent-a", "agent-b"):
        wait_for(
            lambda role=role: cluster.ping(role) == 204,  # type: ignore[misc]
            120,
            f"{role} did not reconnect after the 60 s outage",
        )
    for role in ("agent-a", "agent-b"):
        address = cluster.call(role, "fabric_address")["address"]
        assert cluster.tcp_peer(role, "hub", address) == HUB_FABRIC_ADDRESS


@pytest.mark.e2e_case("routed")
def test_nl_05_awg_client_leaves_through_upstream_office_and_fails_closed_when_it_is_gone(
    cluster: Cluster,
) -> None:
    """NL-05: a real wg-easy (AmneziaWG) is the source of agent-a (same network namespace as
    the node, NAT hooks off). Its client reaches the "internet" (a listener on the agent-b VM)
    through `upstream:office` (the ext VM masquerades it); with ext gone nothing arrives,
    neither from ext nor from agent-a's own uplink."""
    inventory = cluster.fleet.inventory
    agent_a, agent_b = inventory.host("agent-a").address, inventory.host("agent-b").address
    ext = inventory.host("ext").address
    cluster.configure_upstream()
    before = cluster.status("agent-a")["applied_version"]
    config = cluster.call("agent-a", "awg_server")["config"]
    cluster.call("hub", "awg_policy")
    wait_for(
        lambda: cluster.status("agent-a")["applied_version"] > before,
        60,
        "agent-a did not apply the bundle with the wg-easy source",
    )
    try:
        cluster.call(
            "agent-b", "awg_client", config=config, endpoint_host=agent_a, routes=[f"{agent_b}/32"]
        )
        del config

        def through_office() -> str | None:
            try:
                return cluster.tcp_peer("agent-b", "agent-b", agent_b, awg=True, seconds=30)
            except E2EError:
                return None

        wait_for(
            lambda: through_office() == ext,
            150,
            "the AmneziaWG client did not leave through upstream:office",
        )

        cluster.call("ext", "stop")
        time.sleep(15)  # the upstream tunnel notices the server going away
        try:
            assert cluster.tcp_unreachable("agent-b", "agent-b", agent_b, awg=True), (
                "AmneziaWG client traffic arrived while the upstream was down"
            )
        finally:
            cluster.call("ext", "restart")
    finally:
        cluster.call("agent-b", "awg_client_stop")
