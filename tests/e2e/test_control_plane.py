"""Real VM scenarios. No fixture or network command runs without explicit opt-in."""

from __future__ import annotations

import secrets
import time

import pytest
from tests.e2e.fleet import Cluster, wait_for

pytestmark = pytest.mark.e2e


@pytest.mark.e2e_case("route")
def test_nl_10_running_reconciler_repairs_deleted_route_within_2_seconds(cluster: Cluster) -> None:
    result = cluster.call("agent-a", "repair_route")
    assert result["restored"] and result["seconds"] <= 2
    assert cluster.ping("agent-a") == 204


@pytest.mark.e2e_case("rollback")
def test_nl_11_interlink_cutting_signed_bundle_rolls_back_and_reports(cluster: Cluster) -> None:
    previous = cluster.status("agent-a")["applied_version"]
    started = time.monotonic()
    version = cluster.call("hub", "inject_bundle")["version"]

    def recovered() -> bool:
        status = cluster.call("agent-a", "state")
        last = status.get("last_apply") or {}
        return (
            last.get("version") == version
            and last.get("result") == "rolled_back"
            and status["current"] == previous
            and cluster.ping("agent-a") == 204
        )

    wait_for(
        recovered,
        max(0.01, 70 - (time.monotonic() - started)),
        "interlink-cutting bundle did not roll back within 70 seconds",
    )
    assert time.monotonic() - started <= 70
    wait_for(
        lambda: cluster.call("hub", "rollback_report", version=version)["reported"],
        30,
        "hub did not receive rollback report",
    )


@pytest.mark.e2e_case("tamper")
def test_nl_12_tampered_incoming_bundle_is_rejected_without_advancing_version(
    cluster: Cluster,
) -> None:
    before = cluster.status("agent-a")
    version = cluster.call("hub", "inject_bundle")["version"]
    assert version > before["high_water_version"]
    wait_for(
        lambda: cluster.call("agent-a", "rejected")["rejected"],
        45,
        "agent did not record actual signature rejection",
    )
    after = cluster.status("agent-a")
    assert after["applied_version"] == before["applied_version"]
    assert after["high_water_version"] == before["high_water_version"]
    assert cluster.ping("agent-a") == 204


@pytest.mark.e2e_case("enroll")
def test_e2e_01_fresh_enrollment_within_30_seconds(cluster: Cluster) -> None:
    assert set(cluster.enrollment_seconds) == {"agent-a", "agent-b"}
    assert all(seconds <= 30 for seconds in cluster.enrollment_seconds.values())
    for role in ("agent-a", "agent-b"):
        assert cluster.ping(role) == 204
        assert cluster.status(role)["applied_version"] > 0


@pytest.mark.e2e_case("change")
def test_e2e_02_registry_change_confirmed_within_10_seconds(cluster: Cluster) -> None:
    before = cluster.status("agent-a")["applied_version"]
    version = cluster.changed("agent-a")
    assert version > before


@pytest.mark.e2e_case("blackhole")
def test_e2e_03_60_second_container_uplink_blackhole_recovers(cluster: Cluster) -> None:
    version = cluster.status("agent-b")["applied_version"]
    started = time.monotonic()
    assert cluster.call("agent-b", "fault")["seconds"] == 60
    wait_for(lambda: cluster.ping("agent-b") == 0, 20, "blackhole did not interrupt interlink")
    # The worker arms an independent 60-second watchdog before nft insertion.
    time.sleep(max(0, 61 - (time.monotonic() - started)))
    wait_for(lambda: cluster.ping("agent-b") == 204, 120, "agent failed to recover after blackhole")
    assert cluster.status("agent-b")["applied_version"] >= version


@pytest.mark.e2e_case("revoke")
def test_e2e_04_revoke_cuts_interlink_and_mtls_api_returns_403(cluster: Cluster) -> None:
    # Test-only TCP relay changes reachability, not TLS identity/authentication.
    # It lets an already-disconnected cert holder prove the actual HTTP 403.
    assert cluster.ping("agent-b", relay=True) == 204
    cluster.call("hub", "revoke")
    wait_for(
        lambda: cluster.ping("agent-b", relay=True) == 403,
        30,
        "revoked agent was not denied by the mTLS control API",
    )
    wait_for(lambda: cluster.ping("agent-b") == 0, 30, "revoked interlink session remained usable")


@pytest.mark.e2e_case("restore")
def test_e2e_05_rotating_hub_wipe_restore_preserves_agents(cluster: Cluster) -> None:
    identities = {role: cluster.call(role, "identity") for role in ("agent-a", "agent-b")}
    rotation = cluster.call("hub", "rotate")
    # Wait until both agents have confirmed the announced key before capture.
    for role in identities:
        cluster.changed(role, dpd=30, seconds=30)
    cluster.call("hub", "backup")
    ahead = cluster.changed("agent-a", dpd=35, seconds=30)
    cluster.call("hub", "restore")
    for role in identities:

        def connected(role: str = role) -> bool:
            return cluster.ping(role) == 204

        wait_for(
            connected,
            120,
            "restored hub did not reconnect original agent",
        )
        assert cluster.call(role, "identity") == identities[role]
    wait_for(
        lambda: cluster.status("agent-a")["applied_version"] > ahead,
        150,
        "restored hub failed monotonic high-water recovery",
    )
    after = cluster.call("hub", "status")
    assert after["signing_key_id"] == rotation["signing_key_id"]
    assert after["rotation"]["started_at"] == rotation["rotation"]["started_at"]


@pytest.mark.e2e_case("upgrade")
def test_e2e_06_upgrade_under_interlink_and_client_traffic_gap_at_most_30_seconds(
    cluster: Cluster,
) -> None:
    """One deployment: previous images -> current, same access client reconnects itself.

    The external peer verifies the exit address; the observer also requires the
    client's route to use its VPN device, so direct Docker fallback cannot pass.
    """
    identities = {role: cluster.call(role, "identity") for role in ("agent-a", "agent-b")}
    agent_a = cluster.fleet.inventory.host("agent-a").address
    ext = cluster.fleet.inventory.host("ext").address
    password = secrets.token_hex(12)
    before = cluster.status("agent-a")["applied_version"]
    access = cluster.call(
        "hub", "access_setup", name="agent-a", host=agent_a, port=8443,
        user="alice", password=password,
    )
    cluster.call("hub", "access_policy")
    wait_for(
        lambda: cluster.status("agent-a")["applied_version"] > before,
        60,
        "previous agent did not apply the access-client policy",
    )

    def login() -> bool:
        cluster.call(
            "agent-b", "access_client", host=agent_a, port=8443,
            pin=access["certificate"]["pin"], user="alice", password=password,
            routes=[f"{ext}/32"],
        )
        return True

    try:
        wait_for(login, 90, "previous agent access-client login failed")
        gap = cluster.upgrade()
        assert gap <= 30, "upgrade interrupted interlink or client forwarding for more than 30 s"
        for role in identities:
            assert cluster.call(role, "identity") == identities[role]
    finally:
        cluster.call("agent-b", "access_client_stop")


@pytest.mark.e2e_case("cache")
def test_nl_13_cache_boot_and_upstream_survive_10_minute_hub_outage(cluster: Cluster) -> None:
    cluster.configure_upstream()
    before = cluster.status("agent-a")["applied_version"]
    assert cluster.call("agent-a", "upstream_ping")["reachable"]
    cluster.call("hub", "stop")
    try:
        started = time.monotonic()
        wait_for(lambda: cluster.ping("agent-a") == 0, 20, "hub stop did not interrupt control")
        cluster.call("agent-a", "restart")
        wait_for(
            lambda: cluster.status("agent-a")["applied_version"] == before,
            45,
            "agent did not boot from confirmed cache without hub",
        )
        # The restart recreates the container's network namespace, so the
        # external tunnel is dialed again from the cached bundle, hub still
        # down. Allow that bounded re-establishment, then it must stay healthy.
        wait_for(
            cluster.upstream_healthy,
            60,
            "external upstream did not re-establish from cache without the hub",
        )
        while time.monotonic() - started < 600:
            assert cluster.upstream_healthy(), (
                f"external upstream regressed while hub was down: {cluster.upstream_summary()}"
            )
            assert cluster.call("agent-a", "upstream_ping")["reachable"], (
                "upstream packets failed during hub outage"
            )
            time.sleep(min(5, max(0, 600 - (time.monotonic() - started))))
    finally:
        cluster.call("hub", "restart")
    wait_for(
        lambda: cluster.ping("agent-a") == 204, 120, "agent did not reconnect after hub outage"
    )
