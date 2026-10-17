from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from tests.test_bundle_service import Env

from kornode.services.agent_models import AgentCreate, AgentPatch, ManagementError, PrefixInput
from kornode.services.agents import AgentService


class Enrollment:
    def __init__(self, env: Env) -> None:
        self.env = env
        self.revoked: list[int] = []

    def issue_token(self, node_id: int, **kwargs: Any) -> str:
        return "one-time-token"

    def revoke_node(self, node_id: int) -> dict[str, Any]:
        self.revoked.append(node_id)
        self.env.registry.set_state(node_id, "revoked")
        self.env.registry.set_prefixes(node_id, [])
        return {"node_id": node_id}

    def revoke_token(self, node_id: int) -> int:
        return 0


@pytest.fixture
def world(tmp_path: Path):  # type: ignore[no-untyped-def]
    env = Env(tmp_path)
    enrollment = Enrollment(env)
    clock = [datetime(2026, 10, 16, tzinfo=UTC)]
    service = AgentService(
        env.config,
        bundles=env.service,
        enrollment=enrollment,
        sync=lambda: None,
        clock=lambda: clock[0],
        password_hasher=lambda pw: "$6$test$hash",
    )
    yield env, service, enrollment, clock
    env.registry.conn.close()


def test_create_allocates_id_token_only_in_explicit_response(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    result = service.create(AgentCreate(name="branch"))
    assert result["agent"]["id"] == 2 and result["token"] == "one-time-token"
    assert "token" not in json.dumps(service.list())
    assert service.show("branch")["prefixes"][0]["prefix"] == "10.100.2.0/24"
    assert env.registry.get_node(2).state == "pending"


def test_delete_revokes_before_removal_and_id_is_quarantined(world) -> None:  # type: ignore[no-untyped-def]
    env, service, enrollment, clock = world
    service.create(AgentCreate(name="branch", id=3))
    service.delete("branch")
    assert enrollment.revoked == [3]
    with pytest.raises(ManagementError) as raised:
        service.create(AgentCreate(name="reuse", id=3))
    assert raised.value.status == 409
    clock[0] += timedelta(days=31)
    assert service.create(AgentCreate(name="reuse", id=3))["agent"]["id"] == 3


def test_patch_compiles_transactionally_and_invalid_policy_rolls_back(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(3)
    env.compile(3)
    result = service.update("node3", AgentPatch(description="new", transport={"dpd": 30}))
    assert result["desired_version"] == 2
    with pytest.raises(ManagementError):
        service.set_policy(
            "node3", {"egress": [{"from": ["host"], "to": "any", "via": "upstream:missing"}]}
        )
    assert env.registry.get_node(3).policy == {}
    assert env.registry.get_node(3).desired_version == 2


def test_prefix_overlap_is_conflict_not_committed(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    service.create(AgentCreate(name="a", id=2))
    service.create(AgentCreate(name="b", id=3))
    with pytest.raises(ManagementError) as exc:
        service.add_prefix("a", PrefixInput(prefix="10.100.3.0/24", kind="lan"))
    assert exc.value.error == "address_overlap" and exc.value.details
    assert len(env.registry.list_prefixes(2)) == 1


def test_hub_cannot_be_managed_as_an_agent(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.registry.create_node(id=1, name="hub")
    with pytest.raises(ManagementError):
        service.delete("hub")


def test_dry_run_no_registry_or_enrollment_changes(world) -> None:  # type: ignore[no-untyped-def]
    env, service, enrollment, _ = world
    preview = service.create(AgentCreate(name="branch", dry_run=True))
    assert preview["dry_run"] and env.registry.list_nodes() == []
    service.create(AgentCreate(name="branch"))
    assert service.delete("branch", dry_run=True)["dry_run"]
    assert enrollment.revoked == [] and len(env.registry.list_nodes()) == 1


def test_reports_commands_strict_and_ownership_checked(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(2)
    env.add(3)
    command = service.enqueue(
        "node2", {"type": "explain", "args": {"src": "host", "dst": "1.1.1.1"}}
    )
    with pytest.raises(ManagementError) as exc:
        service.command("node3", command["id"])
    assert exc.value.status == 404
    for payload in ({"type": "shell", "args": {}}, {"type": "restart", "args": {"shell": "x"}}):
        with pytest.raises(ManagementError):
            service.enqueue("node2", payload)
    assert len(env.registry.list_commands(2)) == 1


def test_bundles_redact_sealed_values_and_safe_diff(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(3)
    env.compile(3)
    service.set_upstream(
        "node3",
        "office",
        {
            "server": "vpn.example.org",
            "interface": "oc-office",
            "port": 443,
            "auth_type": "password",
            "username": "agent",
            "password": "hidden-password",
        },
    )
    shown = json.dumps(service.bundle("node3", 2))
    assert "hidden-password" not in shown and "[redacted]" in shown
    assert '"ct"' not in shown
    assert "hidden-password" not in json.dumps(service.bundle_diff("node3", 1, 2))
    assert "hidden-password" not in json.dumps(service.upstreams("node3"))


def test_access_users_are_write_only_and_explicitly_not_deployed(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    service.create(AgentCreate(name="branch", roles=["access"]))
    saved = service.set_user(
        "branch", "alice", {"password": "private-password", "groups": ["staff"]}
    )
    assert saved["runtime_supported"] is False
    assert "private-password" not in json.dumps(saved) and "$6$" not in json.dumps(saved)
    assert service.users("branch")["users"][0]["password_set"]


def test_sync_failure_reports_committed_state_without_leaking_error(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(3)
    env.compile(3)

    def fail():
        raise OSError("private-filesystem-detail")

    service.sync = fail
    with pytest.raises(ManagementError) as exc:
        service.update("node3", AgentPatch(transport={"dpd": 40}))
    assert exc.value.status == 503 and exc.value.details["committed"]
    assert "private-filesystem-detail" not in str(exc.value)
    assert env.registry.get_node(3).desired_version == 2
    assert env.registry.get_node(3).transport["dpd"] == 40


def test_failed_revocation_never_deletes_or_reuses_id(world) -> None:  # type: ignore[no-untyped-def]
    from kornode.services.enrollment import EnrollmentError

    env, service, enrollment, _ = world
    service.create(AgentCreate(name="branch", id=3))

    def fail(node_id):
        env.registry.set_state(node_id, "revoked")
        raise EnrollmentError(500, "internal", "CRL failure")

    enrollment.revoke_node = fail
    with pytest.raises(ManagementError):
        service.delete("branch")
    assert env.registry.get_node(3).state == "revoked"
    with pytest.raises(ManagementError):
        service.create(AgentCreate(name="unsafe", id=3, force_reuse=True))


def test_force_reuse_requires_explicit_flag_and_does_not_bypass_live_ids(world) -> None:  # type: ignore[no-untyped-def]
    _, service, _, _ = world
    service.create(AgentCreate(name="branch", id=3))
    service.delete("branch")
    assert (
        service.create(AgentCreate(name="replacement", id=3, force_reuse=True))["agent"]["id"] == 3
    )
    with pytest.raises(ManagementError):
        service.create(AgentCreate(name="collision", id=3, force_reuse=True))


def test_source_derived_prefixes_follow_policy_without_deleting_manual_prefixes(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    service.create(AgentCreate(name="branch", id=3))
    service.add_prefix("branch", PrefixInput(prefix="192.168.50.0/24", kind="source"))
    service.set_source(
        "branch", "wireless", {"interface": "wg0", "cidr": "10.8.3.0/24", "export": True}
    )
    service.set_policy("branch", {"sources": [], "egress": []})
    assert {p.prefix for p in env.registry.list_prefixes(3)} == {"10.100.3.0/24", "192.168.50.0/24"}
    service.delete_prefix("branch", "192.168.50.0/24")
    assert len(env.registry.list_prefixes(3)) == 1


def test_source_pool_and_interfaces_are_checked_before_enrollment(world) -> None:  # type: ignore[no-untyped-def]
    _, service, _, _ = world
    service.create(AgentCreate(name="branch", id=3))
    with pytest.raises(ManagementError) as exc:
        service.set_source("branch", "wg", {"interface": "wg0", "cidr": "192.168.3.0/24"})
    assert exc.value.error == "source_pool"
    with pytest.raises(ManagementError) as exc:
        service.set_source("branch", "wg", {"interface": "oc-hub0", "cidr": "10.8.3.0/24"})
    assert exc.value.error == "interface_conflict"


def test_fabric_camouflage_encrypted_at_rest_and_sealed_for_agent(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(3)
    service.update("node3", AgentPatch(transport={"camouflage": "transport-secret"}))
    assert "transport-secret" not in json.dumps(env.registry.get_node(3).transport)
    assert "transport-secret" not in json.dumps(service.show("node3"))
    assert (
        env.check(env.registry.latest_bundle(3)).secrets["/tunnels/fabric/camouflage"]
        == "transport-secret"
    )
    service.update("node3", AgentPatch(transport={"camouflage": None}))
    assert env.registry.get_node(3).transport == {}


def test_command_preview_no_queue_and_expired_commands_do_not_block_enqueue(world) -> None:  # type: ignore[no-untyped-def]
    env, service, _, clock = world
    env.add(3)
    preview = service.enqueue("node3", {"type": "restart", "dry_run": True})
    assert preview["dry_run"] and env.registry.list_commands(3) == []
    for _ in range(100):
        env.registry.enqueue_command(3, "restart", ttl_seconds=1, now=clock[0])
    clock[0] += timedelta(seconds=2)
    assert service.enqueue("node3", {"type": "restart"})["state"] == "queued"
    assert len(env.registry.list_commands(3, "expired")) == 100


def test_password_changes_keep_groups_and_disabled_state(world) -> None:  # type: ignore[no-untyped-def]
    _, service, _, _ = world
    service.create(AgentCreate(name="branch", roles=["access"]))
    service.set_user(
        "branch", "alice", {"password": "initial-password", "enabled": False, "groups": ["staff"]}
    )
    service.set_user("branch", "alice", {"password": "changed-password"})
    user = service.users("branch")["users"][0]
    assert user["groups"] == ["staff"] and user["enabled"] is False


def test_artifact_ownership_size_and_metadata_without_base64(world) -> None:  # type: ignore[no-untyped-def]
    import base64

    env, service, _, clock = world
    env.add(2)
    env.add(3)
    cmd = service.enqueue("node2", {"type": "collect_diag"})
    env.registry.claim_commands(2, now=clock[0])
    raw = b"archive-bytes"
    env.registry.finish_command(
        2, cmd["id"], ok=True, result={"ok": True, "artefact_b64": base64.b64encode(raw).decode()}
    )
    assert service.artifact("node2", cmd["id"]) == raw
    shown = service.command("node2", cmd["id"])
    assert shown["result"]["artefact_available"] and "artefact_b64" not in shown["result"]
    with pytest.raises(ManagementError) as exc:
        service.artifact("node3", cmd["id"])
    assert exc.value.status == 404
    for artifact in (
        "invalid base64!",
        "",
        base64.b64encode(b"x" * (5 * 1024 * 1024 + 1)).decode(),
    ):
        bad = service.enqueue("node2", {"type": "collect_diag"})
        env.registry.claim_commands(2, now=clock[0])
        env.registry.finish_command(
            2, bad["id"], ok=True, result={"ok": True, "artefact_b64": artifact}
        )
        with pytest.raises(ManagementError) as invalid:
            service.artifact("node2", bad["id"])
        assert invalid.value.error == "invalid_artifact"


@pytest.mark.parametrize(
    "policy",
    [
        {"sets": {"web": {"domains": ["example.org"]}}, "egress": []},
        {"sets": {"web": {"route_urls": ["https://example.org/routes"]}}, "egress": []},
        {"egress": [{"from": ["host"], "to": "any", "via": "exit:2"}]},
    ],
)
def test_unsupported_runtime_is_refused_not_delivered(world, policy) -> None:  # type: ignore[no-untyped-def]
    _, service, _, _ = world
    service.create(AgentCreate(name="branch"))
    with pytest.raises(ManagementError) as exc:
        service.set_policy("branch", policy)
    assert exc.value.error == "runtime_unsupported"
