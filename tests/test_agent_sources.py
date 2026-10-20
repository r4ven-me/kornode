"""P4-05: sources attached to agents — export into the fabric, hub routes, validation (D-68)."""

from __future__ import annotations

from typing import Any

import pytest
from tests.test_agent_management import world as world  # noqa: F401

from kornode.registry.db import migrate, open_registry
from kornode.registry.repository import Registry
from kornode.services.agent_models import ManagementError
from kornode.services.fabric_groups import FabricGroupsService

SOURCE = {"interface": "awg0", "cidr": "10.8.3.0/24"}


def _user_files(world: Any) -> dict[str, str]:
    env = world[0]
    conn = open_registry(env.config.system.data_dir / "registry.db")
    try:
        migrate(conn)
        registry = Registry(conn)
        groups = FabricGroupsService(env.config)
        files = groups.render_files(registry.list_nodes(), registry.list_prefixes())
    finally:
        conn.close()
    return {str(item.path.name): item.content for item in files}


def _prefixes_of(world: Any, node: int) -> dict[str, str]:
    """Prefixes other nodes' bundles carry for `node` (what the agent routes into the fabric)."""
    env = world[0]
    other = 2 if node == 3 else 3
    bundle = env.check(env.registry.latest_bundle(other)).bundle
    return {p.prefix: p.kind for p in bundle.fabric.prefixes if p.node_id == node}


def test_an_exported_source_reaches_the_other_nodes_and_the_hub_routes(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(2)
    env.add(3)
    service.set_source("node3", "amnezia", {**SOURCE, "export": True})

    assert _prefixes_of(world, 3)["10.8.3.0/24"] == "source"
    files = _user_files(world)
    assert "iroute = 10.8.3.0/24" in files["agent-3"]
    assert "route = 10.8.3.0/24" in files["agent-2"]
    assert "10.8.3.0/24" not in files["agent-3"].replace("iroute = 10.8.3.0/24", "")
    # The node's own bundle still compiles the source class; its own prefix is not "other".
    own = env.check(env.registry.latest_bundle(3)).bundle
    assert [s.name for s in own.policy.sources] == ["amnezia"]
    assert "10.8.3.0/24" not in {p.prefix for p in own.fabric.prefixes}


def test_a_source_with_export_false_stays_local(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(2)
    env.add(3)
    service.set_source("node3", "amnezia", {**SOURCE, "export": False})
    assert "10.8.3.0/24" not in _prefixes_of(world, 3)
    assert all("10.8.3.0/24" not in text for text in _user_files(world).values())
    assert [s.name for s in env.check(env.registry.latest_bundle(3)).bundle.policy.sources] == [
        "amnezia"
    ]


def test_withdrawing_a_source_withdraws_its_prefix(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(2)
    env.add(3)
    service.set_source("node3", "amnezia", SOURCE)
    assert "10.8.3.0/24" in _prefixes_of(world, 3)
    service.set_source("node3", "amnezia", None)
    assert "10.8.3.0/24" not in _prefixes_of(world, 3)
    assert "10.8.3.0/24" not in _user_files(world)["agent-2"]


def test_a_source_outside_the_node_pool_needs_an_explicit_opt_in(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(2)
    env.add(3)
    outside = {"interface": "wg0", "cidr": "192.168.77.0/24"}
    with pytest.raises(ManagementError) as raised:
        service.set_source("node3", "office", outside)
    assert raised.value.error == "source_pool"
    service.set_source("node3", "office", {**outside, "allow_outside_pool": True})
    assert _prefixes_of(world, 3)["192.168.77.0/24"] == "source"
    # ...and it may not collide with a prefix another node already exports.
    with pytest.raises(ManagementError):
        service.set_source(
            "node2",
            "clash",
            {"interface": "wg1", "cidr": "192.168.77.0/25", "allow_outside_pool": True},
        )


def test_the_sources_listing_reports_runtime_support(world: Any) -> None:  # type: ignore[no-untyped-def]
    env, service, _, _ = world
    env.add(3)
    service.set_source("node3", "amnezia", SOURCE)
    listing = service.sources("node3")
    assert listing["runtime_supported"] is True
    assert [item["name"] for item in listing["sources"]] == ["amnezia"]
