from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kornode.registry.db import migrate, open_registry
from kornode.registry.models import NodePrefix
from kornode.registry.repository import Registry, RegistryConflict, RegistryNotFound


def test_node_repository_round_trips_json_columns(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        migrate(conn)
        registry = Registry(conn)

        created = registry.create_node(
            id=2,
            name="agent-b",
            description="Branch",
            roles=["access", "exit"],
            policy={"egress": ["main"]},
            transport={"dpd": 30},
        )

        assert created.roles == ["access", "exit"]
        assert created.policy == {"egress": ["main"]}
        assert created.transport == {"dpd": 30}
        assert created.created_at.endswith("Z")
        assert registry.get_node(2) == created
        assert registry.get_node_by_name("agent-b") == created

        updated = registry.update_node(2, description="HQ", roles=["exit"], policy={"sets": []})
        assert updated.description == "HQ"
        assert updated.roles == ["exit"]
        assert updated.policy == {"sets": []}


def test_duplicate_name_is_conflict_and_missing_node_is_not_found(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        migrate(conn)
        registry = Registry(conn)
        registry.create_node(id=1, name="agent-a")

        with pytest.raises(RegistryConflict):
            registry.create_node(id=2, name="agent-a")
        with pytest.raises(RegistryNotFound):
            registry.get_node(99)
        with pytest.raises(RegistryNotFound):
            registry.update_node(99, description="missing")


def test_set_prefixes_replaces_atomically_and_lists_all(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        migrate(conn)
        registry = Registry(conn)
        registry.create_node(id=1, name="agent-a")
        registry.create_node(id=2, name="agent-b")

        first = [
            NodePrefix(node_id=1, prefix="10.8.1.0/24", kind="pool", export=True),
            {"prefix": "192.168.1.0/24", "kind": "lan", "export": False},
        ]
        registry.set_prefixes(1, first)
        registry.set_prefixes(2, [{"prefix": "10.8.2.0/24", "kind": "pool", "export": True}])
        registry.set_prefixes(1, [{"prefix": "10.9.1.0/24", "kind": "source", "export": True}])

        assert registry.list_prefixes(1) == [
            NodePrefix(node_id=1, prefix="10.9.1.0/24", kind="source", export=True)
        ]
        assert [prefix.node_id for prefix in registry.list_prefixes()] == [1, 2]


def test_list_nodes_ordered_by_id(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        migrate(conn)
        registry = Registry(conn)
        registry.create_node(id=3, name="agent-c")
        registry.create_node(id=1, name="agent-a")
        registry.create_node(id=2, name="agent-b")

        assert [node.id for node in registry.list_nodes()] == [1, 2, 3]


def test_set_prefixes_binds_prefixes_to_the_given_node(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        migrate(conn)
        registry = Registry(conn)
        registry.create_node(id=1, name="hub")
        registry.create_node(id=2, name="agent-b")

        registry.set_prefixes(
            2, [NodePrefix(node_id=1, prefix="10.100.2.0/24", kind="pool", export=True)]
        )

        assert registry.list_prefixes(1) == []
        assert [p.node_id for p in registry.list_prefixes(2)] == [2]


def _node_registry(conn: sqlite3.Connection, *ids: int) -> Registry:
    migrate(conn)
    registry = Registry(conn)
    for node_id in ids:
        registry.create_node(id=node_id, name=f"agent-{node_id}")
    return registry


def test_reports_keep_only_the_last_n_per_node(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        registry = _node_registry(conn, 2, 3)
        for index in range(7):
            registry.add_report(2, {"n": index}, keep=5)
        registry.add_report(3, {"n": 0}, keep=5)

        reports = registry.list_reports(2, limit=10)

        assert [item.body["n"] for item in reports] == [6, 5, 4, 3, 2]
        assert len(registry.list_reports(3)) == 1


def test_high_water_version_never_decreases(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        registry = _node_registry(conn, 2)

        assert registry.raise_high_water(2, 5) == 5
        assert registry.raise_high_water(2, 3) == 5
        assert registry.raise_high_water(2, 9) == 9


def test_commands_are_delivered_once_expire_and_finish_only_by_owner(tmp_path: Path) -> None:
    now = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
    with open_registry(tmp_path / "registry.db") as conn:
        registry = _node_registry(conn, 2, 3)
        fresh = registry.enqueue_command(2, "reconnect", now=now)
        stale = registry.enqueue_command(2, "restart", now=now - timedelta(minutes=30))
        other = registry.enqueue_command(3, "reconnect", now=now)

        assert registry.has_queued_commands(2, now=now)
        claimed = registry.claim_commands(2, now=now)

        assert [item.id for item in claimed] == [fresh.id]
        assert claimed[0].state == "delivered"
        assert registry.get_command(stale.id).state == "expired"
        assert registry.claim_commands(2, now=now) == []
        assert not registry.has_queued_commands(2, now=now)
        with pytest.raises(RegistryNotFound):
            registry.finish_command(3, fresh.id, ok=True, result={}, now=now)
        with pytest.raises(RegistryNotFound):
            registry.finish_command(2, other.id, ok=True, result={}, now=now)
        done = registry.finish_command(2, fresh.id, ok=False, result={"output": "boom"}, now=now)
        assert done.state == "failed"
        assert done.result == {"output": "boom"}
        with pytest.raises(RegistryNotFound):
            registry.finish_command(2, fresh.id, ok=True, result={}, now=now)
