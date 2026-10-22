from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path

import pytest

from kornode.registry.db import (
    RegistryError,
    _apply_migration,
    _split_sql,
    migrate,
    open_registry,
    transaction,
)
from kornode.registry.repository import Registry, RegistryConflict


def test_open_registry_creates_private_wal_database(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o755)
    data_dir.chmod(0o755)
    db_path = data_dir / "registry.db"

    with open_registry(db_path) as conn:
        migrate(conn)

        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 4

    # data_dir is shared with other services; its mode is not ours to change.
    assert (data_dir.stat().st_mode & 0o777) == 0o755
    assert (db_path.stat().st_mode & 0o777) == 0o600

    with open_registry(db_path) as conn:
        migrate(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 4


def test_migrate_refuses_newer_database(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    with open_registry(db_path) as conn:
        conn.execute("PRAGMA user_version = 999")

        with pytest.raises(RegistryError, match="newer"):
            migrate(conn)


def test_migration_rollback_keeps_previous_version(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    with open_registry(db_path) as conn:
        with pytest.raises(sqlite3.DatabaseError):
            migrate(conn, migrations=[(1, "CREATE TABLE ok_table (id INTEGER); BAD SQL;")])

        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'ok_table'"
        ).fetchone()
        assert exists is None


def test_schema_constraints_and_cascade_delete(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        migrate(conn)
        registry = Registry(conn)
        node = registry.create_node(id=1, name="agent-a")
        registry.set_prefixes(node.id, [{"prefix": "10.8.1.0/24", "kind": "pool", "export": True}])

        for bad_id in (0, 255):
            with pytest.raises(RegistryConflict):
                registry.create_node(id=bad_id, name=f"agent-{bad_id}")
        with pytest.raises(RegistryConflict):
            registry.create_node(id=2, name="Agent")
        with pytest.raises(RegistryConflict):
            registry.set_state(node.id, "disabled")  # type: ignore[arg-type]

        registry.delete_node(node.id)
        assert registry.list_prefixes() == []


def test_transaction_rolls_back_on_error(tmp_path: Path) -> None:
    with open_registry(tmp_path / "registry.db") as conn:
        migrate(conn)

        with pytest.raises(RuntimeError, match="boom"), transaction(conn):
            conn.execute(
                "INSERT INTO nodes (id, name, state, created_at, updated_at) "
                "VALUES (1, 'agent-a', 'pending', '2026-10-13T00:00:00Z', "
                "'2026-10-13T00:00:00Z')"
            )
            raise RuntimeError("boom")

        assert conn.execute("SELECT count(*) FROM nodes").fetchone()[0] == 0


def test_concurrent_writer_waits_for_begin_immediate(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    with open_registry(db_path) as first:
        migrate(first)

    first = open_registry(db_path)
    second = open_registry(db_path)
    try:
        Registry(first).create_node(id=1, name="agent-a")
        started = threading.Event()
        elapsed: list[float] = []

        def write_second() -> None:
            started.set()
            before = time.monotonic()
            Registry(second).create_node(id=2, name="agent-b")
            elapsed.append(time.monotonic() - before)

        with transaction(first):
            thread = threading.Thread(target=write_second)
            thread.start()
            assert started.wait(timeout=1)
            time.sleep(0.2)
        thread.join(timeout=2)

        assert not thread.is_alive()
        assert elapsed and elapsed[0] >= 0.15
        assert [node.id for node in Registry(first).list_nodes()] == [1, 2]
    finally:
        first.close()
        second.close()


def test_migrate_skips_version_applied_by_another_process(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    stale = open_registry(db_path)
    other = open_registry(db_path)
    try:
        migration = [(1, "CREATE TABLE once (id INTEGER)")]
        # `stale` read user_version 0 before `other` migrated; applying must not
        # run the CREATE a second time.
        assert stale.execute("PRAGMA user_version").fetchone()[0] == 0
        migrate(other, migrations=migration)
        _apply_migration(stale, 1, migration[0][1])
        assert stale.execute("PRAGMA user_version").fetchone()[0] == 1
    finally:
        stale.close()
        other.close()


def test_split_sql_keeps_semicolons_inside_strings_comments_and_triggers() -> None:
    sql = """
    -- a comment; with a semicolon
    CREATE TABLE t (v TEXT DEFAULT 'a;b');
    CREATE TRIGGER tr AFTER INSERT ON t BEGIN UPDATE t SET v = 'x;y'; END;
    """
    statements = _split_sql(sql)

    assert len(statements) == 2
    assert statements[1].endswith("END;")
    with pytest.raises(RegistryError):
        _split_sql("CREATE TABLE t (v TEXT DEFAULT 'unterminated)")


def test_migration_with_trigger_applies(tmp_path: Path) -> None:
    sql = (
        "CREATE TABLE t (v TEXT);\n"
        "CREATE TRIGGER tr AFTER INSERT ON t BEGIN UPDATE t SET v = 'x;y'; END;\n"
    )
    with closing(open_registry(tmp_path / "registry.db")) as conn:
        migrate(conn, migrations=[(1, sql)])
        conn.execute("INSERT INTO t (v) VALUES ('a')")
        assert conn.execute("SELECT v FROM t").fetchone()[0] == "x;y"
