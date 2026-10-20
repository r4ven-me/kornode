from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from kornode.registry.db import migrate, open_registry
from kornode.registry.repository import Registry
from kornode.registry.snapshot import due, snapshot


def test_snapshot_copies_database_and_uses_private_mode(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    now = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
    with open_registry(db_path) as conn:
        migrate(conn)
        Registry(conn).create_node(id=1, name="agent-a")
        written = snapshot(conn, tmp_path / "backups", now=now)

    assert written == tmp_path / "backups" / "registry-20261013T120000Z.db"
    assert (written.stat().st_mode & 0o777) == 0o600
    with sqlite3.connect(written) as copied:
        assert copied.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert copied.execute("SELECT name FROM nodes WHERE id = 1").fetchone()[0] == "agent-a"


def test_snapshot_retention_prunes_to_keep_newest(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    with open_registry(db_path) as conn:
        migrate(conn)
        dest_dir = tmp_path / "backups"
        for index in range(9):
            snapshot(
                conn,
                dest_dir,
                now=datetime(2026, 10, 13, index, 0, tzinfo=UTC),
                keep=7,
            )

    names = [path.name for path in sorted(dest_dir.glob("registry-*.db"))]
    assert names == [f"registry-20261013T0{index}0000Z.db" for index in range(2, 9)]


def test_due_logic_uses_newest_snapshot(tmp_path: Path) -> None:
    now = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
    dest_dir = tmp_path / "backups"

    assert due(dest_dir, now=now)
    dest_dir.mkdir()
    fresh = dest_dir / "registry-20261013T000001Z.db"
    old = dest_dir / "registry-20261012T115959Z.db"
    fresh.write_bytes(b"fresh")
    old.write_bytes(b"old")

    assert not due(dest_dir, now=now)
    os.utime(fresh, (0, 0))
    assert due(dest_dir, now=datetime(2026, 10, 14, 0, 0, 2, tzinfo=UTC))


def test_snapshot_noops_when_registry_path_is_absent(tmp_path: Path) -> None:
    missing = tmp_path / "missing.db"

    assert snapshot(missing, tmp_path / "backups", now=datetime(2026, 10, 13, tzinfo=UTC)) is None
    assert not (tmp_path / "backups").exists()
