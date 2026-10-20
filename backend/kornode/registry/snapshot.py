from __future__ import annotations

import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from kornode.registry.db import RegistryError, open_registry


def snapshot(
    conn_or_path: sqlite3.Connection | Path,
    dest_dir: Path,
    *,
    now: datetime,
    keep: int = 7,
) -> Path | None:
    if isinstance(conn_or_path, Path):
        if not conn_or_path.exists():
            return None
        # Copy the database as it is: a snapshot taken before a migration is
        # the one worth having.
        with closing(open_registry(conn_or_path)) as conn:
            return _snapshot(conn, dest_dir, now=now, keep=keep)
    return _snapshot(conn_or_path, dest_dir, now=now, keep=keep)


def _snapshot(conn: sqlite3.Connection, dest_dir: Path, *, now: datetime, keep: int) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o700)
    stamp = _as_utc(now).strftime("%Y%m%dT%H%M%SZ")
    final_path = dest_dir / f"registry-{stamp}.db"
    fd, temp_name = tempfile.mkstemp(prefix=f".{final_path.name}.", suffix=".tmp", dir=dest_dir)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        conn.execute("VACUUM INTO ?", (str(temp_path),))
        os.chmod(temp_path, 0o600)
        with closing(sqlite3.connect(temp_path)) as copied:
            result = copied.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise RegistryError(f"registry snapshot integrity check failed: {result}")
        os.replace(temp_path, final_path)
        _prune(dest_dir, keep)
        return final_path
    finally:
        temp_path.unlink(missing_ok=True)


def due(dest_dir: Path, *, now: datetime) -> bool:
    newest = _newest_snapshot(dest_dir)
    if newest is None:
        return True
    return _as_utc(now) - newest >= timedelta(hours=24)


def _prune(dest_dir: Path, keep: int) -> None:
    snapshots = sorted(dest_dir.glob("registry-*.db"), key=lambda path: path.name)
    for path in snapshots[:-keep]:
        path.unlink()


def _newest_snapshot(dest_dir: Path) -> datetime | None:
    newest: datetime | None = None
    for path in dest_dir.glob("registry-*.db"):
        try:
            stamp = datetime.strptime(path.stem.removeprefix("registry-"), "%Y%m%dT%H%M%SZ")
        except ValueError:
            continue
        stamp = stamp.replace(tzinfo=UTC)
        if newest is None or stamp > newest:
            newest = stamp
    return newest


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
