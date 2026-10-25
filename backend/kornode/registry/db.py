from __future__ import annotations

import fcntl
import os
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path


class RegistryError(RuntimeError):
    """Base registry storage error."""


Migration = tuple[int, str]


def open_registry(path: Path) -> sqlite3.Connection:
    # The parent is data_dir, shared with other services: create it if
    # missing but leave its mode alone. The database is created 0600 before
    # sqlite opens it; sqlite gives -wal/-shm the same mode.
    path.parent.mkdir(parents=True, exist_ok=True)
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    conn = sqlite3.connect(path, isolation_level=None, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
    if str(mode).lower() != "wal":
        raise RegistryError(f"failed to enable WAL journal mode, got {mode!r}")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.execute("COMMIT")
    except BaseException:
        # SQLite rolls back by itself on some errors (SQLITE_FULL, IOERR);
        # a second ROLLBACK would raise and hide the original exception.
        # A failed COMMIT must not leave the connection inside a transaction.
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def migrate(
    conn: sqlite3.Connection,
    migrations: Sequence[Migration] | None = None,
    *,
    now: datetime | None = None,
) -> None:
    """Forward-only migrations. Upgrading an existing registry (0 < current <
    latest) first writes a `VACUUM INTO` snapshot named for the pre-migration
    version (spec 12, D-92); if that snapshot fails nothing is migrated."""
    available = list(migrations) if migrations is not None else _load_migrations()
    latest = max((version for version, _sql in available), default=0)
    current = _user_version(conn)
    _refuse_newer(current, latest)
    if current >= latest:
        return
    path = _database_path(conn)
    if path is None:  # in-memory: nothing on disk to protect
        _apply_all(conn, available)
        return
    # One migrator at a time across processes (hub API, control API, korctl):
    # the version is re-read under the lock so only the first takes the snapshot.
    with _migration_lock(path):
        current = _user_version(conn)
        _refuse_newer(current, latest)
        if current >= latest:
            return
        if current > 0:
            snapshot_before_migration(conn, path, current, now=now or datetime.now(UTC))
        _apply_all(conn, available)


def snapshot_dir(db_path: Path) -> Path:
    """`data_dir/backups/registry` for `data_dir/registry.db` (spec 05)."""
    return db_path.parent / "backups" / "registry"


def snapshot_before_migration(
    conn: sqlite3.Connection, db_path: Path, version: int, *, now: datetime
) -> Path:
    from kornode.registry.snapshot import write_snapshot

    name = f"pre-migration-v{version}-{now.astimezone(UTC).strftime('%Y%m%dT%H%M%SZ')}.db"
    try:
        return write_snapshot(conn, snapshot_dir(db_path), name)
    except (OSError, sqlite3.Error, RegistryError) as exc:
        raise RegistryError(
            f"pre-migration snapshot of registry v{version} failed ({type(exc).__name__}); "
            "the registry was not migrated"
        ) from exc


def _user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _refuse_newer(current: int, latest: int) -> None:
    if current > latest:
        raise RegistryError(
            f"registry database version {current} is newer than this code supports ({latest})"
        )


def _apply_all(conn: sqlite3.Connection, available: Sequence[Migration]) -> None:
    current = _user_version(conn)
    for version, sql in available:
        if version <= current:
            continue
        _apply_migration(conn, version, sql)


def _database_path(conn: sqlite3.Connection) -> Path | None:
    for row in conn.execute("PRAGMA database_list").fetchall():
        if row[1] == "main":
            return Path(row[2]) if row[2] else None
    return None


@contextmanager
def _migration_lock(db_path: Path) -> Iterator[None]:
    lock = db_path.with_name(f".{db_path.name}.migrate.lock")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _load_migrations() -> list[Migration]:
    package = resources.files("kornode.registry.migrations")
    migrations: list[Migration] = []
    for item in sorted(package.iterdir(), key=lambda path: path.name):
        if not item.name.endswith(".sql"):
            continue
        prefix = item.name.split("_", 1)[0]
        migrations.append((int(prefix), item.read_text(encoding="utf-8")))
    return migrations


def _apply_migration(conn: sqlite3.Connection, version: int, sql: str) -> None:
    with transaction(conn):
        # Another process may have migrated between our read and BEGIN IMMEDIATE.
        if int(conn.execute("PRAGMA user_version").fetchone()[0]) >= version:
            return
        for statement in _split_sql(sql):
            conn.execute(statement)
        conn.execute(f"PRAGMA user_version = {version}")


def _split_sql(sql: str) -> list[str]:
    """Split a script into statements; `;` inside strings, comments and
    trigger bodies does not end a statement (sqlite3.complete_statement)."""
    statements: list[str] = []
    pending = ""
    for chunk in sql.split(";"):
        pending += chunk + ";"
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            if statement.strip("; \n\t"):
                statements.append(statement)
            pending = ""
    if pending.strip("; \n\t"):
        raise RegistryError("migration ends with an incomplete SQL statement")
    return statements
