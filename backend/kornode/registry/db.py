from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
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


def migrate(conn: sqlite3.Connection, migrations: Sequence[Migration] | None = None) -> None:
    available = list(migrations) if migrations is not None else _load_migrations()
    latest = max((version for version, _sql in available), default=0)
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if current > latest:
        raise RegistryError(
            f"registry database version {current} is newer than this code supports ({latest})"
        )
    for version, sql in available:
        if version <= current:
            continue
        _apply_migration(conn, version, sql)


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
