"""Encrypted hub backup and non-destructive, staged disaster recovery.

Restore never switches a live runtime. A complete config.yaml is published last;
operators stop the old hub and mount/start the restored tree explicitly.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import secrets
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from kornode import __version__
from kornode.config.models import AppConfig
from kornode.registry.db import transaction
from kornode.services.agent_models import ManagementError
from kornode.services.agents import AgentService
from kornode.services.backup_crypto import decrypt, encrypt, password_bytes
from kornode.services.backup_state import (
    ArchiveState,
    Collector,
    absolute,
    check_database,
    check_identity,
    invalid,
    relocated,
)
from kornode.services.files import FileManager


class BackupService:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    @contextlib.contextmanager
    def _operation(self) -> Iterator[None]:
        # Bound expensive KDFs and snapshots across admin workers/processes.
        directory = self.config.system.data_dir / "control"
        directory.mkdir(parents=True, exist_ok=True)
        fd = os.open(directory / "backup.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+b") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ManagementError(409, "busy", "another backup or restore is running") from None
            try:
                yield
            except ManagementError:
                raise
            except Exception:
                # Neither filesystem errors nor validation exceptions may echo
                # filenames, archive contents, private keys or passphrases.
                raise ManagementError(
                    422, "backup_failed", "hub backup/restore failed validation or I/O"
                ) from None

    def create(self, passphrase: str) -> bytes:
        password_bytes(passphrase)
        if not self.config.fabric.enabled:
            raise ManagementError(409, "disabled", "hub backup requires an initialized fabric hub")
        path = self.config.system.data_dir / "registry.db"
        if not path.is_file() or path.is_symlink():
            raise ManagementError(409, "missing_state", "hub registry is missing")
        with (
            self._operation(),
            AgentService(self.config).exclusive(),
            tempfile.TemporaryDirectory(prefix="kornode-backup-") as tmp,
        ):
            scratch = Path(tmp) / "registry.db"
            # Hold the SQLite writer reservation for DB + file capture. Copy from
            # a second read-only connection: backup() on the reserved connection
            # itself would wait forever for its own write transaction.
            with (
                contextlib.closing(sqlite3.connect(path, isolation_level=None, timeout=5)) as lock,
                transaction(lock),
            ):
                with (
                    contextlib.closing(
                        sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True)
                    ) as source,
                    contextlib.closing(sqlite3.connect(scratch)) as destination,
                ):
                    source.backup(destination)
                    destination.execute("PRAGMA journal_mode=DELETE")
                scratch.chmod(0o600)
                rotation = check_database(scratch)
                collector = Collector(self.config)
                collector.collect(scratch.read_bytes(), rotation)
                collector.verify_unchanged()
            state = ArchiveState(
                format=1,
                created_at=datetime.now(UTC).isoformat(),
                version=__version__,
                config=self.config.model_dump(mode="json"),
                paths=collector.paths,
                files=collector.files,
            )
            check_identity(self.config, state.decoded(), state.paths, rotation)
            return encrypt(state.model_dump_json().encode(), passphrase)

    def restore(
        self,
        archive: bytes,
        passphrase: str,
        *,
        target: Path | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        with self._operation(), tempfile.TemporaryDirectory(prefix="kornode-restore-") as tmp:
            state = ArchiveState.model_validate_json(decrypt(archive, passphrase))
            decoded = state.decoded()
            original = AppConfig.model_validate(state.config)
            database_name = state.paths.get(str(absolute(original.system.data_dir / "registry.db")))
            if database_name != "data/registry.db":
                raise invalid()
            scratch = Path(tmp) / "registry.db"
            FileManager().atomic_write_bytes(scratch, decoded[database_name])
            rotation = check_database(scratch)
            check_identity(original, decoded, state.paths, rotation)
            destination = absolute(
                target
                or (self.config.system.data_dir / "restores" / ("hub-" + secrets.token_hex(12)))
            )
            if any(parent.is_symlink() for parent in destination.parents):
                raise ManagementError(
                    409, "unsafe_target", "restore parent directories must not be symlinks"
                )
            if destination.exists() or destination.is_symlink():
                raise ManagementError(
                    409, "target_exists", "restore requires a new, nonexistent directory"
                )
            # Do not allow a target within any live persistent directory except
            # the dedicated restores/ staging area. No live paths come from the archive.
            staging = absolute(self.config.system.data_dir / "restores")
            live = [
                self.config.system.data_dir,
                self.config.system.secrets_dir,
                self.config.system.generated_dir,
                self.config.system.log_dir,
                self.config.identity.config_per_user_dir or self.config.system.generated_dir,
                self.config.identity.config_per_group_dir or self.config.system.generated_dir,
            ]
            if not destination.is_relative_to(staging) and any(
                destination.is_relative_to(absolute(path)) for path in live
            ):
                raise ManagementError(409, "unsafe_target", "restore target overlaps live state")
            restored = relocated(original, state.paths, destination)
            if rotation:
                with contextlib.closing(sqlite3.connect(scratch)) as conn:
                    conn.execute(
                        "UPDATE control_rotation SET active_path=?, next_path=? WHERE singleton=1",
                        [
                            str(destination / state.paths[str(absolute(Path(path)))])
                            for path in rotation
                        ],
                    )
                    conn.commit()
            decoded[database_name] = scratch.read_bytes()
            result = {
                "dry_run": dry_run,
                "staged": not dry_run,
                "target": str(destination),
                "config_path": str(destination / "config.yaml"),
                "files": len(decoded),
                "created_at": state.created_at,
                "restart_required": True,
                "warning": (
                    "Stop the old hub before activating this tree. "
                    "Never run cloned hub identities concurrently."
                ),
            }
            if dry_run:
                return result
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.mkdir(mode=0o700)  # exclusive claim; never replaces even an empty directory
            try:
                manager = FileManager()
                for name, content in decoded.items():
                    path = destination / name
                    _private_dirs(destination, path.parent)
                    manager.atomic_write_bytes(path, content, state.files[name].mode)
                for directory in (
                    restored.system.generated_dir,
                    restored.system.log_dir,
                    restored.system.secrets_dir,
                    restored.identity.config_per_user_dir,
                    restored.identity.config_per_group_dir,
                ):
                    if directory is not None:
                        _private_dirs(destination, directory)
                manager.atomic_write_private_text(
                    destination / "config.yaml",
                    yaml.safe_dump(restored.model_dump(mode="json"), sort_keys=False),
                )
                fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except BaseException:
                shutil.rmtree(destination)
                raise
            return result

    @staticmethod
    def publish(path: Path, archive: bytes) -> None:
        """Atomically publish an encrypted archive without clobbering a user file."""
        try:
            with tempfile.NamedTemporaryFile(
                prefix=".hub-backup-", dir=path.parent, delete=False
            ) as handle:
                temporary = Path(handle.name)
                try:
                    os.chmod(temporary, 0o600)
                    handle.write(archive)
                    handle.flush()
                    os.fsync(handle.fileno())
                    os.link(temporary, path)
                    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                finally:
                    temporary.unlink(missing_ok=True)
        except FileExistsError:
            raise ManagementError(409, "output_exists", "backup output already exists") from None
        except OSError:
            raise ManagementError(
                409, "write_failed", "could not publish encrypted backup"
            ) from None


def _private_dirs(root: Path, directory: Path) -> None:
    """mkdir -p below `root` with 0700 on every level (`mode=` only covers the leaf)."""
    if root not in directory.parents and directory != root:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return
    missing = []
    current = directory
    while current != root and root in current.parents:
        missing.append(current)
        current = current.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700, exist_ok=True)
        item.chmod(0o700)
