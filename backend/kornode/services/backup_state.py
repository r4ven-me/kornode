"""Collect persistent hub state and validate portable, non-executable archive records."""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field

from kornode.config.models import AppConfig
from kornode.registry.db import migrate
from kornode.services.agent_models import ManagementError
from kornode.services.backup_crypto import MAX_PLAINTEXT

MAX_FILES = 10000
ALLOWED_ROOTS = {"data", "secrets", "users", "groups", "files"}


def invalid() -> ManagementError:
    return ManagementError(422, "invalid_archive", "backup state is incomplete or invalid")


def absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def portable(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or path.is_absolute()
        or any(part in (".", "..", "") for part in name.split("/"))
        or len(path.parts) < 2
        or path.parts[0] not in ALLOWED_ROOTS
        or path.as_posix() != name
    ):
        raise invalid()
    return name


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    data: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: int


class ArchiveState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    format: int
    created_at: str = Field(max_length=64, pattern=r"^\d{4}-\d{2}-\d{2}T[0-9:.+Z-]+$")
    version: str = Field(max_length=32, pattern=r"^\d+\.\d+\.\d+.*$")
    config: dict[str, Any]
    paths: dict[str, str]
    files: dict[str, Record] = Field(max_length=MAX_FILES)

    def decoded(self) -> dict[str, bytes]:
        if self.format != 1:
            raise invalid()
        decoded: dict[str, bytes] = {}
        server = self.config.get("server", {})
        if not isinstance(server, dict):
            raise invalid()
        public_hooks = {
            self.paths.get(str(absolute(Path(value))))
            for field in ("connect_script", "disconnect_script")
            if isinstance(value := server.get(field), str)
        }
        total = 0
        for name, record in self.files.items():
            portable(name)
            if record.mode not in (0o600, 0o700, 0o644, 0o755):
                raise invalid()
            if record.mode in (0o644, 0o755) and not (
                name.startswith(("users/", "groups/")) or name in public_hooks
            ):
                raise invalid()
            data = base64.b64decode(record.data, validate=True)
            total += len(data)
            if total > MAX_PLAINTEXT or hashlib.sha256(data).hexdigest() != record.sha256:
                raise invalid()
            decoded[name] = data
        for name in self.files:
            if any(parent.as_posix() in self.files for parent in PurePosixPath(name).parents):
                raise invalid()
        if any(portable(name) not in self.files for name in self.paths.values()):
            raise invalid()
        return decoded


def path_values(value: Any) -> list[Path]:
    if isinstance(value, Path):
        return [value]
    if isinstance(value, dict):
        return [path for item in value.values() for path in path_values(item)]
    if isinstance(value, list):
        return [path for item in value for path in path_values(item)]
    return []


def directory_map(config: AppConfig) -> dict[Path, str]:
    pairs = [
        (config.system.data_dir, "data"),
        (config.system.secrets_dir, "secrets"),
        (config.identity.config_per_user_dir, "users"),
        (config.identity.config_per_group_dir, "groups"),
    ]
    result: dict[Path, str] = {}
    for path, name in pairs:
        if path is not None:
            key = absolute(path)
            if key in result:
                raise ManagementError(
                    409, "unsupported_layout", "persistent directories must differ"
                )
            result[key] = name
    return result


class Collector:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.directories = directory_map(config)
        self.files: dict[str, Record] = {}
        self.paths: dict[str, str] = {}
        self.explicit_files = {
            absolute(path) for path in path_values(config.model_dump(mode="python"))
        }
        self.total = 0
        self.observed: dict[Path, tuple[int, int, int, int, int]] = {}

    @staticmethod
    def stamp(info: os.stat_result) -> tuple[int, int, int, int, int]:
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    def verify_unchanged(self) -> None:
        if any(self.stamp(path.stat()) != stamp for path, stamp in self.observed.items()):
            raise ManagementError(
                409,
                "state_changed",
                "hub files changed during backup; retry in a maintenance window",
            )

    def name(self, path: Path) -> str:
        path = absolute(path)
        for root in sorted(self.directories, key=lambda p: len(p.parts), reverse=True):
            if path.is_relative_to(root) and path != root:
                return self.directories[root] + "/" + path.relative_to(root).as_posix()
        return "files/" + hashlib.sha256(os.fsencode(path)).hexdigest()

    def add(self, path: Path, *, content: bytes | None = None, required: bool = False) -> None:
        path = absolute(path)
        if content is None and not path.exists():
            if required or path.is_symlink():
                raise ManagementError(409, "missing_state", "required hub state file is missing")
            return
        name = portable(self.name(path))
        if name in self.files:
            self.paths[str(path)] = name
            return
        mode = 0o600
        if content is None:
            # Explicit configured cert paths may be Let's Encrypt symlinks. Resolve
            # only those files; recursive directory capture refuses links entirely.
            source = path.resolve(strict=True)
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                self.observed[path] = self.stamp(info)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PLAINTEXT:
                    raise ManagementError(
                        409, "unsafe_state", "backup requires bounded regular files"
                    )
                content = handle.read(MAX_PLAINTEXT + 1)
                if info.st_mode & stat.S_IXUSR:
                    mode = 0o700
                if name.startswith(("users/", "groups/")) and info.st_mode & stat.S_IROTH:
                    mode = 0o644
                if path in (
                    self.config.server.connect_script,
                    self.config.server.disconnect_script,
                ):
                    mode = 0o755 if info.st_mode & stat.S_IXOTH else 0o700
        self.total += len(content)
        if self.total > MAX_PLAINTEXT // 2 or len(self.files) >= MAX_FILES:
            raise ManagementError(413, "too_large", "hub persistent state exceeds backup limits")
        self.paths[str(path)] = name
        self.files[name] = Record(
            data=base64.b64encode(content).decode("ascii"),
            sha256=hashlib.sha256(content).hexdigest(),
            mode=mode,
        )

    def tree(self, root: Path) -> None:
        root = absolute(root)
        if not root.exists():
            return
        if root.is_symlink():
            raise ManagementError(409, "unsafe_state", "backup directories must not be symlinks")
        self.observed[root] = self.stamp(root.stat())
        config = self.config
        excluded = {
            absolute(config.system.generated_dir),
            absolute(config.system.log_dir),
            absolute(config.web.static_dir),
            absolute(config.system.data_dir / "backups"),
            absolute(config.system.data_dir / "restores"),
            absolute(config.system.data_dir / "run"),
            absolute(config.system.data_dir / "cache"),
        }
        for path in sorted(root.iterdir()):
            if path in excluded or (path in self.directories and path != root):
                continue
            if path.name.startswith(".") or path.name.endswith((".lock", ".tmp", ".sock")):
                continue
            if path.parent == absolute(config.system.data_dir) and path.name in {
                "registry.db",
                "registry.db-wal",
                "registry.db-shm",
            }:
                continue
            if path.is_symlink():
                if path in self.explicit_files and path.is_file():
                    self.add(path, required=True)
                    continue
                raise ManagementError(409, "unsafe_state", "recursive backup refuses symlinks")
            if path.is_dir():
                self.tree(path)
            else:
                self.add(path, required=True)

    def collect(self, snapshot: bytes, rotation_paths: list[str]) -> None:
        self.explicit_files.update(absolute(Path(path)) for path in rotation_paths)
        # Well-known TLS names may be certbot symlinks even when not set in config.
        self.explicit_files.update(
            absolute(path)
            for path in (
                self.config.cert_path("ca.crt"),
                self.config.cert_path("ca.key"),
                self.config.cert_path("server.crt"),
                self.config.cert_path("server.key"),
            )
        )
        for root in self.directories:
            self.tree(root)
        self.add(self.config.system.data_dir / "registry.db", content=snapshot)
        directories = set(self.directories) | {
            absolute(self.config.system.generated_dir),
            absolute(self.config.system.log_dir),
            absolute(self.config.web.static_dir),
        }
        optional = {
            absolute(self.config.auth.oidc.radius.config_file),
        }
        managed_hook = absolute(self.config.generated_path("ocserv-connect-script-kornode"))
        for path in path_values(self.config.model_dump(mode="python")):
            if absolute(path) not in directories and absolute(path) != managed_hook:
                self.add(path, required=absolute(path) not in optional)
        required = [
            self.config.cert_path("ca.key"),
            self.config.cert_path("ca.crt"),
            self.config.system.data_dir / "control" / "master.key",
            self.config.control.signing_key,
            self.config.certificates.server_cert or self.config.cert_path("server.crt"),
            self.config.certificates.server_key or self.config.cert_path("server.key"),
            *[Path(path) for path in rotation_paths],
        ]
        for required_path in required:
            if required_path is not None:
                self.add(required_path, required=True)


def relocated(config: AppConfig, paths: dict[str, str], root: Path) -> AppConfig:
    dirs = directory_map(config)
    dirs[absolute(config.system.generated_dir)] = "generated"
    dirs[absolute(config.system.log_dir)] = "logs"

    def convert(value: Any) -> Any:
        if isinstance(value, Path):
            path = absolute(value)
            if path == absolute(config.generated_path("ocserv-connect-script-kornode")):
                return root / "generated" / "ocserv-connect-script-kornode"
            if str(path) in paths:
                return root / portable(paths[str(path)])
            if path == absolute(config.web.static_dir):
                return value  # application assets belong to the installed image
            for directory in sorted(dirs, key=lambda p: len(p.parts), reverse=True):
                if path.is_relative_to(directory):
                    return root / dirs[directory] / path.relative_to(directory)
            return root / "files" / hashlib.sha256(os.fsencode(path)).hexdigest()
        if isinstance(value, dict):
            return {key: convert(item) for key, item in value.items()}
        if isinstance(value, list):
            return [convert(item) for item in value]
        return value

    return AppConfig.model_validate(convert(config.model_dump(mode="python")))


def check_database(path: Path) -> list[str]:
    with closing(sqlite3.connect(path)) as conn:
        if conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise invalid()
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise invalid()
        migrate(conn)  # newer schemas fail closed; older archives migrate only in staging
        row = conn.execute("SELECT active_path, next_path FROM control_rotation").fetchone()
        return list(row) if row else []


def check_identity(
    config: AppConfig, files: dict[str, bytes], paths: dict[str, str], rotation: list[str]
) -> None:
    def get(path: Path) -> bytes:
        return files[paths[str(absolute(path))]]

    for cert_path, key_path in [
        (config.cert_path("ca.crt"), config.cert_path("ca.key")),
        (
            config.certificates.server_cert or config.cert_path("server.crt"),
            config.certificates.server_key or config.cert_path("server.key"),
        ),
    ]:
        cert = x509.load_pem_x509_certificate(get(cert_path))
        key = serialization.load_pem_private_key(get(key_path), password=None)
        encoding = serialization.Encoding.DER
        fmt = serialization.PublicFormat.SubjectPublicKeyInfo
        if cert.public_key().public_bytes(encoding, fmt) != key.public_key().public_bytes(
            encoding, fmt
        ):
            raise invalid()
    master = get(config.system.data_dir / "control" / "master.key")
    if len(master) != 32:
        raise invalid()
    signing_paths = [Path(path) for path in rotation]
    if config.control.signing_key is not None:
        signing_paths.append(config.control.signing_key)
    for path in signing_paths:
        if not isinstance(serialization.load_pem_private_key(get(path), None), Ed25519PrivateKey):
            raise invalid()
