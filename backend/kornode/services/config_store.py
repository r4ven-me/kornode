"""Serialized config transactions shared by the API and CLI.

The lock is on a stable sibling inode, not the atomically replaced YAML file.
Render preflight happens before persistence. Runtime application has additional
side effects (passwd migration, CRLs, bundles), so a failure after persistence
is explicitly reported as saved_but_not_applied, never as a successful save.
Abrupt process death after persistence still requires startup/re-render recovery;
there is no durable multi-file runtime transaction. Death before atomic replacement
can leave a private temporary file, which is never read as the config source.
"""

from __future__ import annotations

import fcntl
import hashlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

from kornode.config.env import config_environment
from kornode.config.loader import load_yaml_file, validate_config_data
from kornode.config.models import AppConfig
from kornode.services.config import ConfigService
from kornode.services.files import FileManager


class ConfigVersionConflict(ValueError):
    pass


class ConfigPreflightError(RuntimeError):
    pass


class ConfigApplyError(RuntimeError):
    def __init__(self) -> None:
        # Do not include exception text: renderers and subprocesses may include secrets.
        super().__init__(
            "saved_but_not_applied: configuration saved; runtime application failed. "
            "Runtime files may be partially updated; retry rendering before reloading services."
        )


@contextmanager
def config_lock(path: Path) -> Iterator[Path]:
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with (target.parent / f".{target.name}.lock").open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            if path.resolve() != target:
                raise ConfigVersionConflict("configuration source alias changed; retry")
            yield target
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def source_etag(path: Path) -> str:
    # Aliases share source identity; environment context is deliberately not part of it.
    path = path.resolve()
    # Missing and present-but-empty are different source versions.
    value = b"present\0" + path.read_bytes() if path.exists() else b"missing\0"
    return source_version(value)


def source_version(value: bytes) -> str:
    return '"' + hashlib.sha256(value).hexdigest() + '"'


def mutate_config(
    path: Path,
    mutation: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    write_rendered: bool = True,
    env_file: Path | None = None,
    on_commit: Callable[[AppConfig], None] | None = None,
    expected_etag: str | None = None,
    file_manager: FileManager | None = None,
    after_apply: Callable[[AppConfig], None] | None = None,
) -> tuple[AppConfig, list[str]]:
    """Persist one candidate without a post-write reload.

    on_commit installs validated state after YAML persistence; after_apply runs
    only after successful rendered writes. Both callbacks remain under the lock
    and their failures are reported as saved_but_not_applied, not rolled back.
    The supplied path selects .env for all validation/callback reads; only the
    lock, source reads and atomic publication use the pinned canonical target.
    External operations before entering this transaction are not covered.
    """
    with config_lock(path) as target, config_environment(path, env_file):
        if expected_etag is not None and expected_etag != source_etag(target):
            raise ConfigVersionConflict("configuration source changed; reload before saving")
        raw = mutation(load_yaml_file(target))
        if path.resolve() != target:
            raise ConfigVersionConflict("configuration source alias changed; retry")
        config = validate_config_data(raw, path, env_file=env_file)
        service = ConfigService(strict_apply=True)
        if write_rendered:
            try:
                service.render_files(config)
            except Exception:
                raise ConfigPreflightError(
                    "render preflight failed; configuration not saved",
                ) from None
        content = yaml.safe_dump(raw, sort_keys=False, allow_unicode=False)
        if path.resolve() != target:
            raise ConfigVersionConflict("configuration source alias changed; retry")
        (file_manager or FileManager()).atomic_write_text(target, content, mode=0o600)
        # Keep the lock until state installation and runtime writes complete.
        # Never reload after persistence: the validated candidate is authoritative.
        written: list[str] = []
        try:
            if on_commit is not None:
                on_commit(config)
            if write_rendered:
                written = [str(item) for item in service.write_rendered_files(config)]
            if after_apply is not None:
                after_apply(config)
        except Exception:
            raise ConfigApplyError() from None
        return config, written
