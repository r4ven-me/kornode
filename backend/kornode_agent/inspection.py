"""Read-only cache inspection and output sanitizing, shared by CLI and diagnostics."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from kornode.bundle.errors import BundleError
from kornode.bundle.redaction import Redactor as Redactor
from kornode.bundle.validator import Validated, validate
from kornode_agent import __version__
from kornode_agent.config import load_config
from kornode_agent.enroll import load_seal_key
from kornode_agent.local import LocalError
from kornode_agent.store import Store, StoreError


def load_cached(root: Path, version: int) -> Validated:
    if version < 1:
        raise LocalError("not_cached", "bootstrap state has no bundle", 3)
    store = Store(root)
    cached = store.read_bundle(version)
    if cached is None:
        raise LocalError("not_cached", f"bundle {version} is not cached", 3)
    try:
        validated = validate(
            cached.body,
            cached.signature,
            trusted=store.load_trust().keys_for(version),
            high_water_version=store.load_state().high_water,
            agent_version=__version__,
            expected_node_id=load_config(root).node_id,
            seal_private_key=load_seal_key(root),
            revalidate=True,
        )
        if validated.bundle.version != version:
            raise LocalError("invalid_bundle", "cached version does not match its filename", 3)
        return validated
    except (BundleError, StoreError, ValueError, OSError):
        raise LocalError(
            "invalid_bundle", f"cached bundle {version} failed verification", 3
        ) from None


def cache_redactor(root: Path, extra: Iterable[str] = ()) -> Redactor:
    known = list(extra)
    with contextlib.suppress(StoreError):
        known.append(load_config(root).hub.camouflage or "")
    for version in Store(root).cached_versions():
        with contextlib.suppress(LocalError):
            known.extend(load_cached(root, version).secrets.values())
    return Redactor(known)


def bundle_show(root: Path, version: int | None) -> dict[str, Any]:
    if version is None:
        version = Store(root).load_state().current
    validated = load_cached(root, version)
    result: dict[str, Any] = Redactor(validated.secrets.values()).data(
        validated.bundle.model_dump(mode="json", by_alias=True, exclude_none=True)
    )
    return result


def bundle_history(root: Path) -> dict[str, Any]:
    store = Store(root)
    state = store.load_state()
    versions = set(store.cached_versions()) | set(state.confirmed) | {state.current}
    versions |= {int(v) for v in state.failed if v.isdecimal()}
    if state.pending:
        versions.add(state.pending.version)
    if state.deferred:
        versions.add(state.deferred.version)
    rows = []
    redactor = cache_redactor(root)
    for version in sorted(versions - {0}, reverse=True):
        result = "cached"
        if str(version) in state.failed:
            result = "failed"
        elif state.pending and version == state.pending.version:
            result = "pending"
        elif state.deferred and version == state.deferred.version:
            result = "deferred"
        elif version == state.current:
            result = "current"
        elif version in state.confirmed:
            result = "confirmed"
        rows.append(
            {
                "version": version,
                "result": result,
                "cached": store.read_bundle(version) is not None,
                "error": redactor.text(state.failed.get(str(version), "")) or None,
            }
        )
    return {"current": state.current, "high_water": state.high_water, "bundles": rows}


def offline_status(root: Path) -> dict[str, Any]:
    config = load_config(root)
    state = Store(root).load_state()
    return cast(
        dict[str, Any],
        cache_redactor(root).data(
            {
                "running": False,
                "node_id": config.node_id,
                "applied_version": state.current,
                "pending_version": state.pending.version if state.pending else None,
                "high_water_version": state.high_water,
                "last_apply": state.last_apply.model_dump() if state.last_apply else None,
                "failed_versions": state.failed,
                "hub_reachable": None,
                "tunnels": None,
                "sources": None,
                "reconciler": None,
                "notice": "runtime unavailable; versions from disk, not a live health check",
            }
        ),
    )


def write_archive(path: Path, data: bytes) -> None:
    """Publish atomically without clobbering even a dangling symlink (link, not replace)."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except FileExistsError:
        raise LocalError(
            "output_exists", "output already exists; choose a new --out path", 3
        ) from None
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def safe_json(value: Any, redactor: Redactor) -> bytes:
    return json.dumps(redactor.data(value), indent=1).encode()
