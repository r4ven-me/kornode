"""Agent local files (spec 06 "Local files"): atomic writes, state, trust, bundle cache."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from kornode.bundle.signing import key_id

KEEP_CONFIRMED = 3


class StoreError(RuntimeError):
    pass


def atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Temp file in the same directory, fsync, rename, fsync of the directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Pending(_Model):
    version: int
    started_at: str
    previous: int


class Deferred(_Model):
    version: int
    attempts: int = 1


class LastApply(_Model):
    version: int
    result: str
    at: str
    error: str | None = None


class State(_Model):
    current: int = 0
    confirmed: list[int] = Field(default_factory=list)
    high_water: int = 0
    pending: Pending | None = None
    deferred: Deferred | None = None
    failed: dict[str, str] = Field(default_factory=dict)
    last_apply: LastApply | None = None


class TrustKey(_Model):
    key_id: str
    pubkey_b64: str
    last_version: int = 0  # newest confirmed bundle this key signed
    pending_rotation: bool = False  # joined via next_signing_pubkey, not yet used


class RetiredKey(_Model):
    key: TrustKey
    max_version: int


class Trust(_Model):
    active: list[TrustKey] = Field(default_factory=list)
    retired: list[RetiredKey] = Field(default_factory=list)

    def keys_for(self, version: int | None = None) -> dict[str, Ed25519PublicKey]:
        """New bundles (version None) verify against `active` only; a cached
        bundle also against retired keys with `version <= max_version`."""
        keys = {k.key_id: _load_key(k) for k in self.active}
        if version is not None:
            for retired in self.retired:
                if version <= retired.max_version:
                    keys[retired.key.key_id] = _load_key(retired.key)
        return keys

    def add_active(self, pubkey_b64: str, *, pending_rotation: bool = False) -> None:
        raw = _decode_pubkey(pubkey_b64)
        kid = key_id(raw)
        # A retired key never comes back (e.g. via a locally rolled-back bundle).
        if any(k.key_id == kid for k in self.active) or any(
            r.key.key_id == kid for r in self.retired
        ):
            return
        self.active.append(
            TrustKey(key_id=kid, pubkey_b64=pubkey_b64, pending_rotation=pending_rotation)
        )

    def confirmed(self, signer: str, version: int, next_pubkey_b64: str | None) -> None:
        """Bookkeeping after a bundle is confirmed (spec 06 "Trust store")."""
        for key in self.active:
            if key.key_id == signer:
                key.last_version = max(key.last_version, version)
        current = next((k for k in self.active if k.key_id == signer), None)
        if current is not None and current.pending_rotation:
            current.pending_rotation = False
            for other in [k for k in self.active if k.key_id != signer]:
                self.retired.append(RetiredKey(key=other, max_version=other.last_version))
            self.active = [current]
        if next_pubkey_b64:
            self.add_active(next_pubkey_b64, pending_rotation=True)


def _decode_pubkey(pubkey_b64: str) -> bytes:
    try:
        raw = base64.b64decode(pubkey_b64, validate=True)
    except ValueError as exc:
        raise StoreError("signing key is not base64") from exc
    if len(raw) != 32:
        raise StoreError("signing key must be 32 bytes")
    return raw


def _load_key(key: TrustKey) -> Ed25519PublicKey:
    raw = _decode_pubkey(key.pubkey_b64)
    if key_id(raw) != key.key_id:
        raise StoreError(f"signing key id {key.key_id} does not match its key")
    return Ed25519PublicKey.from_public_bytes(raw)


def trust_from_enroll(signing_keys: list[dict[str, str]]) -> Trust:
    trust = Trust()
    for item in signing_keys:
        key = TrustKey(key_id=item["key_id"], pubkey_b64=item["pubkey_b64"])
        _load_key(key)  # validates the claimed id
        trust.active.append(key)
    if not trust.active:
        raise StoreError("enroll result carries no signing key")
    return trust


@dataclass(frozen=True)
class CachedBundle:
    version: int
    body: bytes
    signature: str


class Store:
    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def state_path(self) -> Path:
        return self.root / "state.json"

    @property
    def trust_path(self) -> Path:
        return self.root / "trust.json"

    @property
    def bundles(self) -> Path:
        return self.root / "bundles"

    def _read_model(self, path: Path, model: type[Any]) -> Any:
        try:
            return model.model_validate_json(path.read_bytes())
        except FileNotFoundError:
            return model()
        except (ValidationError, ValueError) as exc:
            raise StoreError(f"{path.name} is corrupt: {exc}") from exc

    def load_state(self) -> State:
        state: State = self._read_model(self.state_path, State)
        return state

    def quarantine_state(self) -> Path:
        """Move a corrupt state file aside (kept for diagnosis, never deleted)."""
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        target = self.state_path.with_name(f"{self.state_path.name}.corrupt-{stamp}")
        os.replace(self.state_path, target)
        return target

    def save_state(self, state: State) -> None:
        atomic_write(self.state_path, state.model_dump_json(indent=1).encode(), 0o600)

    def load_trust(self) -> Trust:
        trust: Trust = self._read_model(self.trust_path, Trust)
        return trust

    def save_trust(self, trust: Trust) -> None:
        atomic_write(self.trust_path, trust.model_dump_json(indent=1).encode(), 0o600)

    def write_bundle(self, version: int, body: bytes, signature: str) -> None:
        atomic_write(self.bundles / f"{version}.json", body, 0o600)
        atomic_write(self.bundles / f"{version}.sig", signature.encode("ascii"), 0o600)

    def read_bundle(self, version: int) -> CachedBundle | None:
        try:
            body = (self.bundles / f"{version}.json").read_bytes()
            signature = (self.bundles / f"{version}.sig").read_text(encoding="ascii").strip()
        except OSError:
            return None
        return CachedBundle(version, body, signature)

    def cached_versions(self) -> list[int]:
        found: list[int] = []
        if self.bundles.is_dir():
            for path in self.bundles.glob("*.json"):
                with contextlib.suppress(ValueError):
                    found.append(int(path.stem))
        return sorted(found, reverse=True)

    def prune(self, state: State) -> None:
        """Drop cached bodies that are neither confirmed, current nor pending."""
        keep = set(state.confirmed[:KEEP_CONFIRMED]) | {state.current}
        if state.pending is not None:
            keep |= {state.pending.version, state.pending.previous}
        if state.deferred is not None:
            keep.add(state.deferred.version)
        for version in self.cached_versions():
            if version not in keep:
                for suffix in ("json", "sig"):
                    (self.bundles / f"{version}.{suffix}").unlink(missing_ok=True)


def dumps(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
