from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kornode.bundle.signing import key_id, raw_public_bytes
from kornode_agent.store import (
    Pending,
    State,
    Store,
    StoreError,
    Trust,
    atomic_write,
    trust_from_enroll,
)


def _pub() -> tuple[Ed25519PrivateKey, str, str]:
    key = Ed25519PrivateKey.generate()
    raw = raw_public_bytes(key.public_key())
    return key, key_id(raw), base64.b64encode(raw).decode()


def test_atomic_write_is_private_and_leaves_no_temp_files(tmp_path: Path) -> None:
    target = tmp_path / "d" / "f"
    atomic_write(target, b"one", 0o600)
    atomic_write(target, b"two", 0o600)
    assert target.read_bytes() == b"two"
    assert os.stat(target).st_mode & 0o777 == 0o600
    assert [p.name for p in target.parent.iterdir()] == ["f"]


def test_state_round_trip_and_corruption(tmp_path: Path) -> None:
    store = Store(tmp_path)
    assert store.load_state() == State()
    state = State(
        current=2,
        confirmed=[2, 1],
        high_water=3,
        pending=Pending(version=3, started_at="t", previous=2),
    )
    store.save_state(state)
    assert store.load_state() == state
    (tmp_path / "state.json").write_text("{nope")
    with pytest.raises(StoreError):
        store.load_state()


def test_prune_keeps_three_confirmed_current_and_pending(tmp_path: Path) -> None:
    store = Store(tmp_path)
    for version in range(1, 8):
        store.write_bundle(version, b"{}", "sig")
    state = State(
        current=6,
        confirmed=[6, 5, 4, 3],
        pending=Pending(version=7, started_at="t", previous=6),
    )
    store.prune(state)
    assert store.cached_versions() == [7, 6, 5, 4]
    assert store.read_bundle(5) is not None and store.read_bundle(2) is None


def test_trust_scopes_retired_keys_by_version() -> None:
    _, old_id, old_b64 = _pub()
    _, new_id, new_b64 = _pub()
    trust = trust_from_enroll([{"key_id": old_id, "pubkey_b64": old_b64}])
    trust.confirmed(old_id, 5, new_b64)  # confirmed bundle announces the next key
    assert set(trust.keys_for()) == {old_id, new_id}

    trust.confirmed(new_id, 6, None)  # first bundle under the new key
    assert set(trust.keys_for()) == {new_id}
    assert set(trust.keys_for(5)) == {new_id, old_id}  # cached, within max_version
    assert set(trust.keys_for(6)) == {new_id}


def test_trust_rejects_mismatched_key_id_and_empty_result() -> None:
    _, _, b64 = _pub()
    with pytest.raises(StoreError):
        trust_from_enroll([{"key_id": "0" * 16, "pubkey_b64": b64}])
    with pytest.raises(StoreError):
        trust_from_enroll([])
    with pytest.raises(StoreError):
        Trust().add_active("not base64!")


def test_a_retired_key_is_never_readded_by_an_old_bundle() -> None:
    _, old_id, old_b64 = _pub()
    _, new_id, new_b64 = _pub()
    trust = trust_from_enroll([{"key_id": old_id, "pubkey_b64": old_b64}])
    trust.confirmed(old_id, 5, new_b64)
    trust.confirmed(new_id, 6, None)  # old key retired
    trust.confirmed(old_id, 4, new_b64)  # local rollback to a bundle announcing it again
    trust.add_active(old_b64)
    assert [k.key_id for k in trust.active] == [new_id]
