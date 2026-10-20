from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tests.test_bundle_service import Env

from kornode.bundle.signing import key_id, verify
from kornode.services.agent_models import ManagementError
from kornode.services.control_management import ControlManagement


def test_rotation_announces_old_key_then_promotes_and_survives_restart(tmp_path: Path) -> None:
    env = Env(tmp_path)
    clock = [datetime(2026, 10, 16, tzinfo=UTC)]
    env.service._clock = lambda: clock[0]
    env.add(3)
    env.compile(3)
    old = env.service.signing_key().public_key()
    manager = ControlManagement(env.config, bundles=env.service, clock=lambda: clock[0])
    preview = manager.rotate(dry_run=True)
    assert preview["dry_run"] and env.registry.rotation() is None
    result = manager.rotate()
    assert result["rotation"]["phase"] == "announcing"
    announced = env.registry.latest_bundle(3)
    doc = json.loads(announced.body)
    assert "next_signing_pubkey" in doc
    assert verify(announced.body, announced.signature, {key_id(old): old}) == key_id(old)
    with pytest.raises(ManagementError) as exc:
        manager.rotate()
    assert exc.value.status == 409
    clock[0] += timedelta(days=7, seconds=1)
    env.service.refresh_rotation(env.registry, 3)
    promoted = env.registry.latest_bundle(3)
    assert promoted.version > announced.version and promoted.key_id != announced.key_id
    assert "next_signing_pubkey" not in json.loads(promoted.body)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    new = Ed25519PublicKey.from_public_bytes(base64.b64decode(doc["next_signing_pubkey"]))
    verify(promoted.body, promoted.signature, {key_id(new): new})
    assert manager.status()["rotation"]["phase"] == "promoted"
    assert b"PRIVATE KEY" not in json.dumps(manager.status()).encode()
    assert env.service._signing_path().exists()  # old key retained, not overwritten
    assert manager.rotate()["rotation"]["phase"] == "announcing"
    env.registry.conn.close()
