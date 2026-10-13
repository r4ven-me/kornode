from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from kornode.bundle.errors import BundleError
from kornode.bundle.sealing import public_bytes, walk_sealed
from kornode.bundle.signing import key_id
from kornode.bundle.validator import validate
from kornode.config.models import AppConfig
from kornode.registry.db import migrate, open_registry, transaction
from kornode.registry.repository import Registry
from kornode.services.bundle import BUNDLE_HISTORY, BundleService

PIN = "pin-sha256:" + "A" * 43 + "="


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.config = AppConfig.model_validate(
            {
                "system": {
                    "data_dir": tmp_path / "data",
                    "generated_dir": tmp_path / "generated",
                    "log_dir": tmp_path / "logs",
                    "secrets_dir": tmp_path / "secrets",
                },
                "fabric": {"enabled": True},
                "auth": {"password": {"enabled": True}},
            }
        )
        conn = open_registry(self.config.system.data_dir / "registry.db")
        migrate(conn)
        self.registry = Registry(conn)
        self.private = X25519PrivateKey.generate()
        self.service = BundleService(self.config, hub_pin=PIN)

    def add(self, node_id: int, *, active: bool = True, **kwargs: Any) -> None:
        self.registry.create_node(
            id=node_id,
            name=f"node{node_id}",
            state="active" if active else "pending",
            seal_pubkey=public_bytes(self.private.public_key()) if active else None,
            **kwargs,
        )

    def compile(self, node_id: int, reason: str = "test") -> Any:
        with transaction(self.registry.conn):
            return self.service.compile_node(self.registry, node_id, reason)

    def check(self, stored: Any, high_water: int = 0) -> Any:
        key = self.service.signing_key()
        return validate(
            stored.body,
            stored.signature,
            trusted={key_id(key.public_key()): key.public_key()},
            high_water_version=high_water,
            agent_version="2.0.0",
            expected_node_id=stored.node_id,
            seal_private_key=self.private,
        )


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def test_compile_produces_valid_signed_bundle(env: Env) -> None:
    env.add(3)
    stored = env.compile(3)

    result = env.check(stored)
    assert stored.version == 1
    assert env.registry.get_node(3).desired_version == 1
    assert result.bundle.node.fabric_address == "10.99.0.3"
    assert result.bundle.node.client_pool == "10.100.3.0/24"
    assert result.bundle.hubs[0].pin == PIN
    assert result.bundle.hubs[0].control_url == "https://10.99.0.1:8444"
    assert result.bundle.policy.egress[0].via == "fabric"
    kinds = {(p.node_id, p.kind) for p in result.bundle.fabric.prefixes}
    assert kinds == {(1, "fabric"), (1, "pool")}


def test_unchanged_input_is_deduplicated(env: Env) -> None:
    env.add(3)
    first = env.compile(3)
    second = env.compile(3)

    assert second.version == first.version
    assert len(env.registry.list_bundles(3)) == 1


def test_change_creates_next_version_and_other_nodes_prefixes_appear(env: Env) -> None:
    env.add(2)
    env.add(3)
    first = env.compile(3)
    env.registry.set_prefixes(2, [{"prefix": "192.168.2.0/24", "kind": "lan"}])
    second = env.compile(3, "prefixes")

    assert second.version == first.version + 1
    prefixes = {p.prefix for p in env.check(second).bundle.fabric.prefixes}
    assert "192.168.2.0/24" in prefixes


def test_version_stays_above_high_water_mark(env: Env) -> None:
    env.add(3)
    env.compile(3)
    env.registry.update_node(3, high_water_version=50)
    env.registry.set_prefixes(3, [{"prefix": "192.168.3.0/24", "kind": "lan"}])
    # a node's own prefixes are not in its bundle; change policy instead
    env.registry.update_node(3, transport={"dpd": 30})
    stored = env.compile(3)

    assert stored.version == 51


def test_upstream_secrets_are_sealed_per_value(env: Env) -> None:
    env.add(3)
    spec = {
        "interface": "oc-office",
        "server": "office.example.org",
        "port": 443,
        "auth_type": "password",
        "username": "node3",
    }
    blob = env.service.encrypt_external_secrets(3, "office", {"password": "hunter2-secret"})
    env.registry.set_external(3, "office", spec, blob)
    env.registry.update_node(
        3,
        policy={
            "egress": [{"from": ["clients"], "to": "any", "via": "upstream:office"}],
        },
    )
    stored = env.compile(3)

    assert b"hunter2-secret" not in stored.body
    result = env.check(stored)
    assert result.secrets == {"/tunnels/upstreams/0/password": "hunter2-secret"}
    assert [p for p, _ in walk_sealed(json.loads(stored.body))] == ["/tunnels/upstreams/0/password"]


def test_resealing_does_not_create_new_version(env: Env) -> None:
    env.add(3)
    spec = {"interface": "oc-o", "server": "o.example.org", "port": 443, "auth_type": "password"}
    env.registry.set_external(
        3, "office", spec, env.service.encrypt_external_secrets(3, "office", {"password": "pw"})
    )
    env.registry.update_node(
        3, policy={"egress": [{"from": ["clients"], "to": "any", "via": "upstream:office"}]}
    )
    first = env.compile(3)

    assert env.compile(3).version == first.version


def test_invalid_output_is_refused_and_rolled_back(env: Env) -> None:
    env.add(3)
    with pytest.raises(BundleError) as bad, transaction(env.registry.conn):
        # the mutation precedes the failing compile and must be undone with it
        env.registry.update_node(
            3, policy={"egress": [{"from": ["clients"], "to": "any", "via": "upstream:ghost"}]}
        )
        env.service.compile_node(env.registry, 3, "test")

    assert bad.value.code == "invalid"
    assert env.registry.get_node(3).policy == {}
    assert env.registry.list_bundles(3) == []
    assert env.registry.get_node(3).desired_version == 0


def test_fabric_rule_id_does_not_clash_with_operator_rule(env: Env) -> None:
    env.add(3)
    env.registry.update_node(
        3,
        policy={"egress": [{"id": "to-fabric", "from": ["clients"], "to": "any", "via": "local"}]},
    )

    assert env.check(env.compile(3)).bundle.policy.egress[0].via == "fabric"


def test_compile_refuses_unenrolled_node(env: Env) -> None:
    env.add(3, active=False)
    with pytest.raises(BundleError) as bad:
        env.compile(3)
    assert bad.value.code == "conflict"


def test_compile_all_skips_pending_and_revoked_nodes(env: Env) -> None:
    env.add(2)
    env.add(3, active=False)
    with transaction(env.registry.conn):
        result = env.service.compile_all(env.registry, "test")

    assert set(result) == {2}


def test_history_is_pruned(env: Env) -> None:
    env.add(3)
    for index in range(BUNDLE_HISTORY + 3):
        env.registry.update_node(3, transport={"dpd": 10 + index})
        env.compile(3)

    versions = [item.version for item in env.registry.list_bundles(3)]
    assert len(versions) == BUNDLE_HISTORY
    assert versions[0] == BUNDLE_HISTORY + 3


def test_master_and_signing_keys_are_private(env: Env) -> None:
    env.service.master_key()
    env.service.signing_key()
    for name in ("master.key", "signing.ed25519"):
        path = env.config.system.data_dir / "control" / name
        assert path.stat().st_mode & 0o777 == 0o600


def test_rotated_seal_key_produces_new_version(env: Env) -> None:
    env.add(3)
    first = env.compile(3)
    env.private = X25519PrivateKey.generate()
    env.registry.update_node(3, seal_pubkey=public_bytes(env.private.public_key()))
    second = env.compile(3)

    assert second.version == first.version + 1
    env.check(second)
