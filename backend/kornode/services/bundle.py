"""Hub-side bundle compiler (spec 05 "Compilation", D-34..D-38).

`compile_node` / `compile_all` run on the caller's registry connection and
therefore inside the caller's transaction: a refused bundle rolls the
mutation back, and `desired_version` never points at a missing bundle.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from kornode.bundle.canonical import body_sha256, canonical_json, content_hash
from kornode.bundle.errors import BundleError
from kornode.bundle.sealing import SECRET_MARKER, digest_secrets, seal_secrets
from kornode.bundle.signing import (
    key_id,
    load_or_create_signing_key,
    raw_public_bytes,
    sign,
)
from kornode.bundle.validator import validate
from kornode.config.models import AppConfig
from kornode.config.reserved import DEFAULT_CONTROL_PORT
from kornode.net.addressing import derive_addresses
from kornode.registry.models import Node, StoredBundle
from kornode.registry.repository import Registry
from kornode.services.cert_pin import certificate_file_pin

MIN_AGENT_VERSION = "2.0.0"
BUNDLE_HISTORY = 20
HUB_NODE_ID = 1
_FABRIC_RULE_ID = "to-fabric"
_SECRET_UPSTREAM_FIELDS = ("password", "key", "camouflage")


class BundleService:
    def __init__(
        self,
        config: AppConfig,
        *,
        clock: Callable[[], datetime] | None = None,
        hub_pin: str | None = None,
    ) -> None:
        self.config = config
        self._clock = clock or (lambda: datetime.now(UTC))
        self._hub_pin = hub_pin

    # ------------------------------------------------------------------ keys

    @property
    def control_dir(self) -> Path:
        return self.config.system.data_dir / "control"

    def signing_key(self) -> Ed25519PrivateKey:
        return load_or_create_signing_key(self.control_dir / "signing.ed25519")

    def signing_keys(self) -> list[dict[str, str]]:
        public = self.signing_key().public_key()
        return [
            {
                "key_id": key_id(public),
                "pubkey_b64": base64.b64encode(raw_public_bytes(public)).decode("ascii"),
            }
        ]

    def master_key(self) -> bytes:
        path = self.control_dir / "master.key"
        if not path.exists():
            self.control_dir.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(f".master.key.{secrets.token_hex(6)}.tmp")
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(secrets.token_bytes(32))
                handle.flush()
                os.fsync(handle.fileno())
            with contextlib.suppress(FileExistsError):
                os.link(tmp, path)
            tmp.unlink()
        key = path.read_bytes()
        if len(key) != 32:
            raise BundleError("internal", "hub master key is corrupt")
        return key

    def encrypt_external_secrets(self, node_id: int, name: str, values: dict[str, str]) -> bytes:
        nonce = secrets.token_bytes(12)
        aad = _external_aad(node_id, name)
        payload = json.dumps(values, sort_keys=True).encode()
        return nonce + ChaCha20Poly1305(self.master_key()).encrypt(nonce, payload, aad)

    def _decrypt_external_secrets(self, node_id: int, name: str, blob: bytes) -> dict[str, str]:
        try:
            raw = ChaCha20Poly1305(self.master_key()).decrypt(
                blob[:12], blob[12:], _external_aad(node_id, name)
            )
        except Exception as exc:  # InvalidTag and friends: never echo material
            raise BundleError("internal", f"cannot decrypt secrets of {name!r}") from exc
        data = json.loads(raw)
        return {str(key): str(value) for key, value in data.items()}

    # --------------------------------------------------------------- compile

    def compile_all(self, registry: Registry, reason: str) -> dict[int, StoredBundle]:
        result: dict[int, StoredBundle] = {}
        for node in registry.list_nodes():
            if node.state == "active" and node.seal_pubkey is not None:
                result[node.id] = self.compile_node(registry, node.id, reason)
        return result

    def compile_node(self, registry: Registry, node_id: int, reason: str) -> StoredBundle:
        node = registry.get_node(node_id)
        if node.state != "active" or node.seal_pubkey is None:
            raise BundleError("conflict", f"node {node_id} is not an active enrolled agent")
        latest = registry.latest_bundle(node_id)
        version = (
            max(latest.version if latest else 0, node.desired_version, node.high_water_version) + 1
        )
        plan = self._plan(registry, node, version)
        # The recipient key is part of the content: a rotated seal key must
        # produce a new bundle, not the old one sealed to the previous key.
        digest = content_hash(
            {
                **digest_secrets(plan, self.master_key(), node.id),
                "_seal_pubkey": node.seal_pubkey.hex(),
            }
        )
        if latest is not None and latest.content_hash == digest:
            if node.desired_version != latest.version:
                registry.update_node(node_id, desired_version=latest.version)
            return latest
        wire = seal_secrets(plan, node.seal_pubkey, node.id)
        body = canonical_json(wire)
        key = self.signing_key()
        signature = sign(body, key)
        trusted = {key_id(key.public_key()): key.public_key()}
        try:
            validate(
                body,
                signature,
                trusted=trusted,
                high_water_version=version - 1,
                agent_version=MIN_AGENT_VERSION,
                expected_node_id=node_id,
            )
        except BundleError as exc:
            raise BundleError("invalid", f"node {node_id}: {exc.code}: {exc.message}") from exc
        stored = registry.add_bundle(
            node_id=node_id,
            version=version,
            body=body,
            signature=signature,
            sha256=body_sha256(body),
            content_hash=digest,
            key_id=key_id(key.public_key()),
            reason=reason,
        )
        registry.update_node(node_id, desired_version=version)
        registry.prune_bundles(node_id, BUNDLE_HISTORY)
        return stored

    # ------------------------------------------------------------------ plan

    def _plan(self, registry: Registry, node: Node, version: int) -> dict[str, Any]:
        fabric = self.config.fabric
        addresses = derive_addresses(
            node.id,
            fabric_cidr=fabric.cidr,
            client_pool=fabric.client_pool,
            source_pool=fabric.source_pool,
            domain=fabric.domain,
        )
        hub = derive_addresses(
            HUB_NODE_ID,
            fabric_cidr=fabric.cidr,
            client_pool=fabric.client_pool,
            source_pool=fabric.source_pool,
            domain=fabric.domain,
        )
        node_info: dict[str, Any] = {
            "name": node.name,
            "roles": sorted(node.roles),
            "fabric_address": str(addresses.fabric_address),
            "service_address": str(addresses.service_address),
            "client_pool": str(addresses.client_pool),
            "source_range": str(addresses.source_pool),
            "uplink_hint": "auto",
        }
        prefixes: list[dict[str, Any]] = [
            {"prefix": fabric.cidr, "node_id": HUB_NODE_ID, "kind": "fabric"},
            {"prefix": str(hub.client_pool), "node_id": HUB_NODE_ID, "kind": "pool"},
        ]
        for other in registry.list_nodes():
            if other.id == node.id or other.state != "active":
                continue
            prefixes.extend(
                {"prefix": item.prefix, "node_id": item.node_id, "kind": item.kind}
                for item in registry.list_prefixes(other.id)
                if item.export
            )
        prefixes.sort(key=lambda item: (item["node_id"], item["prefix"]))
        transport = node.transport
        fabric_tunnel: dict[str, Any] = {
            "interface": "oc-hub0",
            "transport": transport.get("transport", "tcp"),
        }
        for field in ("dpd", "keepalive"):
            if field in transport:
                fabric_tunnel[field] = int(transport[field])
        if transport.get("camouflage"):
            fabric_tunnel["camouflage"] = {SECRET_MARKER: str(transport["camouflage"])}
        return {
            "format": "kornode.bundle/v1",
            "node_id": node.id,
            "version": version,
            "generated_at": self._clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "min_agent_version": MIN_AGENT_VERSION,
            "hubs": [
                {
                    "host": self.config.server.cn,
                    "port": self.config.server.port,
                    "pin": self._pin(),
                    "control_url": f"https://{hub.fabric_address}:{DEFAULT_CONTROL_PORT}",
                }
            ],
            "node": node_info,
            "fabric": {"cidr": fabric.cidr, "domain": fabric.domain, "prefixes": prefixes},
            "tunnels": {
                "fabric": fabric_tunnel,
                "upstreams": self._upstreams(registry, node.id),
            },
            "policy": _policy_with_fabric_rule(node.policy),
            "settings": {
                "report_interval_seconds": 30,
                "confirm_window_seconds": 60,
                "log_level": "info",
            },
        }

    def _pin(self) -> str:
        if self._hub_pin is not None:
            return self._hub_pin
        return certificate_file_pin(self.config.cert_path("server.crt")).pin

    def _upstreams(self, registry: Registry, node_id: int) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for external in registry.list_externals(node_id):
            item: dict[str, Any] = {**external.spec, "name": external.name}
            if external.secrets:
                values = self._decrypt_external_secrets(node_id, external.name, external.secrets)
                for field in _SECRET_UPSTREAM_FIELDS:
                    if field in values:
                        item[field] = {SECRET_MARKER: values[field]}
            result.append(item)
        return result


def _external_aad(node_id: int, name: str) -> bytes:
    return f"kornode-external-secrets-v1|{node_id}|{name}".encode()


def _policy_with_fabric_rule(policy: dict[str, Any]) -> dict[str, Any]:
    """A bundle must keep the agent's path to the hub (spec 11): add the
    fabric rule when the operator's policy has none."""
    result: dict[str, Any] = json.loads(json.dumps(policy))
    result.setdefault("sources", [])
    result.setdefault("sets", {})
    rules = result.setdefault("egress", [])
    if not any(rule.get("via") == "fabric" for rule in rules):
        names = ["clients", "host", *(item["name"] for item in result["sources"])]
        taken = {rule.get("id") for rule in rules}
        rule_id = _FABRIC_RULE_ID
        while rule_id in taken:
            rule_id += "-hub"
        rules.insert(0, {"id": rule_id, "from": names, "to": "fabric", "via": "fabric"})
    return result
