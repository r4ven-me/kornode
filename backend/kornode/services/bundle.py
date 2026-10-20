"""Hub-side bundle compiler (spec 05 "Compilation", D-34..D-38).

`compile_node` / `compile_all` run on the caller's registry connection and
therefore inside the caller's transaction: a refused bundle rolls the
mutation back, and `desired_version` never points at a missing bundle.
"""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import json
import os
import secrets
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
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
from kornode.net.addressing import derive_addresses
from kornode.registry.models import Node, StoredBundle
from kornode.registry.repository import Registry
from kornode.tunnels.pin import certificate_file_pin

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

    def _signing_path(self) -> Path:
        return self.config.control.signing_key or self.control_dir / "signing.ed25519"

    def rotation(self, registry: Registry | None = None) -> dict[str, Any] | None:
        if registry is not None:
            return registry.rotation()
        path = self.config.system.data_dir / "registry.db"
        if not path.exists():
            return None
        with contextlib.closing(sqlite3.connect(path)) as conn:
            conn.row_factory = sqlite3.Row
            if not conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'control_rotation'"
            ).fetchone():
                return None
            return Registry(conn).rotation()

    def key_plan(self, registry: Registry | None = None) -> tuple[Path, str | None]:
        rotation = self.rotation(registry)
        if rotation is None:
            return self._signing_path(), None
        deadline = datetime.fromisoformat(
            rotation["started_at"].replace("Z", "+00:00")
        ) + timedelta(days=7)
        active, upcoming = Path(rotation["active_path"]), Path(rotation["next_path"])
        if not active.is_file() or not upcoming.is_file():
            raise BundleError(
                "internal", "rotation key file is missing; restore keys before continuing"
            )
        if self._clock() >= deadline:
            return upcoming, None
        public = load_or_create_signing_key(upcoming).public_key()
        return active, base64.b64encode(raw_public_bytes(public)).decode()

    def signing_key(self, registry: Registry | None = None) -> Ed25519PrivateKey:
        path, _ = self.key_plan(registry)
        return load_or_create_signing_key(path)

    def refresh_rotation(self, registry: Registry, node_id: int) -> None:
        if registry.rotation() is None:
            return
        latest = registry.latest_bundle(node_id)
        _, announcement = self.key_plan(registry)
        signer = key_id(self.signing_key(registry).public_key())
        if (
            latest
            and latest.key_id == signer
            and json.loads(latest.body).get("next_signing_pubkey") == announcement
        ):
            return
        from kornode.registry.db import transaction

        with (
            contextlib.nullcontext() if registry.conn.in_transaction else transaction(registry.conn)
        ):
            self.compile_node(registry, node_id, "signing key rotation")

    def control_url(self) -> str:
        """The control API as an agent reaches it: the hub's fabric address."""
        fabric = self.config.fabric
        hub = derive_addresses(
            HUB_NODE_ID,
            fabric_cidr=fabric.cidr,
            client_pool=fabric.client_pool,
            source_pool=fabric.source_pool,
            domain=fabric.domain,
        )
        return f"https://{hub.fabric_address}:{self.config.control.port}"

    def signing_keys(self) -> list[dict[str, str]]:
        public = self.signing_key().public_key()
        keys = [
            {
                "key_id": key_id(public),
                "pubkey_b64": base64.b64encode(raw_public_bytes(public)).decode("ascii"),
            }
        ]
        _, announcement = self.key_plan()
        if announcement:
            raw = base64.b64decode(announcement)
            keys.append({"key_id": key_id(raw), "pubkey_b64": announcement})
        return keys

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

    def compile_node(
        self, registry: Registry, node_id: int, reason: str, *, force: bool = False
    ) -> StoredBundle:
        """`force` skips content dedup: recovery after the agent reported a
        version above everything stored needs a fresh, higher version."""
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
                "_signing_key_id": key_id(self.signing_key(registry).public_key()),
            }
        )
        if not force and latest is not None and latest.content_hash == digest:
            if node.desired_version != latest.version:
                registry.update_node(node_id, desired_version=latest.version)
            return latest
        wire = seal_secrets(plan, node.seal_pubkey, node.id)
        body = canonical_json(wire)
        key = self.signing_key(registry)
        signature = sign(body, key)
        trusted = {key_id(key.public_key()): key.public_key()}
        try:
            validate(
                body,
                signature,
                trusted=trusted,
                high_water_version=version - 1,
                agent_version=self.config.control.min_agent_version,
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
        registry.prune_bundles(node_id, self.config.control.bundle_history)
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
        camouflage = transport.get("camouflage")
        if transport.get("camouflage_enc"):
            camouflage = self._decrypt_external_secrets(
                node.id, "fabric-transport", base64.b64decode(transport["camouflage_enc"])
            )["camouflage"]
        if camouflage:
            fabric_tunnel["camouflage"] = {SECRET_MARKER: str(camouflage)}
        plan = {
            "format": "kornode.bundle/v1",
            "node_id": node.id,
            "version": version,
            "generated_at": self._clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "min_agent_version": self.config.control.min_agent_version,
            "hubs": [
                {
                    "host": self.config.server.cn,
                    "port": self.config.server.port,
                    "pin": self._pin(),
                    "control_url": self.control_url(),
                }
            ],
            "node": node_info,
            "fabric": {"cidr": fabric.cidr, "domain": fabric.domain, "prefixes": prefixes},
            "tunnels": {
                "fabric": fabric_tunnel,
                "upstreams": self._upstreams(registry, node.id),
            },
            "policy": _policy_with_fabric_rule(node.policy, node.roles),
            "dns": self._dns(registry, node.id, hub.client_pool),
            **self._access(registry, node),
            "settings": {
                "report_interval_seconds": self.config.control.report_interval_seconds,
                "confirm_window_seconds": 60,
                "log_level": "info",
            },
        }
        _, announcement = self.key_plan(registry)
        if announcement:
            plan["next_signing_pubkey"] = announcement
        return plan

    def _access(self, registry: Registry, node: Node) -> dict[str, Any]:
        """`access` only for role `access` with a configured listener (D-67).
        Users travel as ocpasswd hashes; the server key is sealed to the
        agent. Password authentication only in P4-04."""
        access = node.access
        if "access" not in node.roles or not access.get("cert_pem"):
            return {}
        key = self._decrypt_external_secrets(
            node.id, "access-server", base64.b64decode(access["key_enc"])
        )["key"]
        users = [
            {
                "username": user["username"],
                "pw_hash": user["pw_hash"],
                "groups": list(user["groups"]),
                "enabled": bool(user["enabled"]),
            }
            for user in registry.access_users(node.id)
            if user["pw_hash"]
        ]
        return {
            "access": {
                "port": int(access["port"]),
                "udp": bool(access.get("udp", False)),
                "auth": ["password"],
                "ca_pem": self.config.cert_path("ca.crt").read_text(encoding="utf-8"),
                "server_cert_pem": access["cert_pem"],
                "server_key": {SECRET_MARKER: key},
                "users": users,
            }
        }

    def _dns(
        self, registry: Registry, node_id: int, hub_pool: ipaddress.IPv4Network
    ) -> dict[str, Any]:
        """The agent's own `node<id>` zone plus forwarding of the fabric zone
        to the hub resolver (D-66). The resolver must sit in the hub client
        pool, which every bundle routes via the fabric; otherwise the zone is
        not forwarded at all rather than toward an unreachable address."""
        from kornode.services.fabric_dns import node_zone_records

        dns: dict[str, Any] = {
            "enabled": True,
            "local_records": [
                {"name": item.fqdn, "type": item.type, "value": item.value}
                for item in node_zone_records(self.config, registry, node_id)
            ],
        }
        listen = ipaddress.ip_address(self.config.internal_dns.listen)
        if listen in hub_pool:
            dns["forward_zones"] = [{"zone": self.config.fabric.domain, "servers": [str(listen)]}]
        return dns

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


def _policy_with_fabric_rule(policy: dict[str, Any], roles: list[str]) -> dict[str, Any]:
    """A bundle must keep the agent's path to the hub (spec 11): add the
    fabric rule when no rule gives `host` that path.

    VPN clients of an `access` node are not in the implicit rule (D-67): a
    branch user does not get the whole fabric, including the hub's services,
    unless the operator writes `from: [clients] to: fabric via: fabric`."""
    result: dict[str, Any] = json.loads(json.dumps(policy))
    result.setdefault("sources", [])
    result.setdefault("sets", {})
    rules = result.setdefault("egress", [])
    if not any(
        rule.get("via") == "fabric" and "host" in (rule.get("from") or []) for rule in rules
    ):
        names = ["host", *(item["name"] for item in result["sources"])]
        if "access" not in roles:
            names.insert(0, "clients")
        taken = {rule.get("id") for rule in rules}
        rule_id = _FABRIC_RULE_ID
        while rule_id in taken:
            rule_id += "-hub"
        rules.insert(0, {"id": rule_id, "from": names, "to": "fabric", "via": "fabric"})
    return result
