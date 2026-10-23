"""Hub agent management shared by CLI/API. Kernel state is never changed here."""

from __future__ import annotations

import base64
import contextlib
import difflib
import fcntl
import gzip
import io
import ipaddress
import json
import os
import re
import tarfile
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ValidationError

from kornode.bundle.errors import BundleError
from kornode.bundle.redaction import Redactor
from kornode.config.models import AppConfig
from kornode.net.addressing import LocalNetwork, OwnedPrefix, check_overlaps, derive_addresses
from kornode.net.compile import (
    NodeFacts,
    SourceFact,
    TunnelFact,
    compile_policy,
    gateway_tunnels,
)
from kornode.net.errors import NetError
from kornode.net.model import NAME_PATTERN, EgressPolicy, InlineDest, SetRef, Source
from kornode.registry.db import migrate, open_registry, transaction
from kornode.registry.models import Node, iso_time
from kornode.registry.repository import Registry, RegistryConflict, RegistryNotFound
from kornode.services.agent_models import (
    AccessInput,
    AccessUserInput,
    AgentCreate,
    AgentPatch,
    ExternalInput,
    ManagementError,
    PrefixInput,
    username,
)
from kornode.services.audit import AuditService
from kornode.services.bundle import BundleService
from kornode.services.command import CommandRunner
from kornode.services.enrollment import EnrollmentError, EnrollmentService
from kornode.services.interlink_groups import InterlinkGroupsService
from kornode.services.sessions import SessionService
from kornode.tunnels.pin import certificate_pin, pem_to_der

ACCESS_CERT_DAYS = 825

RUNTIME_GAPS = {
    "access": True,
    "gateway": True,
    "routed_prefixes": True,
    "domain_sets": False,
    "p12": False,
    "accept_server_routes": False,
}


DIAG_MEMBER_RE = re.compile(r"^(logs/)?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIAG_MAX_UNPACKED = 32 * 1024 * 1024
DIAG_MAX_MEMBERS = 64


def _valid_diag_archive(raw: bytes) -> bool:
    """A diagnostic archive is a tar.gz of regular files with flat safe names,
    unpacking to a bounded size; anything else must never reach an operator."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            data = stream.read(DIAG_MAX_UNPACKED + 1)
        if len(data) > DIAG_MAX_UNPACKED:
            return False
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            members = archive.getmembers()
    except (OSError, EOFError, tarfile.TarError):
        return False
    return 0 < len(members) <= DIAG_MAX_MEMBERS and all(
        member.isreg() and ".." not in member.name and DIAG_MEMBER_RE.match(member.name)
        for member in members
    )


def parse[M: BaseModel](model: type[M], data: Any) -> M:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        fields = [".".join(map(str, error["loc"])) for error in exc.errors()]
        raise ManagementError(422, "invalid", "invalid management request", fields) from None


class AgentService:
    def __init__(
        self,
        config: AppConfig,
        *,
        bundles: BundleService | None = None,
        enrollment: Any = None,
        sync: Callable[[], Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        password_hasher: Callable[[str], str] | None = None,
    ) -> None:
        self.config = config
        self.clock = clock or (lambda: datetime.now(UTC))
        self.bundles = bundles or BundleService(config, clock=self.clock)
        self.enrollment = enrollment or EnrollmentService(
            config, clock=self.clock, reload_ocserv=self._reload_ocserv
        )
        self.sync = sync or self._sync_hub
        self.password_hasher = password_hasher or self._hash_password
        self.audit = AuditService(config)

    @contextmanager
    def registry(self) -> Iterator[Registry]:
        conn = open_registry(self.config.system.data_dir / "registry.db")
        try:
            migrate(conn)
            yield Registry(conn)
        except RegistryNotFound:
            raise ManagementError(404, "not_found", "agent or resource not found") from None
        except RegistryConflict:
            raise ManagementError(409, "conflict", "registry conflict") from None
        except (BundleError, NetError):
            raise ManagementError(
                409, "invalid_policy", "mutation would produce an invalid bundle"
            ) from None
        finally:
            conn.close()

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        path = self.config.system.data_dir / "control" / "management.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+b") as handle:
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ManagementError(
                            409, "busy", "another management mutation is running"
                        ) from None
                    time.sleep(0.05)
            yield

    @staticmethod
    def node(registry: Registry, name: str) -> Node:
        node = registry.get_node_by_name(name)
        if node.id == 1:
            raise ManagementError(409, "hub_reserved", "node 1 is the hub, not an agent")
        return node

    def _sync_hub(self) -> None:
        """ocserv group/user files, then the hub zone (`node<N>` names, D-66)."""
        from kornode.services.interlink_dns import InterlinkDnsService

        InterlinkGroupsService(self.config, reload_ocserv=self._reload_ocserv).sync()
        InterlinkDnsService(self.config, agents=self).sync()

    def _synced(self) -> None:
        try:
            self.sync()
        except Exception:
            raise ManagementError(
                503,
                "sync_failed",
                "registry committed; ocserv files need synchronization",
                {"committed": True, "recovery": "korctl registry maintain"},
            ) from None

    def _view(self, node: Node) -> dict[str, Any]:
        data = asdict(node)
        data.pop("seal_pubkey")
        data.pop("policy")
        data["access"] = self._access_view(node)
        data["transport"] = {
            key: value for key, value in node.transport.items() if "camouflage" not in key
        }
        data["transport"]["camouflage_set"] = bool(
            node.transport.get("camouflage") or node.transport.get("camouflage_enc")
        )
        try:
            last = (
                datetime.fromisoformat(node.last_seen.replace("Z", "+00:00"))
                if node.last_seen
                else None
            )
            online = (
                last is not None
                and (self.clock() - last).total_seconds()
                <= self.config.control.offline_after_seconds
            )
        except (ValueError, TypeError):
            online = False
        data["online"] = online and node.state == "active"
        data["runtime_support"] = RUNTIME_GAPS
        return data

    def list(self) -> dict[str, Any]:
        with self.registry() as r:
            return {"agents": [self._view(n) for n in r.list_nodes() if n.id != 1]}

    def show(self, name: str) -> dict[str, Any]:
        with self.registry() as r:
            node = self.node(r, name)
            return {**self._view(node), "prefixes": [asdict(p) for p in r.list_prefixes(node.id)]}

    def create(self, payload: AgentCreate) -> dict[str, Any]:
        with self.exclusive():
            with self.registry() as r, transaction(r.conn):
                occupied = {n.id for n in r.list_nodes()} | {1}
                quarantine = r.quarantined_ids(iso_time(self.clock()))
                candidate = payload.id or next(
                    (i for i in range(2, 255) if i not in occupied | quarantine), None
                )
                if (
                    candidate is None
                    or candidate in occupied
                    or (candidate in quarantine and not payload.force_reuse)
                ):
                    raise ManagementError(
                        409, "id_unavailable", "node id is occupied, quarantined or exhausted"
                    )
                if any(n.name == payload.name for n in r.list_nodes()):
                    raise ManagementError(409, "name_exists", "agent name already exists")
                if payload.dry_run:
                    return {"dry_run": True, "id": candidate, "name": payload.name}
                node = r.create_node(
                    id=candidate,
                    name=payload.name,
                    description=payload.description,
                    roles=payload.roles,
                )
                addresses = self.addresses(node.id)
                r.set_prefixes(
                    node.id,
                    [{"prefix": str(addresses.client_pool), "kind": "pool", "export": True}],
                )
                self._validate(r, changed=node.id)
                self.bundles.compile_all(r, "agent created")
            self._synced()
            try:
                token = self.enrollment.issue_token(
                    node.id,
                    camouflage=self.config.server.camouflage.secret
                    if self.config.server.camouflage.enabled
                    else None,
                )
            except Exception:
                raise ManagementError(
                    503,
                    "token_failed",
                    "agent created, but token issuance failed; re-issue explicitly",
                    {"committed": True, "name": node.name},
                ) from None
            self._audit("agent.create", node.name)
            return {"agent": self.show(node.name), "token": token}

    def addresses(self, node_id: int) -> Any:
        f = self.config.interlink
        return derive_addresses(
            node_id,
            interlink_cidr=f.cidr,
            client_pool=f.client_pool,
            source_pool=f.source_pool,
            domain=f.domain,
        )

    def _change(
        self, name: str, action: str, change: Callable[[Registry, Node], Any]
    ) -> dict[str, Any]:
        with self.exclusive():
            with self.registry() as r, transaction(r.conn):
                node = self.node(r, name)
                if node.state == "revoked":
                    raise ManagementError(409, "revoked", "revoked agents cannot be edited")
                change(r, node)
                self._validate(r, changed=node.id)
                self.bundles.compile_all(r, action)
            self._synced()
            self._audit(action, name)
            return self.show(name)

    def update(self, name: str, patch: AgentPatch) -> dict[str, Any]:
        def change(r: Registry, node: Node) -> None:
            fields = patch.model_dump(exclude_unset=True, exclude={"transport"})
            if any(value is None for value in fields.values()):
                raise ManagementError(422, "invalid", "description and roles cannot be null")
            if patch.transport is not None:
                transport = {
                    **node.transport,
                    **patch.transport.model_dump(exclude_unset=True, exclude={"camouflage"}),
                }
                if "camouflage" in patch.transport.model_fields_set:
                    transport.pop("camouflage", None)
                    transport.pop("camouflage_enc", None)
                    if patch.transport.camouflage:
                        blob = self.bundles.encrypt_external_secrets(
                            node.id,
                            "fabric-transport",
                            {"camouflage": patch.transport.camouflage.get_secret_value()},
                        )
                        transport["camouflage_enc"] = base64.b64encode(blob).decode()
                fields["transport"] = transport
            r.update_node(node.id, **fields)

        return self._change(name, "agent.update", change)

    def token(self, name: str, *, revoke: bool = False) -> dict[str, Any]:
        with self.exclusive(), self.registry() as r:
            node = self.node(r, name)
            try:
                if revoke:
                    return {"revoked_tokens": self.enrollment.revoke_token(node.id)}
                camouflage = self.config.server.camouflage
                return {
                    "token": self.enrollment.issue_token(
                        node.id, camouflage=camouflage.secret if camouflage.enabled else None
                    )
                }
            except EnrollmentError as exc:
                raise ManagementError(exc.status, exc.code, "token action refused") from None

    def revoke(self, name: str, *, dry_run: bool = False) -> dict[str, Any]:
        with self.exclusive(), self.registry() as r:
            node = self.node(r, name)
            if dry_run:
                return {"dry_run": True, "revoke": name, "disconnect": True}
            try:
                result: dict[str, Any] = self.enrollment.revoke_node(node.id)
                return result
            except EnrollmentError as exc:
                raise ManagementError(
                    exc.status,
                    exc.code,
                    "revocation incomplete; node is fail-closed; retry revoke",
                    {"committed": True},
                ) from None

    def delete(self, name: str, *, dry_run: bool = False) -> dict[str, Any]:
        with self.exclusive():
            with self.registry() as r:
                node = self.node(r, name)
            if dry_run:
                return {
                    "dry_run": True,
                    "delete": name,
                    "revoke_first": True,
                    "quarantine_days": 30,
                }
            try:
                self.enrollment.revoke_node(node.id)
            except EnrollmentError:
                raise ManagementError(
                    503,
                    "revoke_incomplete",
                    "deletion refused until revocation completes",
                    {"committed": True},
                ) from None
            with self.registry() as r, transaction(r.conn):
                if self.node(r, name).state != "revoked":
                    raise ManagementError(409, "conflict", "node is not revoked")
                r.quarantine_id(node.id, iso_time(self.clock() + timedelta(days=30)))
                r.delete_node(node.id)
                self.bundles.compile_all(r, "agent deleted")
            self._synced()
            self._audit("agent.delete", name)
            return {"deleted": name, "quarantine_days": 30}

    def prefixes(self, name: str) -> dict[str, Any]:
        return {"prefixes": self.show(name)["prefixes"], "runtime_supported": True}

    def add_prefix(self, name: str, payload: PrefixInput) -> dict[str, Any]:
        def change(r: Registry, node: Node) -> None:
            if payload.kind == "pool":
                raise ManagementError(409, "derived_pool", "client pool is derived from node id")
            old = r.list_prefixes(node.id)
            if any(p.prefix == payload.prefix for p in old):
                raise ManagementError(409, "exists", "prefix already exists")
            r.set_prefixes(node.id, [*[asdict(p) for p in old], payload.model_dump()])

        return self._change(name, "agent.prefix.add", change)

    def delete_prefix(self, name: str, cidr: str) -> dict[str, Any]:
        canonical = parse(PrefixInput, {"prefix": cidr}).prefix

        def change(r: Registry, node: Node) -> None:
            old = r.list_prefixes(node.id)
            target = next((p for p in old if p.prefix == canonical), None)
            if target is None:
                raise ManagementError(404, "not_found", "prefix not found")
            if target.kind == "pool" or (
                target.kind == "source"
                and any(s.get("cidr") == canonical for s in node.policy.get("sources", []))
            ):
                raise ManagementError(
                    409, "derived_prefix", "pool/source prefixes follow addressing and sources"
                )
            r.set_prefixes(node.id, [asdict(p) for p in old if p != target])

        return self._change(name, "agent.prefix.delete", change)

    def policy(self, name: str) -> dict[str, Any]:
        with self.registry() as r:
            return cast(
                dict[str, Any],
                Redactor().data(
                    {"policy": self.node(r, name).policy, "runtime_support": RUNTIME_GAPS}
                ),
            )

    def set_policy(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        policy = parse(EgressPolicy, data).model_dump(mode="json", by_alias=True)

        def change(r: Registry, node: Node) -> None:
            self._source_prefixes(r, node, policy)
            r.update_node(node.id, policy=policy)

        return self._change(name, "agent.policy", change)

    def sources(self, name: str) -> dict[str, Any]:
        return {
            "sources": self.policy(name)["policy"].get("sources", []),
            "runtime_supported": True,
        }

    def set_source(
        self, name: str, source_name: str, data: dict[str, Any] | None
    ) -> dict[str, Any]:
        source = parse(Source, {**(data or {}), "name": source_name}) if data is not None else None

        def change(r: Registry, node: Node) -> None:
            policy = parse(EgressPolicy, node.policy).model_dump(mode="json", by_alias=True)
            old = policy["sources"]
            if source is None and not any(s["name"] == source_name for s in old):
                raise ManagementError(404, "not_found", "source not found")
            policy["sources"] = [s for s in old if s["name"] != source_name]
            if source:
                policy["sources"].append(source.model_dump(mode="json"))
            self._source_prefixes(r, node, policy)
            r.update_node(node.id, policy=policy)

        return self._change(name, "agent.source", change)

    def _source_prefixes(self, r: Registry, node: Node, policy: dict[str, Any]) -> None:
        replaced = {s["cidr"] for s in node.policy.get("sources", [])} | {
            s["cidr"] for s in policy["sources"]
        }
        prefixes = [
            asdict(p)
            for p in r.list_prefixes(node.id)
            if not (p.kind == "source" and p.prefix in replaced)
        ]
        prefixes += [
            {"prefix": s["cidr"], "kind": "source", "export": s["export"]}
            for s in policy["sources"]
        ]
        r.set_prefixes(node.id, prefixes)

    def upstreams(self, name: str) -> dict[str, Any]:
        with self.registry() as r:
            node = self.node(r, name)
            return cast(
                dict[str, Any],
                Redactor().data(
                    {
                        "upstreams": [
                            {"name": e.name, **e.spec, "credentials_set": bool(e.secrets)}
                            for e in r.list_externals(node.id)
                        ]
                    }
                ),
            )

    def set_upstream(self, name: str, upstream: str, data: dict[str, Any] | None) -> dict[str, Any]:
        if not re.fullmatch(NAME_PATTERN, upstream):
            raise ManagementError(422, "invalid", "invalid upstream name")

        def change(r: Registry, node: Node) -> None:
            if data is None:
                r.delete_external(node.id, upstream)
                return
            old = next((e for e in r.list_externals(node.id) if e.name == upstream), None)
            previous = (
                self.bundles._decrypt_external_secrets(node.id, upstream, old.secrets)
                if old and old.secrets
                else {}
            )
            payload = parse(ExternalInput, {**(old.spec if old else {}), **data})
            for key in ("password", "key", "camouflage"):
                if key in payload.model_fields_set:
                    value = getattr(payload, key)
                    if value is None:
                        previous.pop(key, None)
                    else:
                        previous[key] = value.get_secret_value()
            if payload.auth_type == "password" and "password" not in previous:
                raise ManagementError(422, "credentials_required", "upstream password is required")
            if payload.auth_type == "cert" and (not payload.cert_pem or "key" not in previous):
                raise ManagementError(
                    422, "credentials_required", "certificate and private key are required"
                )
            spec = payload.model_dump(exclude={"password", "key", "camouflage"}, exclude_none=True)
            blob = (
                self.bundles.encrypt_external_secrets(node.id, upstream, previous)
                if previous
                else None
            )
            r.set_external(node.id, upstream, spec, blob)

        return self._change(name, "agent.upstream", change)

    @staticmethod
    def _access_view(node: Node) -> dict[str, Any]:
        """Listener settings without key material (the key never leaves sealed)."""
        access = node.access
        if not access:
            return {"configured": False}
        cert = access.get("cert_pem")
        return {
            "configured": bool(cert),
            "hostname": access.get("hostname"),
            "port": access.get("port"),
            "udp": access.get("udp", False),
            "certificate": {
                "not_after": access.get("cert_not_after"),
                "pin": certificate_pin(pem_to_der(cert)).pin if cert else None,
            },
        }

    def access(self, name: str) -> dict[str, Any]:
        with self.registry() as r:
            node = self.node(r, name)
            return {**self._access_view(node), "role": "access" in node.roles}

    def set_access(self, name: str, data: dict[str, Any] | None) -> dict[str, Any]:
        payload = parse(AccessInput, data) if data is not None else None
        with self.registry() as r:
            current = self.node(r, name)
        if payload is not None and "access" not in current.roles:
            raise ManagementError(409, "role_required", "agent requires access role")
        issued: tuple[str, str] | None = None
        if payload is not None and (
            payload.reissue
            or payload.hostname != current.access.get("hostname")
            or not current.access.get("cert_pem")
        ):
            # certtool spawns a process: issue before the registry write lock.
            try:
                certificates = self.certificates()
                issued = certificates.issue_access_server_certificate(
                    current.id, payload.hostname, lifetime_days=ACCESS_CERT_DAYS
                )
                # Defence in depth (D-67): a hub-CA certificate without OU must never
                # log in to the hub. Revoking it in the hub CRL makes ocserv refuse it
                # as a client certificate whatever groups are configured; the agent's
                # ocserv has no CRL and clients do not check one for a server.
                certificates.revoke_certificate_pem(issued[0])
                with contextlib.suppress(Exception):
                    self._reload_ocserv()
            except Exception:
                raise ManagementError(
                    503, "certificate_failed", "access server certificate could not be issued"
                ) from None

        def change(r: Registry, node: Node) -> None:
            if payload is None:
                r.update_node(node.id, access={})
                return
            access = {
                key: value
                for key, value in node.access.items()
                if key in ("cert_pem", "cert_not_after", "key_enc")
            }
            if issued is not None:
                cert_pem, key_pem = issued
                blob = self.bundles.encrypt_external_secrets(
                    node.id, ACCESS_SECRET_NAME, {"key": key_pem}
                )
                access.update(
                    cert_pem=cert_pem,
                    cert_not_after=_not_after(cert_pem),
                    key_enc=base64.b64encode(blob).decode(),
                )
            access.update(hostname=payload.hostname, port=payload.port, udp=payload.udp)
            r.update_node(node.id, access=access)

        self._change(name, "agent.access", change)
        return self.access(name)

    def certificates(self) -> Any:
        from kornode.services.certificates import CertificateService

        return CertificateService(self.config)

    def users(self, name: str) -> dict[str, Any]:
        with self.registry() as r:
            node = self.node(r, name)
            configured = bool(node.access.get("cert_pem"))
            return {
                "users": [
                    {
                        "username": u["username"],
                        "groups": u["groups"],
                        "enabled": u["enabled"],
                        "password_set": bool(u["pw_hash"]),
                    }
                    for u in r.access_users(node.id)
                ],
                "runtime_supported": True,
                "delivered": "access" in node.roles and configured,
                "reason": None if configured else "configure the access listener to deliver users",
            }

    def set_user(self, name: str, user: str, data: dict[str, Any] | None) -> dict[str, Any]:
        username(user)
        payload = parse(AccessUserInput, data) if data is not None else None
        # ocpasswd is slow and spawns a process: hash before the registry
        # transaction (BEGIN IMMEDIATE) so the write lock is not held meanwhile.
        new_hash = (
            self.password_hasher(payload.password.get_secret_value())
            if payload is not None and payload.password
            else None
        )

        def change(r: Registry, node: Node) -> None:
            if "access" not in node.roles:
                raise ManagementError(409, "role_required", "agent requires access role")
            if payload is None:
                r.delete_access_user(node.id, user)
                return
            old = next((u for u in r.access_users(node.id) if u["username"] == user), None)
            hashed = old["pw_hash"] if old else None
            if new_hash:
                hashed = new_hash
            if not hashed:
                raise ManagementError(
                    422, "password_required", "new access user requires a password"
                )
            groups = (
                payload.groups
                if "groups" in payload.model_fields_set
                else (old["groups"] if old else [])
            )
            enabled = (
                payload.enabled
                if "enabled" in payload.model_fields_set
                else (old["enabled"] if old else True)
            )
            r.set_access_user(node.id, user, hashed, groups, enabled)

        self._change(name, "agent.user", change)
        return self.users(name)

    def reports(self, name: str, limit: int = 50) -> dict[str, Any]:
        if not 1 <= limit <= 500:
            raise ManagementError(422, "invalid", "limit must be 1..500")
        with self.registry() as r:
            node = self.node(r, name)
            return cast(
                dict[str, Any],
                self._redactor(r, node).data(
                    {"reports": [asdict(p) for p in r.list_reports(node.id, limit)]}
                ),
            )

    def bundles_list(self, name: str) -> dict[str, Any]:
        with self.registry() as r:
            node = self.node(r, name)
            return {
                "bundles": [
                    {
                        "version": b.version,
                        "key_id": b.key_id,
                        "sha256": b.sha256,
                        "created_at": b.created_at,
                        "reason": b.reason,
                    }
                    for b in r.list_bundles(node.id)
                ]
            }

    def bundle(self, name: str, version: int) -> dict[str, Any]:
        with self.registry() as r:
            node = self.node(r, name)
            return cast(
                dict[str, Any],
                self._redactor(r, node).data(json.loads(r.get_bundle(node.id, version).body)),
            )

    def bundle_diff(self, name: str, a: int, b: int) -> dict[str, Any]:
        first, second = self.bundle(name, a), self.bundle(name, b)
        lines = list(
            difflib.unified_diff(
                json.dumps(first, indent=2, sort_keys=True).splitlines(),
                json.dumps(second, indent=2, sort_keys=True).splitlines(),
                fromfile=str(a),
                tofile=str(b),
                lineterm="",
            )
        )
        return {"a": a, "b": b, "diff": "\n".join(lines), "secret_changes_redacted": True}

    def enqueue(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        kind, args = validate_command(data)
        with self.exclusive(), self.registry() as r, transaction(r.conn):
            node = self.node(r, name)
            if node.state != "active":
                raise ManagementError(409, "not_active", "commands require an active agent")
            if data.get("dry_run", False):
                return {"dry_run": True, "agent": name, "type": kind, "args": args}
            r.expire_commands(node.id, iso_time(self.clock()))
            pending = sum(1 for c in r.list_commands(node.id) if c.state in ("queued", "delivered"))
            if pending >= 100:
                raise ManagementError(409, "queue_full", "agent command queue is full")
            cmd = r.enqueue_command(node.id, kind, args, now=self.clock())
            self._audit("agent.command." + kind, name)
            return asdict(cmd)

    def commands(self, name: str) -> dict[str, Any]:
        with self.registry() as r:
            node = self.node(r, name)
            return {
                "commands": [
                    self._command_view(r, node, c.id) for c in r.list_commands(node.id)[-100:][::-1]
                ]
            }

    def command(self, name: str, command_id: str) -> dict[str, Any]:
        with self.registry() as r:
            return self._command_view(r, self.node(r, name), command_id)

    def _command_view(self, r: Registry, node: Node, command_id: str) -> dict[str, Any]:
        command = r.get_command(command_id)
        if command.node_id != node.id:
            raise ManagementError(404, "not_found", "command not found for agent")
        data = asdict(command)
        if command.state == "queued" and command.expires_at <= iso_time(self.clock()):
            data["state"] = "expired"
        if data["result"]:
            artifact = data["result"].pop("artefact_b64", None)
            data["result"]["artefact_available"] = artifact is not None
        return self._redactor(r, node).data(data)  # type: ignore[no-any-return]

    def artifact(self, name: str, command_id: str) -> bytes:
        with self.registry() as r:
            node = self.node(r, name)
            self._command_view(r, node, command_id)
            command = r.get_command(command_id)
            if command.type != "collect_diag" or command.state != "done" or not command.result:
                raise ManagementError(409, "not_ready", "diagnostic artifact is not ready")
            try:
                raw = base64.b64decode(command.result.get("artefact_b64", ""), validate=True)
            except (ValueError, TypeError):
                raise ManagementError(
                    409, "invalid_artifact", "invalid diagnostic artifact"
                ) from None
            if not raw or len(raw) > 5 * 1024 * 1024:
                raise ManagementError(
                    409, "invalid_artifact", "diagnostic artifact is empty or exceeds 5 MiB"
                )
            if not _valid_diag_archive(raw):
                raise ManagementError(
                    409, "invalid_artifact", "diagnostic artifact is not a plain tar.gz"
                )
            return raw

    def _redactor(self, r: Registry, node: Node) -> Redactor:
        known: list[str] = []
        for external in r.list_externals(node.id):
            if external.secrets:
                known.extend(
                    self.bundles._decrypt_external_secrets(
                        node.id, external.name, external.secrets
                    ).values()
                )
        if node.transport.get("camouflage_enc"):
            known.extend(
                self.bundles._decrypt_external_secrets(
                    node.id, "fabric-transport", base64.b64decode(node.transport["camouflage_enc"])
                ).values()
            )
        if node.transport.get("camouflage"):
            known.append(str(node.transport["camouflage"]))
        return Redactor(known)

    def _validate(self, r: Registry, *, changed: int) -> None:
        # Only the prefixes of the node being mutated are "adding": a conflict
        # elsewhere in the interlink must not block unrelated mutations.
        owned: list[OwnedPrefix] = []
        local: list[LocalNetwork] = []
        for node in r.list_nodes():
            if node.state == "revoked":
                continue
            address = self.addresses(node.id)
            owned.append(
                OwnedPrefix(address.client_pool, node.id, "client_pool", node.id == changed)
            )
            for p in r.list_prefixes(node.id):
                if p.kind != "pool":
                    owned.append(
                        OwnedPrefix(
                            ipaddress.ip_network(p.prefix), node.id, p.kind, node.id == changed
                        )
                    )
            for report in r.list_reports(node.id, 1):
                reported = report.body.get("local_networks", [])
                for network in reported if isinstance(reported, list) else []:
                    if not isinstance(network, str):
                        continue
                    with contextlib.suppress(ValueError, TypeError):
                        local.append(
                            LocalNetwork(ipaddress.ip_network(network), node.id, "reported")
                        )
            policy = parse(EgressPolicy, node.policy)
            owned.append(OwnedPrefix(address.source_pool, node.id, "source", node.id == changed))
            if node.id != changed:
                # Another node's stale policy must not block this mutation.
                continue
            self._check_exits(r, node, policy)
            for source in policy.sources:
                network = ipaddress.ip_network(source.cidr)
                if not source.allow_outside_pool and (
                    network.version != address.source_pool.version
                    or not network.subnet_of(address.source_pool)
                ):
                    raise ManagementError(
                        409,
                        "source_pool",
                        "source must use its derived pool, or explicitly allow_outside_pool",
                    )
                if network.overlaps(address.client_pool):
                    raise ManagementError(
                        409, "address_overlap", "source overlaps its own client pool"
                    )
            externals = r.list_externals(node.id)
            interfaces = [
                "oc-hub0",
                *(s.interface for s in policy.sources),
                *(str(e.spec.get("interface")) for e in externals),
            ]
            if len(interfaces) != len(set(interfaces)):
                raise ManagementError(
                    409, "interface_conflict", "sources and tunnels must have distinct interfaces"
                )
            tunnels = {"interlink": TunnelFact("oc-hub0", False)}
            tunnels.update(gateway_tunnels(policy, "oc-hub0", False))
            tunnels.update(
                {
                    f"upstream:{e.name}": TunnelFact(str(e.spec.get("interface", "")), False)
                    for e in externals
                    if e.spec.get("enabled", True)
                }
            )
            compile_policy(
                policy,
                NodeFacts(
                    node_id=node.id,
                    client_pool=address.client_pool,
                    upstreams=tuple(e.name for e in externals if e.spec.get("enabled", True)),
                    tunnels=tunnels,
                    sources={s.name: SourceFact(False) for s in policy.sources},
                    node_prefixes={
                        other.id: (self.addresses(other.id).client_pool,)
                        for other in r.list_nodes()
                        if other.state == "active" and other.id != node.id
                    },
                ),
            )
        self._check_gateway_role_kept(r, changed)
        f = self.config.interlink
        conflicts = check_overlaps(
            owned,
            interlink_cidr=f.cidr,
            reserved=f.reserved,
            enroll_pool=f.enroll_pool,
            local_networks=local,
        )
        if conflicts.errors:
            raise ManagementError(
                409,
                "address_overlap",
                "network overlaps another owner",
                [c.to_dict() for c in conflicts.errors],
            )

    def _check_exits(self, r: Registry, node: Node, policy: EgressPolicy) -> None:
        """`via: node:<n>` (D-69, D-84): n must be another active agent with role `gateway`; only
        `to: any` (the hub does not repeat domain/set matching), only clients and
        sources (host traffic carries the uplink address, which the hub's strict reverse
        path drops), and a source must be exported so that answers find their way back."""
        nodes = {item.id: item for item in r.list_nodes()}
        for rule in policy.egress:
            via = rule.parsed_via
            if via.kind != "node":
                continue
            target = int(via.target or 0)
            other = nodes.get(target)
            if target == node.id or other is None or other.state != "active":
                raise ManagementError(
                    409,
                    "gateway_node",
                    f"node:{target} needs another active agent with role gateway",
                )
            if "gateway" not in other.roles:
                raise ManagementError(
                    409, "role_required", f"agent {other.name} lacks the gateway role"
                )
            if not (rule.to == "any" or isinstance(rule.to, SetRef | InlineDest)):
                raise ManagementError(
                    409,
                    "runtime_unsupported",
                    "leaving through another node supports `to: any`, a set or an inline "
                    "destination, not `interlink` or a node",
                )
            if "host" in rule.from_:
                raise ManagementError(
                    409,
                    "runtime_unsupported",
                    "the node's own traffic cannot use node:<n>; use clients or sources",
                )
            for name in rule.from_:
                source = next((item for item in policy.sources if item.name == name), None)
                if source is not None and not source.export:
                    raise ManagementError(
                        409,
                        "source_export",
                        f"source {name} must be exported to leave through a gateway "
                        "(answers return by prefix)",
                    )

    def _check_gateway_role_kept(self, r: Registry, changed: int) -> None:
        """A node that other agents use as their gateway keeps its role (and stays active)."""
        node = r.get_node(changed)
        if "gateway" in node.roles and node.state == "active":
            return
        for other in r.list_nodes():
            if other.id == changed or other.state == "revoked":
                continue
            try:
                policy = parse(EgressPolicy, other.policy)
            except ManagementError:
                continue  # another node's stale policy is not this mutation's problem
            if any(
                rule.parsed_via.kind == "node" and rule.parsed_via.target == str(changed)
                for rule in policy.egress
            ):
                raise ManagementError(
                    409,
                    "gateway_in_use",
                    f"agent {other.name} uses {node.name} as its gateway; change its policy first",
                )

    def _reload_ocserv(self) -> None:
        CommandRunner().run(SessionService(self.config).occtl_argv("reload"), timeout=15)

    def _hash_password(self, password: str) -> str:
        root = self.config.system.secrets_dir
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".access-user-", dir=root) as directory:
            path = Path(directory) / "passwd"
            CommandRunner().run(
                ["ocpasswd", "-c", str(path), "user"],
                input_text=password + "\n" + password + "\n",
                timeout=30,
                extra_secrets=[password],
            )
            value = path.read_text().strip().split(":")[-1]
            if not value.startswith("$"):
                raise ManagementError(
                    503, "hash_failed", "ocpasswd did not produce a password hash"
                )
            return value

    def _audit(self, action: str, target: str) -> None:
        with contextlib.suppress(OSError):
            self.audit.record(
                actor="operator", action=action, outcome="success", details={"agent": target}
            )


def validate_command(data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if set(data) - {"type", "args", "dry_run"} or type(data.get("dry_run", False)) is not bool:
        raise ManagementError(422, "invalid", "unknown command fields")
    kind, args = data.get("type"), data.get("args", {})
    allowed = {
        "reconnect": {"tunnel"},
        "explain": {"src", "dst", "proto", "port"},
        "collect_diag": set(),
        "restart": set(),
        "rollback": {"to_version"},
    }
    if (
        not isinstance(kind, str)
        or kind not in allowed
        or not isinstance(args, dict)
        or set(args) - allowed[kind]
    ):
        raise ManagementError(422, "invalid", "unknown command type or arguments")
    try:
        if kind == "explain":
            if args.get("src") != "host":
                ipaddress.ip_address(args["src"])
            ipaddress.ip_address(args["dst"])
            if args.get("proto") not in (None, "tcp", "udp", "icmp", "icmpv6"):
                raise ValueError()
            if "port" in args and (
                type(args["port"]) is not int
                or not 1 <= args["port"] <= 65535
                or args.get("proto") not in (None, "tcp", "udp")
            ):
                raise ValueError()
        elif kind == "reconnect" and args.get("tunnel") is not None:
            if not re.fullmatch(r"interlink|upstream:[a-z][a-z0-9_-]{0,30}", args["tunnel"]):
                raise ValueError()
        elif kind == "rollback":
            if type(args.get("to_version")) is not int or not 1 <= args["to_version"] <= 2**31 - 1:
                raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ManagementError(422, "invalid", "invalid command arguments") from None
    return kind, args


ACCESS_SECRET_NAME = "access-server"


def _not_after(cert_pem: str) -> str:
    from cryptography import x509

    value = x509.load_pem_x509_certificate(cert_pem.encode()).not_valid_after_utc
    return iso_time(value)
