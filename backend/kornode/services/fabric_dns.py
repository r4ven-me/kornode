"""Fabric DNS zone (spec 07 "DNS", D-66) shared by CLI/API/panel.

The hub's dnsmasq answers the whole `<fabric.domain>` zone from local data
(`local=/<domain>/`); each agent's dnsmasq answers its own
`node<id>.<domain>` from the bundle and forwards the rest of the zone to the
hub. Stored names (and CNAME targets) are relative to `fabric.domain`, so a
domain change never leaves stale absolute names in the registry.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator

from kornode.bundle.models import dns_name
from kornode.config.models import AppConfig
from kornode.net.addressing import derive_addresses
from kornode.registry.db import migrate, open_registry, transaction
from kornode.registry.models import DnsRecord, DnsRecordType
from kornode.registry.repository import Registry
from kornode.services.agent_models import ManagementError, Model

HUB_NODE_ID = 1
# The last label of a hub-wide name must not shadow a generated host or a
# node zone: `hub`, `node<N>`.
_RESERVED_LABEL = re.compile(r"^(hub|node[0-9]+)$")


class DnsRecordInput(Model):
    name: str = Field(min_length=1, max_length=200)
    type: Literal["A", "AAAA", "CNAME"]
    value: str = Field(min_length=1, max_length=253)
    # Agent name; None means a hub-wide record `<name>.<domain>`.
    node: str | None = Field(default=None, max_length=63)

    @field_validator("name")
    @classmethod
    def relative_name(cls, value: str) -> str:
        return dns_name(value.lower().rstrip("."))


@dataclass(frozen=True, slots=True)
class ZoneRecord:
    """One answer of the zone with absolute names."""

    fqdn: str
    type: DnsRecordType
    value: str
    node_id: int | None
    generated: bool = False


def _fqdn(relative: str, domain: str) -> str:
    return f"{relative}.{domain}"


def _zone(node_id: int, domain: str) -> str:
    return _fqdn(f"node{node_id}", domain)


def _service_address(config: AppConfig, node_id: int) -> str:
    fabric = config.fabric
    return str(
        derive_addresses(
            node_id,
            fabric_cidr=fabric.cidr,
            client_pool=fabric.client_pool,
            source_pool=fabric.source_pool,
            domain=fabric.domain,
        ).service_address
    )


def _stored(record: DnsRecord, domain: str) -> ZoneRecord:
    value = _fqdn(record.value, domain) if record.type == "CNAME" else record.value
    return ZoneRecord(_fqdn(record.name, domain), record.type, value, record.node_id)


def zone_records(config: AppConfig, registry: Registry) -> list[ZoneRecord]:
    """Every answer of the hub: generated host names plus stored records.

    `node<N>` exists for every registered node, whatever its state: the name
    goes away with the registry row, so revocation needs no DNS step.
    """
    domain = config.fabric.domain
    hub = _service_address(config, HUB_NODE_ID)
    records = [
        ZoneRecord(_fqdn("hub", domain), "A", hub, HUB_NODE_ID, True),
        ZoneRecord(_zone(HUB_NODE_ID, domain), "A", hub, HUB_NODE_ID, True),
    ]
    records.extend(
        ZoneRecord(_zone(node.id, domain), "A", _service_address(config, node.id), node.id, True)
        for node in registry.list_nodes()
        if node.id != HUB_NODE_ID
    )
    records.extend(_stored(record, domain) for record in registry.dns_records())
    return sorted(records, key=lambda item: (item.fqdn, item.type, item.value))


def node_zone_records(config: AppConfig, registry: Registry, node_id: int) -> list[ZoneRecord]:
    """The answers an agent serves locally: its own `node<id>` zone."""
    zone = _zone(node_id, config.fabric.domain)
    return [
        record
        for record in zone_records(config, registry)
        if record.fqdn == zone or record.fqdn.endswith("." + zone)
    ]


def dnsmasq_lines(records: Iterable[ZoneRecord]) -> list[str]:
    """`host-record` per name (all its addresses on one line) and `cname`.

    A CNAME whose target has no address here is left out: dnsmasq answers a
    `cname` only from local data, and a node deletion can orphan one.
    """
    records = list(records)
    addresses: dict[str, list[str]] = {}
    for record in records:
        if record.type != "CNAME":
            addresses.setdefault(record.fqdn, []).append(record.value)
    lines = [
        f"cname={record.fqdn},{record.value}"
        for record in records
        if record.type == "CNAME" and record.value in addresses
    ]
    hosts = [f"host-record={name},{','.join(values)}" for name, values in addresses.items()]
    return sorted(hosts) + sorted(lines)


class FabricDnsService:
    def __init__(
        self,
        config: AppConfig,
        *,
        agents: Any = None,
        restart_dnsmasq: Callable[[], Any] | None = None,
    ) -> None:
        self.config = config
        self._agents = agents
        self.restart_dnsmasq = restart_dnsmasq or self._restart_dnsmasq

    @property
    def agents(self) -> Any:
        if self._agents is None:
            from kornode.services.agents import AgentService

            self._agents = AgentService(self.config)
        return self._agents

    # ------------------------------------------------------------- queries

    def hub_records(self) -> list[ZoneRecord]:
        """Zone data for the hub's dnsmasq renderer; empty without a registry."""
        path = self.config.system.data_dir / "registry.db"
        if not path.exists():
            return [
                ZoneRecord(
                    _fqdn(name, self.config.fabric.domain),
                    "A",
                    _service_address(self.config, HUB_NODE_ID),
                    HUB_NODE_ID,
                    True,
                )
                for name in ("hub", "node1")
            ]
        conn = open_registry(path)
        try:
            migrate(conn)
            return zone_records(self.config, Registry(conn))
        finally:
            conn.close()

    def list(self) -> dict[str, Any]:
        if not self.config.fabric.enabled:
            return {"enabled": False, "domain": self.config.fabric.domain, "records": []}
        with self.agents.registry() as r:
            names = {node.id: node.name for node in r.list_nodes()}
            return {
                "enabled": True,
                "domain": self.config.fabric.domain,
                "records": [self._view(item, names) for item in zone_records(self.config, r)],
            }

    @staticmethod
    def _view(record: ZoneRecord, names: dict[int, str]) -> dict[str, Any]:
        return {
            "fqdn": record.fqdn,
            "type": record.type,
            "value": record.value,
            "node": (
                "hub"
                if record.node_id is None or record.node_id == HUB_NODE_ID
                else names.get(record.node_id)
            ),
            "generated": record.generated,
        }

    # ----------------------------------------------------------- mutations

    def add(self, payload: DnsRecordInput) -> dict[str, Any]:
        def change(r: Registry) -> None:
            r.add_dns_record(self._record(r, payload))

        return self._change("dns.record.add", change)

    def delete(self, payload: DnsRecordInput) -> dict[str, Any]:
        def change(r: Registry) -> None:
            record = self._record(r, payload, deleting=True)
            r.delete_dns_record(record.name, record.type, record.value)
            fqdn = _fqdn(record.name, self.config.fabric.domain)
            records = zone_records(self.config, r)
            if not any(item.fqdn == fqdn for item in records) and any(
                item.type == "CNAME" and item.value == fqdn for item in records
            ):
                raise ManagementError(409, "cname_target", "a CNAME still points at this name")

        return self._change("dns.record.delete", change)

    def _change(self, action: str, change: Callable[[Registry], None]) -> dict[str, Any]:
        agents = self.agents
        with agents.exclusive():
            with agents.registry() as r, transaction(r.conn):
                change(r)
                agents.bundles.compile_all(r, action)
            self.synced()
        with contextlib.suppress(OSError):
            agents.audit.record(actor="operator", action=action, outcome="success", details={})
        return self.list()

    def _record(
        self, r: Registry, payload: DnsRecordInput, *, deleting: bool = False
    ) -> DnsRecord:
        domain = self.config.fabric.domain
        name = payload.name
        node_id: int | None = None
        if payload.node is not None:
            node = self.agents.node(r, payload.node)
            if node.state == "revoked" and not deleting:
                raise ManagementError(409, "revoked", "revoked agents cannot be edited")
            node_id = node.id
            name = f"{name}.node{node.id}"
        elif _RESERVED_LABEL.fullmatch(name.rsplit(".", 1)[-1]):
            raise ManagementError(422, "reserved", "hub, node<N> are generated names")
        if len(_fqdn(name, domain)) > 253:
            raise ManagementError(422, "invalid", "name is too long for the zone")
        value = self._value(payload, node_id)
        record = DnsRecord(name=name, type=payload.type, value=value, node_id=node_id)
        if deleting:
            return record
        existing = [
            item for item in zone_records(self.config, r) if item.fqdn == _fqdn(name, domain)
        ]
        if any((item.type == "CNAME") != (payload.type == "CNAME") for item in existing):
            raise ManagementError(409, "cname_conflict", "a CNAME cannot share its name")
        if payload.type == "CNAME" and existing:
            raise ManagementError(409, "cname_conflict", "a name has at most one CNAME")
        if payload.type == "CNAME":
            target = _fqdn(value, domain)
            if not any(item.fqdn == target for item in zone_records(self.config, r)):
                raise ManagementError(422, "cname_target", "CNAME target must exist in the zone")
        return record

    def _value(self, payload: DnsRecordInput, node_id: int | None) -> str:
        domain = self.config.fabric.domain
        if payload.type != "CNAME":
            try:
                address = ipaddress.ip_address(payload.value)
            except ValueError:
                raise ManagementError(422, "invalid", "record value must be an IP") from None
            if address.version != (4 if payload.type == "A" else 6):
                raise ManagementError(422, "invalid", f"{payload.type} needs another IP family")
            return str(address)
        target = payload.value.lower().rstrip(".")
        if target.endswith("." + domain):
            target = target[: -len(domain) - 1]
        try:
            dns_name(target)
        except ValueError:
            raise ManagementError(422, "invalid", "CNAME target is not a name") from None
        # An agent answers its own zone without the hub: its CNAMEs must stay
        # inside that zone, or the local answer would dangle.
        if node_id is not None and not (
            target == f"node{node_id}" or target.endswith(f".node{node_id}")
        ):
            raise ManagementError(422, "cname_target", "agent CNAME must stay in its node zone")
        return target

    # ---------------------------------------------------------------- sync

    def synced(self) -> None:
        try:
            self.sync()
        except Exception:
            raise ManagementError(
                503,
                "dns_sync_failed",
                "registry committed; hub dnsmasq needs a restart",
                {"committed": True, "recovery": "korctl registry maintain"},
            ) from None

    def sync(self) -> bool:
        """Rewrite the hub's dnsmasq.conf and restart dnsmasq when it changed.

        A marker written before the file and removed only after a successful
        restart makes a failed restart retried by the next sync (`korctl
        registry maintain`), although the file already matches.
        """
        if not self.config.fabric.enabled:
            return False
        from kornode.renderers import DnsmasqConfigRenderer
        from kornode.services.files import FileManager

        renderer = DnsmasqConfigRenderer()
        path: Path = renderer.target_path(self.config)
        pending = path.with_name("dnsmasq.restart-pending")
        content = renderer.render(self.config)
        try:
            unchanged = path.read_text(encoding="utf-8") == content
        except FileNotFoundError:
            unchanged = False
        if unchanged and not pending.exists():
            return False
        files = FileManager()
        files.ensure_dir(path.parent)
        if not unchanged:
            files.atomic_write_text(pending, "")
            files.atomic_write_text(path, content)
        self.restart_dnsmasq()
        pending.unlink(missing_ok=True)
        return True

    def _restart_dnsmasq(self) -> None:
        """Restart the supervised dnsmasq. Without a supervisor that knows the
        program (a host running korctl without the hub image) there is no
        resolver to restart: whoever starts dnsmasq reads the new file."""
        from kornode.services.internal_dns import InternalDnsService
        from kornode.services.server import ServerService

        server = ServerService(self.config)
        if not server.process_action("status", "dnsmasq").ok:
            return
        InternalDnsService(self.config).ensure_listen_address()
        if not server.process_action("restart", "dnsmasq").ok:
            raise RuntimeError("dnsmasq restart failed")
