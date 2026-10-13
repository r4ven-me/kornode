"""Per-node address derivation and the overlap validator (docs/spec/01-addressing.md)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from kornode.net.errors import PolicyError

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

NODE_ID_MIN = 1
NODE_ID_MAX = 254
_PLACEHOLDER_RE = re.compile(r"\{([^}]*)\}")


def render_template(template: str, node_id: int) -> ipaddress.IPv4Network:
    """`10.100.{id}.0/24` for node 3 -> 10.100.3.0/24."""
    placeholders = _PLACEHOLDER_RE.findall(template)
    if placeholders != ["id"]:
        raise PolicyError(f"template {template!r} must contain exactly one {{id}} placeholder")
    text = template.replace("{id}", str(node_id))
    try:
        return ipaddress.IPv4Network(text, strict=True)
    except ValueError as exc:
        raise PolicyError(f"template {template!r} is not a valid network for id {node_id}") from exc


@dataclass(frozen=True, slots=True)
class _Labelled:
    network: Network
    label: str


def _first_overlap(items: Iterable[_Labelled]) -> tuple[_Labelled, _Labelled] | None:
    """Two overlapping networks among `items`, if any. CIDR networks are
    either nested or disjoint, so after sorting by start address it is enough
    to compare each network with the furthest-reaching one seen so far."""
    ordered = sorted(
        items, key=lambda item: (item.network.version, int(item.network.network_address))
    )
    widest: _Labelled | None = None
    for item in ordered:
        if (
            widest is not None
            and widest.network.version == item.network.version
            and int(item.network.network_address) <= int(widest.network.broadcast_address)
        ):
            return widest, item
        if widest is None or int(item.network.broadcast_address) > int(
            widest.network.broadcast_address
        ):
            widest = item
    return None


def validate_templates(
    *,
    fabric_cidr: str,
    client_pool: str,
    source_pool: str,
    reserved: Iterable[str] = (),
    enroll_pool: str | None = None,
) -> None:
    """Reject templates that are invalid for some id in 1..254 or that make
    any two derived prefixes (of any ids, of either template) overlap each
    other, the fabric cidr, a reserved range or the enroll pool."""
    items: list[_Labelled] = [
        _Labelled(ipaddress.ip_network(fabric_cidr, strict=True), "fabric.cidr")
    ]
    items.extend(
        _Labelled(ipaddress.ip_network(cidr, strict=True), f"reserved {cidr}") for cidr in reserved
    )
    for name, template in (("client_pool", client_pool), ("source_pool", source_pool)):
        for node_id in range(NODE_ID_MIN, NODE_ID_MAX + 1):
            items.append(_Labelled(render_template(template, node_id), f"{name}[{node_id}]"))
    clash = _first_overlap(items)
    if clash is not None:
        first, second = clash
        raise PolicyError(
            f"{second.label} ({second.network}) overlaps {first.label} ({first.network})"
        )
    if enroll_pool is not None:
        try:
            enroll = _Labelled(
                ipaddress.ip_network(enroll_pool, strict=True),
                "fabric.enroll_pool",
            )
        except ValueError as exc:
            raise PolicyError(f"fabric.enroll_pool ({enroll_pool}) is not a valid network") from exc
        enroll_clash = _first_overlap([enroll, *items])
        if enroll_clash is not None:
            first, second = enroll_clash
            other = second if first.label == "fabric.enroll_pool" else first
            raise PolicyError(
                f"fabric.enroll_pool ({enroll.network}) overlaps {other.label} ({other.network})"
            )


@dataclass(frozen=True, slots=True)
class DerivedAddresses:
    node_id: int
    fabric_address: ipaddress.IPv4Address
    client_pool: ipaddress.IPv4Network
    service_address: ipaddress.IPv4Address
    source_pool: ipaddress.IPv4Network
    dns_zone: str


def derive_addresses(
    node_id: int,
    *,
    fabric_cidr: str,
    client_pool: str,
    source_pool: str,
    domain: str,
) -> DerivedAddresses:
    if not NODE_ID_MIN <= node_id <= NODE_ID_MAX:
        raise PolicyError(f"node id {node_id} is outside {NODE_ID_MIN}..{NODE_ID_MAX}")
    fabric = ipaddress.IPv4Network(fabric_cidr, strict=True)
    fabric_address = fabric.network_address + node_id
    if fabric_address >= fabric.broadcast_address:
        raise PolicyError(f"fabric cidr {fabric} has no host address for node {node_id}")
    pool = render_template(client_pool, node_id)
    if pool.num_addresses < 4:
        raise PolicyError(f"client pool {pool} is too small")
    return DerivedAddresses(
        node_id=node_id,
        fabric_address=fabric_address,
        client_pool=pool,
        service_address=pool.network_address + 1,
        source_pool=render_template(source_pool, node_id),
        dns_zone=f"node{node_id}.{domain}",
    )


PrefixKind = Literal["client_pool", "source", "lan"]


@dataclass(frozen=True, slots=True)
class OwnedPrefix:
    """A fabric prefix owned by a node. `adding` marks prefixes introduced
    by the mutation being validated (rule 3 is an error only for those)."""

    prefix: Network
    node: int
    kind: PrefixKind
    adding: bool = False


@dataclass(frozen=True, slots=True)
class LocalNetwork:
    """A connected network a node reported (physical interface, docker bridge)."""

    prefix: Network
    node: int
    description: str


@dataclass(frozen=True, slots=True)
class Conflict:
    prefix: str
    node: int
    with_: str
    owner: str

    def to_dict(self) -> dict[str, object]:
        return {"prefix": self.prefix, "node": self.node, "with": self.with_, "owner": self.owner}


@dataclass(slots=True)
class OverlapResult:
    errors: list[Conflict] = field(default_factory=list)
    warnings: list[Conflict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def error_body(self) -> dict[str, object]:
        return {
            "error": "address_overlap",
            "conflicts": [conflict.to_dict() for conflict in self.errors],
        }


def check_overlaps(
    prefixes: Iterable[OwnedPrefix],
    *,
    fabric_cidr: str,
    reserved: Iterable[str] = (),
    enroll_pool: str | None = None,
    local_networks: Iterable[LocalNetwork] = (),
) -> OverlapResult:
    owned = list(prefixes)
    locals_ = list(local_networks)
    fabric = ipaddress.ip_network(fabric_cidr, strict=True)
    reserved_networks = [ipaddress.ip_network(cidr, strict=True) for cidr in reserved]
    enroll_network = (
        ipaddress.ip_network(enroll_pool, strict=True) if enroll_pool is not None else None
    )
    result = OverlapResult()

    # Rule 1: fabric prefixes of different nodes never overlap.
    for index, first in enumerate(owned):
        for second in owned[index + 1 :]:
            if first.node != second.node and first.prefix.overlaps(second.prefix):
                subject, other = (
                    (second, first)
                    if second.adding and not first.adding
                    else (
                        first,
                        second,
                    )
                )
                result.errors.append(
                    Conflict(
                        str(subject.prefix),
                        subject.node,
                        str(other.prefix),
                        f"node {other.node} {other.kind}",
                    )
                )

    for item in owned:
        # Rule 2: nothing overlaps the fabric cidr or a reserved range.
        if item.prefix.overlaps(fabric):
            result.errors.append(Conflict(str(item.prefix), item.node, str(fabric), "fabric.cidr"))
        for network in reserved_networks:
            if item.prefix.overlaps(network):
                result.errors.append(
                    Conflict(str(item.prefix), item.node, str(network), "fabric.reserved")
                )
        if enroll_network is not None and item.prefix.overlaps(enroll_network):
            result.errors.append(
                Conflict(str(item.prefix), item.node, str(enroll_network), "fabric.enroll_pool")
            )
        # Rule 3: a node's prefix must not collide with another node's local
        # networks -- that node could not reach it.
        for local in locals_:
            if local.node != item.node and item.prefix.overlaps(local.prefix):
                conflict = Conflict(
                    str(item.prefix),
                    item.node,
                    str(local.prefix),
                    f"node {local.node} local ({local.description})",
                )
                (result.errors if item.adding else result.warnings).append(conflict)
        # Rule 4: an exported LAN should be one of its own node's networks.
        if item.kind == "lan" and not any(
            local.node == item.node and item.prefix.subnet_of(local.prefix)  # type: ignore[arg-type]
            for local in locals_
            if local.prefix.version == item.prefix.version
        ):
            result.warnings.append(
                Conflict(
                    str(item.prefix), item.node, "", f"not reported as local on node {item.node}"
                )
            )
    return result
