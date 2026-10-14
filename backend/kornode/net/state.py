"""Desired/actual kernel networking state as plain, hashable data.

The compiler (P2-04) produces a DesiredState; the kernel adapter (P2-03)
reads an ActualState of the same shape; diff.py turns the two into a Plan.
Nothing here touches the kernel.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Literal

from kornode.net.errors import PolicyError

# Ownership (docs/spec/03-kernel-dataplane.md): kornode creates and removes
# only these objects and never touches anything else.
RULE_PRIORITY_MIN = 90
RULE_PRIORITY_MAX = 199
TABLE_ID_MIN = 12000
TABLE_ID_MAX = 12999
OWNED_NFT_TABLES: frozenset[tuple[str, str]] = frozenset(
    {("inet", "kornode"), ("ip", "kornode_nat")}
)

Family = Literal[4, 6]
RouteType = Literal["unicast", "unreachable", "throw", "blackhole"]
NamedTable = Literal["main", "local", "default"]
TableRef = int | NamedTable


def _normalize_prefix(value: str) -> tuple[str, Family]:
    network = ipaddress.ip_network(value, strict=False)
    family: Family = 4 if network.version == 4 else 6
    return str(network), family


@dataclass(frozen=True, slots=True)
class Sysctl:
    key: str
    value: str


@dataclass(frozen=True, slots=True)
class Address:
    """An address kornode adds to an interface (the hub fabric address on `lo`).
    Add-only: kornode cannot prove it owns a foreign address, so it never
    removes one."""

    dev: str
    cidr: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "cidr", str(ipaddress.ip_interface(self.cidr)))


@dataclass(frozen=True, slots=True)
class IpRule:
    priority: int
    table: TableRef
    family: Family = 4
    fwmark: int | None = None
    fwmask: int | None = None
    to: str | None = None
    suppress_prefixlength: int | None = None

    def __post_init__(self) -> None:
        if self.to is not None:
            prefix, family = _normalize_prefix(self.to)
            if family != self.family:
                raise PolicyError(f"rule to {self.to} does not match family {self.family}")
            object.__setattr__(self, "to", prefix)
        if self.fwmask is not None and self.fwmark is None:
            raise PolicyError("rule fwmask without fwmark")


@dataclass(frozen=True, slots=True)
class Route:
    """One route. Identity (see `key`) follows the kernel's: two routes with
    the same table/destination but different metrics coexist, which is how
    the exit's `default dev <tun>` and its permanent `unreachable default
    metric 4096` share one table (spec 03); anything else about a route with
    the same key is a replacement, not a second route."""

    table: int
    dst: str
    type: RouteType = "unicast"
    dev: str | None = None
    gateway: str | None = None
    metric: int = 0
    family: Family = 4

    def __post_init__(self) -> None:
        if self.dst != "default":
            prefix, family = _normalize_prefix(self.dst)
            if family != self.family:
                raise PolicyError(f"route {self.dst} does not match family {self.family}")
            object.__setattr__(self, "dst", prefix)
        if self.type != "unicast" and (self.dev or self.gateway):
            raise PolicyError(f"{self.type} route cannot have a device or gateway")

    @property
    def key(self) -> tuple[int, int, str, int]:
        return (self.family, self.table, self.dst, self.metric)


_ELEMENTS_RE = re.compile(r"\belements\s*=")


@dataclass(frozen=True, slots=True)
class NftRuleset:
    """The full nft script for kornode's own tables, applied as one
    transaction. Set *elements* never appear in it: they are always applied
    separately as NftElements, so element churn (domain resolution, list
    refreshes) can never force a full reload, and `schema_hash` is simply the
    hash of the script."""

    script: str
    schema_hash: str = field(default="")

    def __post_init__(self) -> None:
        if _ELEMENTS_RE.search(self.script):
            raise PolicyError("nft script must not inline set elements; use NftElements")
        object.__setattr__(self, "schema_hash", schema_hash_of(self.script))


def schema_hash_of(script: str) -> str:
    return hashlib.sha256(script.encode("utf-8")).hexdigest()


def normalize_elements(elements: frozenset[str]) -> frozenset[str]:
    """Collapse address elements into the minimal CIDR set. nft's
    auto-merge stores adjacent prefixes as ranges and hosts as bare
    addresses, so both sides of a diff must be compared in this canonical
    form or a set would look different forever. Non-address elements
    (interface names) are returned unchanged."""
    try:
        networks = [ipaddress.ip_network(item, strict=False) for item in elements]
    except ValueError:
        return elements
    v4 = [net for net in networks if isinstance(net, ipaddress.IPv4Network)]
    v6 = [net for net in networks if isinstance(net, ipaddress.IPv6Network)]
    collapsed = [*ipaddress.collapse_addresses(v4), *ipaddress.collapse_addresses(v6)]
    return frozenset(str(net) for net in collapsed)


@dataclass(frozen=True, slots=True)
class NftElements:
    family: str
    table: str
    set_name: str
    elements: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "elements", normalize_elements(frozenset(self.elements)))

    @property
    def set_key(self) -> tuple[str, str, str]:
        return (self.family, self.table, self.set_name)


COMPAT_COMMENT = "kornode-compat"


@dataclass(frozen=True, slots=True)
class ForeignNftRule:
    """A rule kornode keeps in someone else's chain -- today only Docker's
    documented `ip filter DOCKER-USER` hook, which otherwise drops forwarded
    VPN traffic. Always tagged with `comment "kornode-compat"` in the kernel
    so kornode can tell its own rules from the chain owner's. Never created
    when the chain doesn't exist."""

    family: str
    table: str
    chain: str
    expr: str

    @property
    def chain_key(self) -> tuple[str, str, str]:
        return (self.family, self.table, self.chain)


@dataclass(frozen=True, slots=True)
class DesiredState:
    sysctls: frozenset[Sysctl] = frozenset()
    addresses: frozenset[Address] = frozenset()
    rules: frozenset[IpRule] = frozenset()
    routes: frozenset[Route] = frozenset()
    nft: NftRuleset | None = None
    elements: frozenset[NftElements] = frozenset()
    foreign_rules: frozenset[ForeignNftRule] = frozenset()

    def __post_init__(self) -> None:
        for rule in self.rules:
            if not owns_rule(rule):
                raise PolicyError(f"desired rule outside owned priorities: {rule}")
        for route in self.routes:
            if not owns_route(route):
                raise PolicyError(f"desired route outside owned tables: {route}")
        keys = [route.key for route in self.routes]
        if len(keys) != len(set(keys)):
            raise PolicyError("desired state has two routes with the same key")
        for item in self.elements:
            if (item.family, item.table) not in OWNED_NFT_TABLES:
                raise PolicyError(f"desired elements outside owned nft tables: {item.set_key}")
        set_keys = [item.set_key for item in self.elements]
        if len(set_keys) != len(set(set_keys)):
            raise PolicyError("desired state lists one nft set twice")
        sysctl_keys = [sysctl.key for sysctl in self.sysctls]
        if len(sysctl_keys) != len(set(sysctl_keys)):
            raise PolicyError("desired state sets one sysctl twice")


@dataclass(frozen=True, slots=True)
class ActualState:
    """What the kernel has. Rules/routes include objects kornode does not
    own (they are read but never changed). `nft_schema_hash` is the schema
    hash of kornode's tables as last loaded (None if they are absent); the
    kernel adapter is responsible for knowing it."""

    sysctls: frozenset[Sysctl] = frozenset()
    # Only addresses on the interfaces the desired state names are read.
    addresses: frozenset[Address] = frozenset()
    rules: frozenset[IpRule] = frozenset()
    routes: frozenset[Route] = frozenset()
    nft_schema_hash: str | None = None
    elements: frozenset[NftElements] = frozenset()
    # kornode-tagged rules found in foreign chains, and which of the chains
    # asked about exist at all.
    foreign_rules: frozenset[ForeignNftRule] = frozenset()
    foreign_chains: frozenset[tuple[str, str, str]] = frozenset()


def owns_rule(rule: IpRule) -> bool:
    return RULE_PRIORITY_MIN <= rule.priority <= RULE_PRIORITY_MAX


def owns_route(route: Route) -> bool:
    return TABLE_ID_MIN <= route.table <= TABLE_ID_MAX
