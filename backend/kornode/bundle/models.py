"""Pydantic mirror of docs/spec/schemas/bundle.v1.schema.json."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from kornode.bundle.sealing import SEAL_ALG
from kornode.net.model import NAME_PATTERN, EgressPolicy

BUNDLE_FORMAT = "kornode.bundle/v1"
VERSION_RE = r"^[0-9]+\.[0-9]+\.[0-9]+$"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Sealed(_Model):
    alg: Literal["x25519-hkdf-sha256-chacha20poly1305"]
    epk: StrictStr
    nonce: StrictStr
    ct: StrictStr


assert SEAL_ALG == "x25519-hkdf-sha256-chacha20poly1305"


class Hub(_Model):
    host: StrictStr
    port: Annotated[StrictInt, Field(ge=1, le=65535)]
    pin: Annotated[StrictStr, Field(pattern=r"^pin-sha256:")]
    control_url: Annotated[StrictStr, Field(pattern=r"^https://")]
    server_name: StrictStr | None = None


class NodeInfo(_Model):
    name: StrictStr
    roles: tuple[Literal["access", "exit"], ...]
    fabric_address: StrictStr
    service_address: StrictStr
    client_pool: StrictStr
    source_range: StrictStr | None = None
    uplink_hint: StrictStr | None = None

    # Both end up in the node resolver's configuration (D-66).
    @field_validator("fabric_address", "service_address")
    @classmethod
    def _ipv4(cls, value: str) -> str:
        return str(ipaddress.IPv4Address(value))

    @field_validator("roles")
    @classmethod
    def _unique_roles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate roles")
        return value


class FabricPrefix(_Model):
    prefix: StrictStr
    node_id: StrictInt
    kind: Literal["pool", "source", "lan", "fabric"] | None = None


class FabricInfo(_Model):
    cidr: StrictStr
    domain: StrictStr
    prefixes: tuple[FabricPrefix, ...]


class FabricTunnel(_Model):
    interface: StrictStr = "oc-hub0"
    transport: Literal["tcp", "auto"]
    dpd: Annotated[StrictInt, Field(ge=5)] | None = None
    keepalive: Annotated[StrictInt, Field(ge=5)] | None = None
    camouflage: Sealed | None = None


class UpstreamTunnel(_Model):
    name: Annotated[StrictStr, Field(pattern=NAME_PATTERN)]
    interface: StrictStr
    enabled: StrictBool = True
    server: StrictStr
    port: StrictInt
    transport: Literal["tcp", "auto"] | None = None
    auth_type: Literal["password", "cert", "p12"]
    username: StrictStr | None = None
    password: Sealed | None = None
    cert_pem: StrictStr | None = None
    key: Sealed | None = None
    server_cert_pin: StrictStr | None = None
    camouflage: Sealed | None = None
    check_host: StrictStr | None = None
    accept_server_routes: StrictBool | None = None
    dns: tuple[StrictStr, ...] | None = None


class Tunnels(_Model):
    fabric: FabricTunnel
    upstreams: tuple[UpstreamTunnel, ...] = ()


# DNS names land in the agent's dnsmasq configuration: only plain lower-case
# host names pass, so a bundle can never smuggle an extra option line in.
_DNS_NAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def dns_name(value: str) -> str:
    if not _DNS_NAME_RE.fullmatch(value):
        raise ValueError("invalid DNS name")
    return value


def _ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


class ForwardZone(_Model):
    zone: StrictStr
    servers: tuple[StrictStr, ...]

    _zone = field_validator("zone")(dns_name)

    @field_validator("servers")
    @classmethod
    def addresses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_ip(item) for item in value)


class LocalRecord(_Model):
    name: StrictStr
    type: Literal["A", "AAAA", "CNAME"]
    value: StrictStr

    _name = field_validator("name")(dns_name)

    @model_validator(mode="after")
    def typed_value(self) -> Self:
        if self.type == "CNAME":
            dns_name(self.value)
        elif ipaddress.ip_address(self.value).version != (4 if self.type == "A" else 6):
            raise ValueError(f"{self.type} record needs an IPv{4 if self.type == 'A' else 6}")
        return self


class Dns(_Model):
    enabled: StrictBool | None = None
    upstream_servers: tuple[StrictStr, ...] | None = None
    forward_zones: tuple[ForwardZone, ...] | None = None
    local_records: tuple[LocalRecord, ...] | None = None
    blocklist_domains: tuple[StrictStr, ...] | None = None

    @field_validator("upstream_servers")
    @classmethod
    def upstreams(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        return None if value is None else tuple(_ip(item) for item in value)

    @field_validator("blocklist_domains")
    @classmethod
    def blocklist(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        return None if value is None else tuple(dns_name(item) for item in value)


# Access users become ocpasswd lines `user:groups:hash` (P4-04, D-67): no
# field may carry a separator, a newline or anything but its own syntax.
_ACCESS_USER_RE = re.compile(r"^[a-zA-Z0-9_@.\-]{1,64}$")
_CRYPT_RE = re.compile(r"^\$[0-9a-z]{1,4}\$[./0-9A-Za-z$=]{1,200}$")


class AccessUser(_Model):
    username: Annotated[StrictStr, Field(pattern=_ACCESS_USER_RE.pattern)]
    pw_hash: Annotated[StrictStr, Field(pattern=_CRYPT_RE.pattern)] | None = None
    groups: tuple[Annotated[StrictStr, Field(pattern=NAME_PATTERN)], ...] | None = None
    enabled: StrictBool


class Access(_Model):
    port: Annotated[StrictInt, Field(ge=1, le=65535)]
    udp: StrictBool | None = None
    auth: Annotated[tuple[Literal["password", "certificate"], ...], Field(min_length=1)]
    camouflage: Sealed | None = None
    ca_pem: StrictStr
    server_cert_pem: StrictStr | None = None
    server_key: Sealed | None = None
    users: tuple[AccessUser, ...]
    groups: dict[StrictStr, StrictStr] | None = None
    crl_pem: StrictStr | None = None


class Settings(_Model):
    report_interval_seconds: Annotated[StrictInt, Field(ge=5)] | None = None
    confirm_window_seconds: Annotated[StrictInt, Field(ge=30, le=600)] | None = None
    log_level: Literal["debug", "info", "warning", "error"] | None = None


class Bundle(_Model):
    format: Literal["kornode.bundle/v1"]
    node_id: Annotated[StrictInt, Field(ge=2, le=254)]
    version: Annotated[StrictInt, Field(ge=1)]
    generated_at: StrictStr
    min_agent_version: Annotated[StrictStr, Field(pattern=VERSION_RE)] | None = None
    next_signing_pubkey: StrictStr | None = None
    hubs: Annotated[tuple[Hub, ...], Field(min_length=1)]

    @field_validator("generated_at")
    @classmethod
    def _date_time(cls, value: str) -> str:
        datetime.fromisoformat(value)
        return value

    node: NodeInfo
    fabric: FabricInfo
    tunnels: Tunnels
    policy: EgressPolicy
    dns: Dns | None = None
    access: Access | None = None
    settings: Settings | None = None
