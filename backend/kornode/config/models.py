from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import re
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from kornode.config.reserved import RESERVED_GROUPS
from kornode.net.addressing import (
    Conflict,
    OwnedPrefix,
    check_overlaps,
    derive_addresses,
    validate_templates,
)
from kornode.net.errors import PolicyError
from kornode.net.model import DestSet, EgressPolicy, Rule, Source

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

# Public blocklists commonly contain underscores in hostnames, so this is a
# relaxed variant of DOMAIN_RE; at least two labels are required.
BLOCKLIST_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


_LOGGER = logging.getLogger(__name__)

def _default_hub_rule() -> Rule:
    return Rule.model_validate({"id": "default", "from": ["clients"], "to": "any", "via": "local"})


class StrictModel(BaseModel):
    # CLI/API errors can surface these exceptions; never include raw config values.
    model_config = ConfigDict(
        extra="forbid", validate_assignment=True, hide_input_in_errors=True
    )


IntervalUnit = Literal["hours", "days", "weeks", "months"]

INTERVAL_UNIT_SECONDS: dict[str, int] = {
    "hours": 3600,
    "days": 86400,
    "weeks": 7 * 86400,
    # Calendar months vary; a fixed 30 days keeps the schedule predictable.
    "months": 30 * 86400,
}


def _validate_cidr(value: str) -> str:
    ipaddress.ip_network(value, strict=False)
    return value


class AddressOverlapError(Exception):
    def __init__(self, conflicts: list[Conflict]) -> None:
        self.conflicts = conflicts
        super().__init__(
            "address_overlap: "
            + "; ".join(
                f"{conflict.prefix} overlaps {conflict.with_} ({conflict.owner})"
                for conflict in conflicts
            )
        )


def _validate_ip(value: str) -> str:
    ipaddress.ip_address(value)
    return value


def _validate_domain(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate or not DOMAIN_RE.match(candidate):
        raise ValueError(f"invalid domain name: {value}")
    return candidate


def _validate_blocklist_domain(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or not BLOCKLIST_DOMAIN_RE.match(candidate):
        raise ValueError(f"invalid blocklist domain: {value}")
    return candidate


def _validate_local_record(value: str) -> str:
    parts = value.split()
    if len(parts) != 2:
        raise ValueError(f"local DNS record must be 'hostname ip': {value}")
    hostname, ip = parts
    return f"{_validate_domain(hostname)} {_validate_ip(ip)}"


def _dedup_paths(value: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in value:
        if path not in seen:
            deduped.append(path)
            seen.add(path)
    return deduped


def _validate_http_url_list(value: list[str], *, field_name: str) -> list[str]:
    validated: list[str] = []
    seen: set[str] = set()
    for item in value:
        candidate = item.strip()
        if not candidate:
            continue
        if not candidate.startswith(("https://", "http://")):
            raise ValueError(f"{field_name} entries must be HTTP(S) URLs")
        if any(char.isspace() for char in candidate):
            raise ValueError(f"{field_name} entries must not contain whitespace")
        if candidate not in seen:
            validated.append(candidate)
            seen.add(candidate)
    return validated


def _validate_interface_name(value: str) -> str:
    # IFNAMSIZ is 16 including the NUL terminator, so 15 usable characters.
    if not re.match(r"^[A-Za-z0-9_.-]{1,15}$", value):
        raise ValueError(f"invalid network interface name (1-15 chars, alphanumeric/._-): {value}")
    return value


_MAX_SLUG = 22  # "upstream:" + slug stays within the 31 characters of an exit name


def profile_slug(name: str) -> str:
    """Identifier of an upstream profile in `via: upstream:<slug>` and in nftables names
    ("My-VPN" -> "my_vpn"; a leading non-letter gets a `p` prefix, since exit names start
    with a letter). UpstreamConfig.validate_profiles keeps slugs unique."""
    slug = re.sub(r"[^a-z0-9_]", "_", name.lower())
    if not re.match(r"[a-z]", slug):
        slug = f"p{slug}"
    return slug[:_MAX_SLUG]


class NodeConfig(StrictModel):
    id: int = Field(default=1, ge=1, le=254)


class InterlinkConfig(StrictModel):
    cidr: str = "10.99.0.0/24"
    client_pool: str = "10.100.{id}.0/24"
    source_pool: str = "10.8.{id}.0/24"
    domain: str = "kornode.lan"
    enroll_pool: str = "10.99.255.240/28"
    reserved: list[str] = Field(default_factory=list)

    @property
    def server_name(self) -> str:
        """Name of the ocserv virtual host for agents and enrollment (S-07, D-71).

        Selected by TLS SNI on the same 443/tcp as the client host; agents dial the hub
        address but present this name.
        """
        return f"interlink.{self.domain}"

    @field_validator("cidr", "enroll_pool")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        return _validate_cidr(value)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return _validate_domain(value)

    @field_validator("reserved")
    @classmethod
    def validate_reserved(cls, value: list[str]) -> list[str]:
        return [_validate_cidr(item) for item in value]

    @model_validator(mode="after")
    def validate_address_templates(self) -> InterlinkConfig:
        try:
            validate_templates(
                interlink_cidr=self.cidr,
                client_pool=self.client_pool,
                source_pool=self.source_pool,
                reserved=self.reserved,
                enroll_pool=self.enroll_pool,
            )
        except PolicyError as exc:
            raise ValueError(str(exc)) from exc
        return self


class ControlConfig(StrictModel):
    """Hub control plane (docs/spec/05-control-plane.md)."""

    enabled: bool = False
    port: int = Field(default=8444, ge=1, le=65535)
    long_poll_seconds: int = Field(default=60, ge=1, le=300)
    report_interval_seconds: int = Field(default=30, ge=5, le=3600)
    offline_after_seconds: int = Field(default=90, ge=10, le=86400)
    cert_lifetime_days: int = Field(default=90, ge=3, le=3650)
    enroll_token_ttl_minutes: int = Field(default=60, ge=1, le=1440)
    bundle_history: int = Field(default=20, ge=3, le=500)
    min_agent_version: str = Field(default="2.1.0", pattern=r"^\d+\.\d+\.\d+$")
    signing_key: Path | None = None


class LogRotationConfig(StrictModel):
    enabled: bool = False
    # 0 disables the size trigger.
    max_size_mb: int = Field(default=50, ge=0)
    # 0 disables the age trigger; age counts from the file's last rotation
    # (or from when the rotation service first saw the file).
    max_age: int = Field(default=0, ge=0)
    max_age_unit: IntervalUnit = "days"
    keep_files: int = Field(default=5, ge=1, le=100)

    @property
    def max_size_bytes(self) -> int:
        return self.max_size_mb * 1024 * 1024

    @property
    def max_age_seconds(self) -> int:
        return self.max_age * INTERVAL_UNIT_SECONDS[self.max_age_unit]


class SystemConfig(StrictModel):
    timezone: str = "UTC"
    data_dir: Path = Path("/var/lib/kornode")
    log_dir: Path = Path("/var/log/kornode")
    generated_dir: Path = Path("/var/lib/kornode/generated")
    secrets_dir: Path = Path("/var/lib/kornode/secrets")
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    project_name: str = "kornode"
    log_rotation: LogRotationConfig = Field(default_factory=LogRotationConfig)


class CamouflageConfig(StrictModel):
    enabled: bool = False
    secret: str | None = None
    realm: str = "Hidden service"

    @model_validator(mode="after")
    def require_secret_when_enabled(self) -> CamouflageConfig:
        if self.enabled and not self.secret:
            raise ValueError("server.camouflage.secret is required when camouflage is enabled")
        return self


class ServerConfig(StrictModel):
    enabled: bool = True
    listen: str = "0.0.0.0"
    port: int = Field(default=443, ge=1, le=65535)
    udp_enabled: bool = True
    device: str = "vpns"
    cn: str = "vpn.example.com"
    realm: str = "Korvus VPN Server"
    ipv4_network: str = "10.100.1.0/24"
    dns: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    search_domains: list[str] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)
    no_routes: list[str] = Field(default_factory=list)
    max_clients: int = Field(default=128, ge=1)
    max_same_clients: int = Field(default=2, ge=1)
    keepalive: int = Field(default=32400, ge=0)
    dpd: int = Field(default=90, ge=0)
    mobile_dpd: int = Field(default=1800, ge=0)
    compression: bool = False
    cisco_client_compat: bool = True
    isolate_workers: bool = True
    try_mtu_discovery: bool = True
    predictable_ips: bool = True
    deny_roaming: bool = False
    ping_leases: bool = False
    dtls_legacy: bool = True
    client_bypass_protocol: bool = False
    rate_limit_ms: int = Field(default=200, ge=0)
    server_stats_reset_time: int = Field(default=604800, ge=0)
    switch_to_tcp_timeout: int = Field(default=25, ge=0)
    auth_timeout: int = Field(default=240, ge=0)
    cookie_timeout: int = Field(default=600, ge=0)
    ban_time: int = Field(default=300, ge=0)
    max_ban_score: int = Field(default=80, ge=0)
    ban_reset_time: int = Field(default=1200, ge=0)
    rekey_time: int = Field(default=172800, ge=0)
    rekey_method: Literal["ssl", "new-tunnel"] = "ssl"
    cert_user_oid: str = "2.5.4.3"
    tls_priorities: str | None = None
    camouflage: CamouflageConfig = Field(default_factory=CamouflageConfig)
    connect_script: Path | None = None
    disconnect_script: Path | None = None
    debug_level: int = Field(default=2, ge=0, le=9)

    @field_validator("ipv4_network")
    @classmethod
    def validate_network(cls, value: str) -> str:
        return _validate_cidr(value)

    @field_validator("cert_user_oid")
    @classmethod
    def validate_cert_user_oid(cls, value: str) -> str:
        if not re.match(r"^\d+(\.\d+)+$", value):
            raise ValueError("server.cert_user_oid must be a dotted OID, e.g. 2.5.4.3")
        return value

    @field_validator("device")
    @classmethod
    def validate_device(cls, value: str) -> str:
        if not re.match(r"^[A-Za-z][A-Za-z0-9_.-]{0,15}$", value):
            raise ValueError("server.device must be a short Linux interface prefix")
        return value

    @field_validator("dns")
    @classmethod
    def validate_dns(cls, value: list[str]) -> list[str]:
        return [_validate_ip(item) for item in value]

    @field_validator("search_domains")
    @classmethod
    def validate_search_domains(cls, value: list[str]) -> list[str]:
        return [_validate_domain(item) for item in value]

    @field_validator("routes", "no_routes")
    @classmethod
    def validate_routes(cls, value: list[str]) -> list[str]:
        return [_validate_cidr(item) for item in value]


class LetsEncryptConfig(StrictModel):
    enabled: bool = False
    email: str | None = None
    domains: list[str] = Field(default_factory=list)
    renew_reload: bool = True
    auto_renew_enabled: bool = True
    auto_renew_interval: int = Field(default=7, ge=1)
    auto_renew_interval_unit: IntervalUnit = "days"
    http01_address: str | None = None
    http01_port: int = Field(default=80, ge=1, le=65535)

    @property
    def auto_renew_interval_seconds(self) -> int:
        return self.auto_renew_interval * INTERVAL_UNIT_SECONDS[self.auto_renew_interval_unit]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, value: list[str]) -> list[str]:
        return [_validate_domain(item) for item in value]

    @field_validator("http01_address")
    @classmethod
    def validate_http01_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_ip(value)


class CertificatesConfig(StrictModel):
    mode: Literal["auto", "external"] = "auto"
    ca_name: str = "Korvus Node CA"
    server_cert: Path | None = None
    server_key: Path | None = None
    ca_cert: Path | None = None
    letsencrypt: LetsEncryptConfig = Field(default_factory=LetsEncryptConfig)

    @model_validator(mode="after")
    def require_external_paths(self) -> CertificatesConfig:
        if self.mode == "external" and not (self.server_cert and self.server_key and self.ca_cert):
            raise ValueError(
                "certificates.server_cert, server_key and ca_cert are required in external mode"
            )
        return self


class PasswordAuthConfig(StrictModel):
    enabled: bool = True


class CertificateAuthConfig(StrictModel):
    enabled: bool = False


class OtpAuthConfig(StrictModel):
    enabled: bool = False
    ocserv_oath_auth: bool = False
    issuer: str = "Korvus Node"
    send_by_email: bool = False
    send_by_telegram: bool = False
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_starttls: bool = True
    smtp_test_recipient: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


class OidcPamConnectorConfig(StrictModel):
    service: str = "ocserv"
    gid_min: int | None = Field(default=1000, ge=0)


class OidcRadiusConnectorConfig(StrictModel):
    config_file: Path = Path("/etc/radiusclient/radiusclient.conf")
    groupconfig: bool = True
    nas_identifier: str | None = None
    group_separator: Literal["semicolon", "comma"] = "semicolon"


class OidcAuthConfig(StrictModel):
    enabled: bool = False
    connector: Literal["pam", "radius"] = "pam"
    pam: OidcPamConnectorConfig = Field(default_factory=OidcPamConnectorConfig)
    radius: OidcRadiusConnectorConfig = Field(default_factory=OidcRadiusConnectorConfig)


class AuthConfig(StrictModel):
    password: PasswordAuthConfig = Field(default_factory=PasswordAuthConfig)
    certificate: CertificateAuthConfig = Field(default_factory=CertificateAuthConfig)
    otp: OtpAuthConfig = Field(default_factory=OtpAuthConfig)
    oidc: OidcAuthConfig = Field(default_factory=OidcAuthConfig)

    @model_validator(mode="after")
    def require_auth_method(self) -> AuthConfig:
        if not (self.password.enabled or self.certificate.enabled or self.oidc.enabled):
            raise ValueError("at least one of password, certificate or oidc auth must be enabled")
        return self


class UpstreamProfileConfig(StrictModel):
    name: str
    # "openconnect" (default): kornode dials out itself and owns the whole
    # connect/disconnect/reconnect lifecycle, as every profile has always
    # worked. "external_interface": this profile only points at a device
    # that already exists on the host (e.g. a WireGuard interface the admin
    # brought up outside kornode entirely) -- kornode never creates, brings
    # up, tears down, or redials it, it only applies the same routing/
    # nftables/split-DNS automation on top of it. See
    # UpstreamService._profile_connected/connect/disconnect.
    kind: Literal["openconnect", "external_interface"] = "openconnect"
    server: str | None = None
    port: str = "443"
    # Whether the watchdog should keep this profile dialed at all. A
    # disabled profile is never connected (and gets disconnected if it
    # already is), and is never eligible to be the active/selected profile
    # -- disabling the currently active one drops it and leaves no active
    # profile selected, since picking a replacement is the user's call, not
    # automatic. See UpstreamService.selected_profile/enforce_profile_enablement.
    enabled: bool = True
    # Tunnel device for this profile's own connection. Every profile keeps
    # its own interface so several upstream connections can be up at the
    # same time (failover then just re-points routing at another device
    # instead of dialing from scratch). Unset -> derived per profile, see
    # UpstreamConfig.profile_interface().
    interface: str | None = None
    auth_type: Literal["password", "cert", "p12"] = "password"
    trusted_cert: bool = False
    username: str | None = None
    password: str | None = None
    cert_file: Path | None = None
    cert_file_base64: str | None = None
    key_file: Path | None = None
    key_file_base64: str | None = None
    cert_pass: str | None = None
    server_cert_pin: str | None = None
    check_host: str | None = None
    # ocserv camouflage on the UPSTREAM server: appended as a "/?secret"
    # suffix after host:port (see UpstreamService.openconnect_argv), not
    # part of the port number itself. Optional -- most upstreams don't use
    # camouflage.
    camouflage_secret: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        # First character alnum, not letter-only: this exists to keep
        # profile.name safe as a path segment (UpstreamService.
        # _profile_secrets_dir() does secrets_dir / "upstream" / profile.name)
        # -- a leading digit doesn't affect that at all, since "." and "/"
        # are excluded from every position either way. No real reason to
        # reject a name like "4laddin".
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", value):
            raise ValueError("upstream.profiles[].name must be a short identifier")
        if profile_slug(value) == "active":
            raise ValueError("upstream profile name is reserved for the active alias")
        return value

    @field_validator("check_host")
    @classmethod
    def validate_check_host(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        return _validate_ip(value)

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        return _validate_interface_name(value)

    @field_validator("cert_file_base64", "key_file_base64")
    @classmethod
    def validate_base64(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        # Standard base64 tools wrap output at 64/76 chars (e.g. `base64
        # file.p12`); strip that whitespace instead of rejecting it, the
        # same way base64.b64decode's own default (non-strict) mode does.
        cleaned = "".join(value.split())
        if not cleaned:
            return None
        try:
            base64.b64decode(cleaned, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("must be valid base64") from exc
        return cleaned

    @model_validator(mode="after")
    def validate_kind_fields(self) -> UpstreamProfileConfig:
        if self.kind == "openconnect":
            if not self.server:
                raise ValueError(f"upstream profile {self.name!r} requires server")
            if self.auth_type == "password" and not self.username:
                raise ValueError(f"upstream profile {self.name!r} requires username")
            if self.auth_type in {"cert", "p12"} and not (self.cert_file or self.cert_file_base64):
                raise ValueError(
                    f"upstream profile {self.name!r} requires cert_file or cert_file_base64"
                )
            if self.cert_file and self.cert_file_base64:
                raise ValueError(
                    f"upstream profile {self.name!r}: set cert_file or cert_file_base64, not both"
                )
            if self.key_file and self.key_file_base64:
                raise ValueError(
                    f"upstream profile {self.name!r}: set key_file or key_file_base64, not both"
                )
        elif not self.interface:
            # external_interface: kornode can't invent a device name for an
            # interface it doesn't own, so unlike the openconnect case
            # (UpstreamConfig.profile_interface() derives oc-middle0/
            # oc-up<N> when unset) this must be given explicitly.
            raise ValueError(
                f"upstream profile {self.name!r}: kind='external_interface' requires "
                "'interface' (the pre-existing device kornode should route through)"
            )
        return self


class UpstreamConfig(StrictModel):
    enabled: bool = False
    interface: str = "oc-middle0"
    active_profile: str | None = None
    check_interval: int = Field(default=5, ge=1)
    check_threshold: int = Field(default=3, ge=1)
    # A freshly (re)connected tunnel's routing/DPD needs a moment to settle;
    # health-check failures inside this window after a recover() don't count
    # toward the next consecutive_failures streak, so a still-settling tunnel
    # can't immediately re-trigger another recover() before the last one had
    # a chance to stabilize (see UpstreamWatch in cli.py).
    check_settle_seconds: int = Field(default=15, ge=0)
    failover: bool = False
    # Whether the watchdog should dial the selected profile on its own the
    # first time it sees it down after the process starts (container/service
    # boot). When off, upstream stays disconnected after a restart until an
    # admin explicitly connects it -- once any connection succeeds, normal
    # health-check-triggered reconnection resumes regardless of this flag
    # (it only gates that very first dial). See UpstreamWatch in cli.py.
    connect_on_boot: bool = True
    profiles: list[UpstreamProfileConfig] = Field(default_factory=list)

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        return _validate_interface_name(value)

    @model_validator(mode="after")
    def validate_profiles(self) -> UpstreamConfig:
        names = [profile.name for profile in self.profiles]
        if len(names) != len(set(names)):
            raise ValueError("upstream profile names must be unique")
        if self.enabled and not self.profiles:
            raise ValueError("upstream.profiles is required when upstream is enabled")
        if self.active_profile and self.active_profile not in names:
            raise ValueError("upstream.active_profile must match an existing profile")
        interfaces = [self.profile_interface(profile) for profile in self.profiles]
        if len(interfaces) != len(set(interfaces)):
            raise ValueError(
                "upstream profiles must use distinct interfaces so their "
                "connections can be up simultaneously"
            )
        # `via: upstream:<slug>` names a profile by its slug (profile_slug()); two
        # names colliding after normalization (e.g. "My-VPN" and "my_vpn") would be
        # one exit.
        safe_names = [profile_slug(profile.name) for profile in self.profiles]
        if len(safe_names) != len(set(safe_names)):
            raise ValueError(
                "upstream profile names must remain distinct once normalized to "
                "a-z0-9_ for their nftables set names"
            )
        return self

    def selected_profile(self) -> UpstreamProfileConfig | None:
        """The effective active profile, or None if there isn't one.

        A disabled profile is never returned here, even if it's the
        explicitly configured active_profile or the first in the list:
        disabling a profile always means "not active", not just "not
        auto-maintained". Falls back to the first *enabled* profile when
        active_profile isn't set (or is itself disabled) -- there's no
        automatic promotion of some other profile in its place.
        """
        if self.active_profile:
            for profile in self.profiles:
                if profile.name == self.active_profile:
                    return profile if profile.enabled else None
        for profile in self.profiles:
            if profile.enabled:
                return profile
        return None

    def profile_interface(self, profile: UpstreamProfileConfig) -> str:
        """Tunnel device this profile's connection uses.

        Explicit profile.interface wins. Without it, the first profile
        keeps the top-level upstream.interface (existing single-profile
        configs stay on the device they already run on) and later ones get
        a stable oc-up<N> derived from their list position.
        """
        if profile.interface:
            return profile.interface
        for index, candidate in enumerate(self.profiles):
            if candidate.name == profile.name:
                return self.interface if index == 0 else f"oc-up{index}"
        return self.interface


class RoutingConfig(StrictModel):
    """Host-level settings only. What leaves where is the top-level `egress`/`sources`/`sets`
    (docs/spec/02-egress-and-sources.md); the old client_policy/host_policy/split keys are
    gone (D-70) and rejected as unknown."""

    # Point the HOST's own resolver at the built-in dnsmasq so the host's own lookups
    # get the blocklist/local-records effect (see services/host_dns.py). Needs
    # network_mode: host plus a mount of the host file/directory:
    #   resolv_conf -- /etc/resolv.conf:/host/etc/resolv.conf, rewritten in
    #                  place and restored when kornode stops;
    #   resolved    -- /etc/systemd/resolved.conf.d:/host/resolved.conf.d, a
    #                  systemd-resolved drop-in (restart resolved once).
    # Only asserted while dnsmasq actually runs (dns_tunnel_active()), so
    # the host never ends up pointed at a resolver that isn't there.
    host_dns: Literal["off", "resolv_conf", "resolved"] = "off"
    main_interface: str = "auto"

    @field_validator("host_dns", mode="before")
    @classmethod
    def validate_literal_off(cls, value: object) -> object:
        # "off" is a YAML/env boolean word: YAML 1.1 and parse_env_value()
        # both turn it into False before this model sees it. Map it back so
        # `host_dns: off` means the literal string "off", not the boolean.
        if value is False:
            return "off"
        return value

    @field_validator("main_interface")
    @classmethod
    def validate_main_interface(cls, value: str) -> str:
        # Rendered into the nft kill-switch (`oifname "<uplink>"`).
        return value if value == "auto" else _validate_interface_name(value)


class InternalDnsConfig(StrictModel):
    listen: str = "10.100.1.1"
    port: int = Field(default=53, ge=1, le=65535)
    blocklist_enabled: bool = False
    local_records_enabled: bool = False
    blocklist_domains: list[str] = Field(default_factory=list)
    blocklist_files: list[Path] = Field(default_factory=list)
    blocklist_urls: list[str] = Field(default_factory=list)
    cache_size: int = Field(default=150, ge=0, le=10000)
    log_queries: bool = False
    local_records: list[str] = Field(default_factory=list)
    # What the built-in resolver forwards unmatched queries to. Unlike the
    # legacy default_upstreams this replaced, there is no fallback to
    # server.dns: the resolver always runs while server.enabled (see
    # AppConfig.client_dns_servers()), so it needs its own real default.
    upstreams: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    forward_upstreams: list[str] = Field(default_factory=list)
    forward_domains: list[str] = Field(default_factory=list)

    @field_validator("listen")
    @classmethod
    def validate_listen(cls, value: str) -> str:
        return _validate_ip(value)

    @field_validator("blocklist_domains")
    @classmethod
    def validate_blocklist_domains(cls, value: list[str]) -> list[str]:
        return [_validate_blocklist_domain(item) for item in value]

    @field_validator("blocklist_files")
    @classmethod
    def validate_blocklist_files(cls, value: list[Path]) -> list[Path]:
        return _dedup_paths(value)

    @field_validator("blocklist_urls")
    @classmethod
    def validate_blocklist_urls(cls, value: list[str]) -> list[str]:
        return _validate_http_url_list(value, field_name="internal_dns.blocklist_urls")

    @field_validator("local_records")
    @classmethod
    def validate_local_records(cls, value: list[str]) -> list[str]:
        return [_validate_local_record(item) for item in value]

    @field_validator("upstreams")
    @classmethod
    def validate_upstreams(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(_validate_ip(resolver) for resolver in value))

    @field_validator("forward_upstreams")
    @classmethod
    def validate_forward_upstreams(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(_validate_ip(resolver) for resolver in value))

    @field_validator("forward_domains")
    @classmethod
    def validate_forward_domains(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(_validate_domain(domain).lower() for domain in value))

    @model_validator(mode="after")
    def validate_forward_pairing(self) -> InternalDnsConfig:
        if bool(self.forward_upstreams) != bool(self.forward_domains):
            raise ValueError(
                "internal_dns.forward_upstreams and internal_dns.forward_domains "
                "must either both be configured or both be empty"
            )
        return self


class OidcProviderConfig(StrictModel):
    name: str
    issuer_url: str
    client_id: str
    client_secret: str | None = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    username_claim: str = "preferred_username"
    groups_claim: str = "groups"
    allowed_groups: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        # See UpstreamProfileConfig.validate_name's comment on allowing a
        # leading digit -- same identifier-safety reasoning applies here.
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", value):
            raise ValueError("identity.oidc.providers.name must be a short identifier")
        return value

    @field_validator("issuer_url")
    @classmethod
    def validate_issuer_url(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("identity.oidc.providers.issuer_url must be an HTTP(S) URL")
        return value.rstrip("/")


class GroupPolicyConfig(StrictModel):
    name: str
    display_name: str | None = None
    routes: list[str] = Field(default_factory=list)
    no_routes: list[str] = Field(default_factory=list)
    dns: list[str] = Field(default_factory=list)
    split_dns: list[str] = Field(default_factory=list)
    tunnel_all_dns: bool | None = None
    max_same_clients: int | None = Field(default=None, ge=1)
    session_timeout: int | None = Field(default=None, ge=1)
    idle_timeout: int | None = Field(default=None, ge=1)
    no_udp: bool | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not re.match(r"^[A-Za-z0-9_.@-]{1,64}$", value):
            raise ValueError("identity.group_policies.name must be ocserv group-safe")
        if value.lower() in RESERVED_GROUPS:
            raise ValueError(f"group '{value}' is reserved")
        return value

    @field_validator("routes", "no_routes")
    @classmethod
    def validate_routes(cls, value: list[str]) -> list[str]:
        return [_validate_cidr(item) for item in value]

    @field_validator("dns")
    @classmethod
    def validate_dns(cls, value: list[str]) -> list[str]:
        return [_validate_ip(item) for item in value]

    @field_validator("split_dns")
    @classmethod
    def validate_split_dns(cls, value: list[str]) -> list[str]:
        return [_validate_domain(item) for item in value]


class IdentityConfig(StrictModel):
    config_per_group_dir: Path | None = None
    config_per_user_dir: Path | None = None
    default_group_config: Path | None = None
    select_group_by_url: bool = False
    default_select_group: str | None = None
    oidc_providers: list[OidcProviderConfig] = Field(default_factory=list)
    group_policies: list[GroupPolicyConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_identity(self) -> IdentityConfig:
        provider_names = [provider.name for provider in self.oidc_providers]
        if len(provider_names) != len(set(provider_names)):
            raise ValueError("identity.oidc_providers names must be unique")
        group_names = [group.name for group in self.group_policies]
        if len(group_names) != len(set(group_names)):
            raise ValueError("identity.group_policies names must be unique")
        if self.default_select_group and self.default_select_group not in group_names:
            raise ValueError("identity.default_select_group must match a group policy")
        return self


class WebConfig(StrictModel):
    enabled: bool = False
    listen: str = "127.0.0.1"
    port: int = Field(default=8443, ge=1, le=65535)
    tls: bool = True
    tls_cert: Path | None = None
    tls_key: Path | None = None
    allow_insecure_http: bool = False
    trusted_proxies: list[str] = Field(default_factory=list)
    admin_user: str = "admin"
    admin_password: str | None = None
    admin_password_hash: str | None = None
    static_dir: Path = Path("/usr/share/kornode/frontend")
    terminal_enabled: bool = False
    terminal_idle_timeout: int = Field(default=900, ge=60, le=86400)
    terminal_max_sessions: int = Field(default=2, ge=1, le=10)
    # Serves GET /api/client/routing (api/routes_client_sync.py), polled by a
    # Korvus Client for mid-session route/split-DNS refresh. That
    # endpoint has no admin auth by design (VPN clients authenticate by
    # their session source IP instead), so unlike most other web.* surfaces
    # it needs its own default-off gate distinct from `enabled`: turning on
    # the admin panel must never also quietly expose this unauthenticated
    # endpoint.
    client_sync_enabled: bool = False
    session_lifetime: int = Field(default=43200, ge=300, le=86400)
    session_cookie_secure: bool = True
    admin_totp_enabled: bool = False
    admin_totp_secret: str | None = None

    @field_validator("trusted_proxies")
    @classmethod
    def validate_trusted_proxies(cls, value: list[str]) -> list[str]:
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ValueError(
                    "web.trusted_proxies entries must be IP addresses or CIDR networks"
                ) from exc
        return value

    @model_validator(mode="after")
    def validate_public_bind(self) -> WebConfig:
        if self.enabled and not (self.admin_password or self.admin_password_hash):
            raise ValueError(
                "web.admin_password or web.admin_password_hash is required when web.enabled is true"
            )
        if (self.tls_cert is None) != (self.tls_key is None):
            raise ValueError("web.tls_cert and web.tls_key must be configured together")
        if (
            self.enabled
            and self.listen == "0.0.0.0"
            and not self.tls
            and not self.allow_insecure_http
        ):
            raise ValueError(
                "web.tls or web.allow_insecure_http must be enabled before binding "
                "the API to 0.0.0.0"
            )
        if self.admin_totp_enabled and not self.admin_totp_secret:
            raise ValueError(
                "web.admin_totp_secret is required when web.admin_totp_enabled is true"
            )
        return self


class CliConfig(StrictModel):
    enabled: bool = True


RawOcservOptions = list[str] | dict[str, str | int | bool | None]


class AdvancedConfig(StrictModel):
    raw_ocserv_options: RawOcservOptions = Field(default_factory=list)


def _context_explicit_paths(info: ValidationInfo) -> set[tuple[str, ...]] | None:
    if isinstance(info.context, dict):
        paths = info.context.get("explicit_paths")
        if isinstance(paths, set):
            return {tuple(str(part) for part in path) for path in paths}
    return None


def _raw_has_path(data: Any, path: tuple[str, ...]) -> bool:
    current = data
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return True


def _is_explicit(data: Any, info: ValidationInfo, path: tuple[str, ...]) -> bool:
    explicit_paths = _context_explicit_paths(info)
    if explicit_paths is not None:
        return path in explicit_paths
    return _raw_has_path(data, path)


def _raw_section(data: dict[str, Any], name: str) -> dict[str, Any]:
    section = data.get(name)
    return dict(section) if isinstance(section, dict) else {}


class AppConfig(StrictModel):
    @model_validator(mode="before")
    @classmethod
    def derive_interlink_defaults(cls, data: Any, info: ValidationInfo) -> Any:
        if not isinstance(data, dict):
            return data
        interlink_raw = _raw_section(data, "interlink")

        node_raw = _raw_section(data, "node")
        node_id = int(node_raw.get("id", 1))
        interlink_cidr = str(interlink_raw.get("cidr", "10.99.0.0/24"))
        client_pool = str(interlink_raw.get("client_pool", "10.100.{id}.0/24"))
        source_pool = str(interlink_raw.get("source_pool", "10.8.{id}.0/24"))
        enroll_pool = str(interlink_raw.get("enroll_pool", "10.99.255.240/28"))
        domain = str(interlink_raw.get("domain", "kornode.lan"))
        reserved_raw = interlink_raw.get("reserved", [])
        reserved = [str(item) for item in reserved_raw] if isinstance(reserved_raw, list) else []
        try:
            derived = derive_addresses(
                node_id,
                interlink_cidr=interlink_cidr,
                client_pool=client_pool,
                source_pool=source_pool,
                domain=domain,
            )
        except PolicyError as exc:
            raise ValueError(str(exc)) from exc

        server = _raw_section(data, "server")
        internal_dns = _raw_section(data, "internal_dns")
        server_explicit = _is_explicit(data, info, ("server", "ipv4_network"))
        dns_explicit = _is_explicit(data, info, ("internal_dns", "listen"))

        if not server_explicit:
            server["ipv4_network"] = str(derived.client_pool)
        try:
            client_network = ipaddress.ip_network(str(server["ipv4_network"]), strict=False)
        except ValueError:
            # server.ipv4_network's own field validator reports a malformed value.
            return data
        if not dns_explicit:
            # The service address follows the pool: the derived one, or the first host
            # of a customized server.ipv4_network.
            internal_dns["listen"] = (
                str(client_network.network_address + 1)
                if server_explicit
                else str(derived.service_address)
            )

        conflicts: list[Conflict] = []
        owned = [
            OwnedPrefix(derived.source_pool, node_id, "source"),
            OwnedPrefix(
                client_network,
                node_id,
                "client_pool",
                adding=True,
            ),
        ]
        overlap_result = check_overlaps(
            owned,
            interlink_cidr=interlink_cidr,
            reserved=reserved,
            enroll_pool=enroll_pool,
        )
        conflicts.extend(overlap_result.errors)
        if conflicts:
            raise AddressOverlapError(conflicts)

        updated = dict(data)
        updated["server"] = server
        updated["internal_dns"] = internal_dns
        return updated

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_dns_keys(cls, data: Any) -> Any:
        # Needs both internal_dns and server in the same pass (unlike the
        # self-contained migrations on RoutingConfig/RoutingSplitConfig), so
        # it has to run here, before AppConfig's nested models are built --
        # and on the raw dict passed to model_validate(), not a merged
        # config.loader.py dict: that's what lets this see "listen was never
        # set" regardless of whether the caller is the loader, a config
        # PATCH, or a test building an AppConfig directly. That's also why
        # config/defaults.py deliberately leaves internal_dns.listen out.
        if not isinstance(data, dict):
            return data
        raw_internal_dns = data.get("internal_dns")
        if raw_internal_dns is not None and not isinstance(raw_internal_dns, dict):
            return data
        internal_dns = dict(raw_internal_dns) if raw_internal_dns else {}
        warnings: list[str] = []
        if "resolver_enabled" in internal_dns:
            internal_dns.pop("resolver_enabled")
            warnings.append("internal_dns.resolver_enabled")
        if "default_upstreams" in internal_dns:
            legacy_value = internal_dns.pop("default_upstreams")
            if "upstreams" not in internal_dns:
                if legacy_value:
                    internal_dns["upstreams"] = legacy_value
                else:
                    # The old fallback: an empty default_upstreams meant
                    # "use server.dns". Snapshot that here, once, since the
                    # fallback itself is gone -- upstreams is independent of
                    # server.dns from now on.
                    server = data.get("server")
                    fallback = server.get("dns") if isinstance(server, dict) else None
                    if fallback:
                        internal_dns["upstreams"] = fallback
            warnings.append("internal_dns.default_upstreams")
        if warnings:
            _LOGGER.warning(
                "config: migrated legacy keys %s; the built-in resolver now runs "
                "automatically whenever the VPN server is enabled",
                ", ".join(warnings),
            )
        # internal_dns.listen must be reachable from server.ipv4_network --
        # the resolver is mandatory, not opt-in, while server.enabled (see
        # client_dns_servers()). The model default (10.100.1.1) only matches
        # the model default ipv4_network (10.100.1.0/24); a deployment that
        # customizes ipv4_network without separately customizing listen
        # would otherwise fail validation for an unrelated-looking reason.
        # An explicit listen always wins -- this only fills the gap.
        if "listen" not in internal_dns:
            server = data.get("server")
            ipv4_network = server.get("ipv4_network") if isinstance(server, dict) else None
            if ipv4_network:
                try:
                    network = ipaddress.ip_network(ipv4_network, strict=False)
                    internal_dns["listen"] = str(next(network.hosts()))
                except (ValueError, StopIteration):
                    pass  # let the normal field/cross-field validators raise
        if internal_dns:
            data = dict(data)
            data["internal_dns"] = internal_dns
        return data

    node: NodeConfig = Field(default_factory=NodeConfig)
    interlink: InterlinkConfig = Field(default_factory=InterlinkConfig)
    control: ControlConfig = Field(default_factory=ControlConfig)
    system: SystemConfig = Field(default_factory=SystemConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    certificates: CertificatesConfig = Field(default_factory=CertificatesConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    # Declarative hub egress (P4-06 part 2, docs/spec/02-egress-and-sources.md); the
    # same model the agents use. Registry-dependent checks live in services/hub_egress.
    sources: tuple[Source, ...] = ()
    sets: dict[str, DestSet] = Field(default_factory=dict)
    # Without an explicit `egress` the hub's clients leave through the uplink (D-72); an
    # explicit list replaces this rule and everything not matched is dropped (spec 02).
    egress: tuple[Rule, ...] = Field(default_factory=lambda: (_default_hub_rule(),))
    internal_dns: InternalDnsConfig = Field(default_factory=InternalDnsConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    cli: CliConfig = Field(default_factory=CliConfig)
    advanced: AdvancedConfig = Field(default_factory=AdvancedConfig)

    def exported_source_cidrs(self) -> list[str]:
        """Hub source subnets announced to the agents (bundle prefixes, per-user `route`)."""
        return [source.cidr for source in self.sources if source.export]

    def egress_policy(self) -> EgressPolicy:
        return EgressPolicy(sources=self.sources, sets=self.sets, egress=self.egress)

    @model_validator(mode="after")
    def validate_hub_egress(self) -> AppConfig:
        # Builds the policy: duplicate names and unknown source/set references raise here.
        policy = self.egress_policy()
        derived = derive_addresses(
            self.node.id,
            interlink_cidr=self.interlink.cidr,
            client_pool=self.interlink.client_pool,
            source_pool=self.interlink.source_pool,
            domain=self.interlink.domain,
        )
        client_pool = ipaddress.ip_network(self.server.ipv4_network, strict=False)
        fixed = {
            "the client pool": client_pool,
            "interlink.cidr": ipaddress.ip_network(self.interlink.cidr, strict=False),
            "interlink.enroll_pool": ipaddress.ip_network(self.interlink.enroll_pool, strict=False),
        }
        seen: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
        interfaces: set[str] = set()
        for source in policy.sources:
            net = ipaddress.ip_network(source.cidr)
            if not source.allow_outside_pool and not net.subnet_of(derived.source_pool):  # type: ignore[arg-type]
                raise ValueError(
                    f"source {source.name}: {net} is outside the source pool {derived.source_pool}"
                    " (set allow_outside_pool: true to override)"
                )
            for label, other in (*fixed.items(), *seen.items()):
                if net.version == other.version and net.overlaps(other):
                    raise ValueError(f"source {source.name}: {net} overlaps {label} ({other})")
            if source.interface in interfaces:
                raise ValueError(f"source {source.name}: interface {source.interface} is reused")
            interfaces.add(source.interface)
            seen[f"source {source.name}"] = net
        for index, rule in enumerate(policy.egress):
            via = rule.parsed_via
            if via.kind != "node":
                continue
            if "host" in rule.from_:
                raise ValueError(f"egress[{index}]: host traffic cannot use {rule.via}")
            for name in rule.from_:
                src = next((s for s in policy.sources if s.name == name), None)
                if src is not None and not src.export:
                    raise ValueError(
                        f"egress[{index}]: source {name} must be exported to use {rule.via}"
                    )
        return self

    @model_validator(mode="after")
    def validate_control(self) -> AppConfig:
        if self.control.signing_key is None:
            self.control.signing_key = self.system.data_dir / "control" / "signing.ed25519"
        return self

    @model_validator(mode="after")
    def validate_routing_compatibility(self) -> AppConfig:
        if self.identity.config_per_user_dir is None:
            self.identity.config_per_user_dir = self.system.generated_dir / "config-per-user"
        if self.identity.config_per_group_dir is None:
            self.identity.config_per_group_dir = self.system.generated_dir / "config-per-group"
        if self.certificates.letsencrypt.http01_address is None:
            self.certificates.letsencrypt.http01_address = self.server.listen
        # server.ipv4_network is the address pool ocserv hands out to ITS
        # OWN VPN clients -- a real, meaningful constraint only while
        # server.enabled: true. In client-only deployments (server.enabled:
        # false, e.g. examples/config.client.yaml) there are no VPN clients
        # at all, so server.ipv4_network is just an inert default -- every
        # "must/must not overlap the VPN client subnet" check below only
        # makes sense, and so only applies, while the server actually runs.
        vpn_network = ipaddress.ip_network(self.server.ipv4_network, strict=False)
        if self.upstream.enabled:
            profile = self.upstream.selected_profile()
            if self.server.enabled and profile and profile.check_host:
                check_ip = ipaddress.ip_address(profile.check_host)
                if check_ip in vpn_network:
                    raise ValueError("upstream.check_host must not be inside the VPN client subnet")
        # client_dns_servers() always returns internal_dns.listen while
        # server.enabled (the resolver is mandatory then -- see
        # dnsmasq_active_reasons()/client_dns_servers() below), so that's the
        # precise condition for requiring listen to be reachable from the
        # VPN client subnet, independent of any other dnsmasq-active reason.
        if self.server.enabled:
            listen_ip = ipaddress.ip_address(self.internal_dns.listen)
            if listen_ip not in vpn_network:
                raise ValueError(
                    "internal_dns.listen must be inside server.ipv4_network "
                    "so VPN clients can reach the built-in DNS resolver"
                )
        return self

    def dnsmasq_active_reasons(self) -> list[str]:
        """Return the configured features that require project-owned dnsmasq."""
        reasons: list[str] = []
        settings = self.internal_dns
        # The resolver is mandatory, not opt-in, whenever the VPN server
        # itself is enabled -- see client_dns_servers().
        if self.server.enabled:
            reasons.append("server_enabled")
        if settings.blocklist_enabled:
            reasons.append("blocklist_enabled")
        if settings.local_records_enabled:
            reasons.append("local_records_enabled")
        if settings.forward_domains:
            reasons.append("forward_domains")
        # The hub answers the interlink zone for agents and clients (D-66).
        if self.server.enabled:
            reasons.append("interlink_dns")
        return reasons

    def dns_tunnel_active(self) -> bool:
        """Whether the project-owned dnsmasq instance must run."""
        return bool(self.dnsmasq_active_reasons())

    def client_dns_servers(self) -> list[str]:
        """DNS servers pushed to VPN clients by ocserv.

        Always the built-in resolver while the VPN server is enabled --
        there is no opt-out, see dnsmasq_active_reasons(). server.dns only
        still applies in a client-only/middle-server deployment that has no
        VPN clients of its own to push DNS to in the first place.
        """
        if self.server.enabled:
            return [self.internal_dns.listen]
        return self.server.dns

    def generated_path(self, name: str) -> Path:
        return self.system.generated_dir / name

    def secret_path(self, name: str) -> Path:
        return self.system.secrets_dir / name

    def cert_path(self, name: str) -> Path:
        return self.system.data_dir / "certs" / name

    def web_tls_cert_path(self) -> Path:
        if self.web.tls_cert is not None:
            return self.web.tls_cert
        if self.certificates.server_cert is not None:
            return self.certificates.server_cert
        return self.cert_path("server.crt")

    def web_tls_key_path(self) -> Path:
        if self.web.tls_key is not None:
            return self.web.tls_key
        if self.certificates.server_key is not None:
            return self.certificates.server_key
        return self.cert_path("server.key")

    def model_dump_safe(self) -> dict[str, Any]:
        from kornode.services.secrets import redact_value

        return cast(dict[str, Any], redact_value(self.model_dump(mode="json")))
