from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


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


RESERVED_ROUTING_TABLE_IDS = frozenset({253, 254, 255})


def _validate_routing_table_id(value: int, *, field_name: str) -> int:
    if value in RESERVED_ROUTING_TABLE_IDS:
        raise ValueError(
            f"{field_name} must not be one of the kernel-reserved routing "
            f"table IDs {sorted(RESERVED_ROUTING_TABLE_IDS)} "
            "(default/main/local) -- using one would corrupt the host's own "
            "routing table"
        )
    return value


def profile_safe_name(name: str) -> str:
    """Normalize an upstream profile name into an nftables-safe identifier
    for set names (e.g. "My-VPN" -> "my_vpn"). Shared with
    RoutingService.list_targets() so the uniqueness check in
    UpstreamConfig.validate_profiles() below stays in sync with what actually
    gets rendered -- two profiles colliding on their normalized name would
    otherwise make the whole nft ruleset load fail."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower())


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
    ipv4_network: str = "10.10.10.0/24"
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
    # Route these specific CIDRs/domains through THIS profile specifically,
    # regardless of which profile is active/default. Distinct from
    # routing.split.routes/domains, which target whichever profile is
    # currently active. Gets its own fwmark/table/kill-switch, auto-derived
    # -- see RoutingService.list_targets(). Only applied to CLIENT
    # (VPN-subnet-forwarded) traffic when route_clients_enabled is set --
    # default True so upgrading configs that already populated these lists
    # keep working unchanged.
    route_clients_enabled: bool = True
    routes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    routes_files: list[Path] = Field(default_factory=list)
    routes_urls: list[str] = Field(default_factory=list)
    domains_files: list[Path] = Field(default_factory=list)
    domains_urls: list[str] = Field(default_factory=list)
    # Same idea as routes/domains above, but for the HOST's own traffic
    # routed through this specific profile -- independent toggle and lists,
    # since an admin may want a profile to carry client traffic, host
    # traffic, or both, on entirely different route/domain sets. New in this
    # release, so no compatibility default needed: off until explicitly
    # enabled.
    route_host_enabled: bool = False
    host_routes: list[str] = Field(default_factory=list)
    host_domains: list[str] = Field(default_factory=list)
    # Server-driven host routing (the former korclient): take the routes
    # (`route =`, CISCO_SPLIT_INC) and split-DNS domains (`split-dns =`,
    # CISCO_SPLIT_DNS) the upstream server pushes in the connect handshake
    # and add them to this profile's host routing on top of host_routes/
    # host_domains. Pushed domains resolve through the upstream's own DNS
    # (INTERNAL_IP4_DNS), itself routed through this tunnel. Only has an
    # effect together with route_host_enabled. See services/upstream_pushed.py.
    accept_server_routes: bool = False
    # Mid-session refresh of those pushed lists: poll the upstream kornode
    # panel's GET /api/client/routing through this profile's own tunnel
    # (curl --interface), so edits made on the server apply without a
    # reconnect. The endpoint identifies the caller by its VPN address, so
    # point this at the panel address reachable inside the tunnel, e.g.
    # https://10.10.10.1:8443. Unset -> handshake lists only.
    sync_url: str | None = None
    sync_interval: int = Field(default=60, ge=10)
    # The request already travels inside this profile's authenticated
    # tunnel, and an upstream panel usually runs on its own self-signed
    # certificate, so TLS verification of the panel is opt-in.
    sync_verify_tls: bool = False
    # Explicit override for the fwmark/table_id offset this profile's named
    # routing target uses (see RoutingService.list_targets()). Unset ->
    # derived from this profile's fixed position in upstream.profiles, the
    # same "explicit wins, otherwise stable by list position" pattern as
    # `interface` above -- deriving it from a count of *other* profiles that
    # currently have routes/domains would silently reassign this profile's
    # live fwmark/table whenever an unrelated profile's routes/domains change.
    routing_offset: int | None = Field(default=None, ge=1)

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
        return value

    @field_validator("routes")
    @classmethod
    def validate_routes(cls, value: list[str]) -> list[str]:
        return [_validate_cidr(item) for item in value]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, value: list[str]) -> list[str]:
        return [_validate_domain(item) for item in value]

    @field_validator("routes_files", "domains_files")
    @classmethod
    def validate_list_files(cls, value: list[Path]) -> list[Path]:
        return _dedup_paths(value)

    @field_validator("routes_urls")
    @classmethod
    def validate_routes_urls(cls, value: list[str]) -> list[str]:
        return _validate_http_url_list(value, field_name="upstream.profiles[].routes_urls")

    @field_validator("domains_urls")
    @classmethod
    def validate_domains_urls(cls, value: list[str]) -> list[str]:
        return _validate_http_url_list(value, field_name="upstream.profiles[].domains_urls")

    @field_validator("host_routes")
    @classmethod
    def validate_host_routes(cls, value: list[str]) -> list[str]:
        return [_validate_cidr(item) for item in value]

    @field_validator("host_domains")
    @classmethod
    def validate_host_domains(cls, value: list[str]) -> list[str]:
        return [_validate_domain(item) for item in value]

    @field_validator("check_host")
    @classmethod
    def validate_check_host(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        return _validate_ip(value)

    @field_validator("sync_url")
    @classmethod
    def validate_sync_url(cls, value: str | None) -> str | None:
        if value is None or value.strip() == "":
            return None
        candidate = value.strip().rstrip("/")
        if not candidate.startswith(("https://", "http://")):
            raise ValueError("upstream.profiles[].sync_url must be an HTTP(S) URL")
        if any(char.isspace() for char in candidate):
            raise ValueError("upstream.profiles[].sync_url must not contain whitespace")
        return candidate

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
        else:
            # external_interface: kornode can't invent a device name for an
            # interface it doesn't own, so unlike the openconnect case
            # (UpstreamConfig.profile_interface() derives oc-middle0/
            # oc-up<N> when unset) this must be given explicitly.
            if not self.interface:
                raise ValueError(
                    f"upstream profile {self.name!r}: kind='external_interface' requires "
                    "'interface' (the pre-existing device kornode should route through)"
                )
            # No vpnc-script handshake and no kornode panel on the other end
            # of a plain externally-managed interface, so there's nothing
            # for these to poll/parse.
            if self.accept_server_routes or self.sync_url:
                raise ValueError(
                    f"upstream profile {self.name!r}: accept_server_routes/sync_url require "
                    "kind='openconnect'"
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
        # The nftables set name for a profile's named routing target is its
        # name normalized to [a-z0-9_] (see RoutingService.list_targets());
        # two distinct names colliding after normalization (e.g. "My-VPN" and
        # "my_vpn") would render two identically-named nft sets and break the
        # whole ruleset load.
        safe_names = [profile_safe_name(profile.name) for profile in self.profiles]
        if len(safe_names) != len(set(safe_names)):
            raise ValueError(
                "upstream profile names must remain distinct once normalized to "
                "a-z0-9_ for their nftables set names"
            )
        # Each profile's fwmark/table_id offset (explicit routing_offset, or
        # derived from list position -- see profile_routing_offset()) must be
        # unique so two profiles' named routing targets never share a
        # fwmark/table.
        offsets = [self.profile_routing_offset(profile) for profile in self.profiles]
        if len(offsets) != len(set(offsets)):
            raise ValueError(
                "upstream profiles must use distinct routing_offset values "
                "(or leave it unset so it's derived from list position)"
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

    def profile_routing_offset(self, profile: UpstreamProfileConfig) -> int:
        """fwmark/table_id offset for this profile's own named routing
        target, added to routing.fwmark/table_id (see
        RoutingService.list_targets()).

        Explicit profile.routing_offset wins. Without it, derived from this
        profile's fixed 1-based position in upstream.profiles -- the same
        "explicit override, otherwise stable by list position" pattern as
        profile_interface() above. Deriving it instead from a count of only
        the *other* profiles that currently have routes/domains assigned
        would silently reassign this profile's live fwmark/table whenever an
        unrelated profile's routes/domains change.
        """
        if profile.routing_offset is not None:
            return profile.routing_offset
        for index, candidate in enumerate(self.profiles):
            if candidate.name == profile.name:
                return index + 1
        return 1


class RoutingSplitConfig(StrictModel):
    tunnel_dns: bool = False
    routes_file: Path = Path("/var/lib/kornode/routes.txt")
    domains_file: Path = Path("/var/lib/kornode/domains.txt")
    routes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    # Static, admin-configured external sources -- same shape as
    # internal_dns's blocklist_files/blocklist_urls: kornode reads/fetches
    # and caches these, merged in alongside the inline `routes`/`domains`
    # lists above and the separate runtime-editable routes_file/domains_file
    # (which `korctl routes/domains add/delete` manage). See
    # RoutingService.list_routes()/list_domains().
    routes_files: list[Path] = Field(default_factory=list)
    routes_urls: list[str] = Field(default_factory=list)
    domains_files: list[Path] = Field(default_factory=list)
    domains_urls: list[str] = Field(default_factory=list)

    @field_validator("routes")
    @classmethod
    def validate_routes(cls, value: list[str]) -> list[str]:
        # A single host is just a /32 (or /128) CIDR, so routes already
        # covers individual IPs -- no need for a separate "ips" list.
        return [_validate_cidr(item) for item in value]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, value: list[str]) -> list[str]:
        return [_validate_domain(item) for item in value]

    @field_validator("routes_files", "domains_files")
    @classmethod
    def validate_list_files(cls, value: list[Path]) -> list[Path]:
        return _dedup_paths(value)

    @field_validator("routes_urls")
    @classmethod
    def validate_routes_urls(cls, value: list[str]) -> list[str]:
        return _validate_http_url_list(value, field_name="routing.split.routes_urls")

    @field_validator("domains_urls")
    @classmethod
    def validate_domains_urls(cls, value: list[str]) -> list[str]:
        return _validate_http_url_list(value, field_name="routing.split.domains_urls")


class HostSplitConfig(StrictModel):
    """Same shape as RoutingSplitConfig's routes/domains lists (inline,
    runtime-editable file, static files, URLs), but for the HOST's own
    traffic under routing.host_mode: split -- deliberately a separate list
    from routing.split's, not shared, since an admin may want the host to
    follow entirely different routes/domains than clients do. No
    tunnel_dns or internal DNS listen/port fields here: those are about
    clients picking this server as their DNS, which has no host equivalent -- host
    domains are just resolved via whatever DNS the host itself already
    uses (see RoutingService.list_host_domains()).
    """

    routes_file: Path = Path("/var/lib/kornode/host-routes.txt")
    domains_file: Path = Path("/var/lib/kornode/host-domains.txt")
    routes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    routes_files: list[Path] = Field(default_factory=list)
    routes_urls: list[str] = Field(default_factory=list)
    domains_files: list[Path] = Field(default_factory=list)
    domains_urls: list[str] = Field(default_factory=list)

    @field_validator("routes")
    @classmethod
    def validate_routes(cls, value: list[str]) -> list[str]:
        return [_validate_cidr(item) for item in value]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, value: list[str]) -> list[str]:
        return [_validate_domain(item) for item in value]

    @field_validator("routes_files", "domains_files")
    @classmethod
    def validate_list_files(cls, value: list[Path]) -> list[Path]:
        return _dedup_paths(value)

    @field_validator("routes_urls")
    @classmethod
    def validate_routes_urls(cls, value: list[str]) -> list[str]:
        return _validate_http_url_list(value, field_name="routing.host_split.routes_urls")

    @field_validator("domains_urls")
    @classmethod
    def validate_domains_urls(cls, value: list[str]) -> list[str]:
        return _validate_http_url_list(value, field_name="routing.host_split.domains_urls")


class RoutingConfig(StrictModel):
    # Whether a connected client's traffic is routed through Upstream by
    # default at all (governed by `mode` below) when no profile claims it
    # specifically via its own route_clients_enabled. Off leaves clients on
    # plain host NAT even with Upstream enabled, relying only on explicit
    # per-profile targeting. Defaults True (not False, unlike host_traffic)
    # purely for upgrade compatibility: `mode` has always had an effect on
    # its own until this toggle was introduced, so defaulting it off would
    # silently stop routing client traffic for every already-configured
    # deployment the moment they upgrade.
    client_traffic: bool = True
    mode: Literal["full", "split"] = "full"
    # Route the server host's own traffic through upstream too: marks
    # host-originated packets in the nftables output hook, so the host
    # follows the same treatment as VPN clients without connecting to its
    # own ocserv. Independent of `mode` -- host_mode picks full/split for the
    # host's own traffic on its own terms, so e.g. "client full + host full"
    # marks all host traffic unconditionally instead of reusing the split
    # sets to approximate it.
    host_traffic: bool = False
    host_mode: Literal["full", "split"] = "full"
    # Point the HOST's own resolver at the built-in dnsmasq, so domain-based
    # host routing (host_split/host_domains, server-pushed split-DNS)
    # actually sees the host's lookups. Needs network_mode: host plus a
    # mount of the host file/directory (see services/host_dns.py):
    #   resolv_conf -- /etc/resolv.conf:/host/etc/resolv.conf, rewritten in
    #                  place and restored when kornode stops;
    #   resolved    -- /etc/systemd/resolved.conf.d:/host/resolved.conf.d, a
    #                  systemd-resolved drop-in (restart resolved once).
    # Only asserted while dnsmasq actually runs (dns_tunnel_active()), so
    # the host never ends up pointed at a resolver that isn't there.
    host_dns: Literal["off", "resolv_conf", "resolved"] = "off"
    main_interface: str = "auto"
    fwmark: str = "0x0c01"
    table_id: int = Field(default=1201, ge=1)
    nft_prefix: str = "kornode"
    split: RoutingSplitConfig = Field(default_factory=RoutingSplitConfig)
    host_split: HostSplitConfig = Field(default_factory=HostSplitConfig)

    @field_validator("host_dns", mode="before")
    @classmethod
    def validate_host_dns_off(cls, value: object) -> object:
        # "off" is a YAML/env boolean word: YAML 1.1 and parse_env_value()
        # both turn it into False before this model sees it. Map it back so
        # `host_dns: off` and KORNODE_ROUTING__HOST_DNS=off mean the same.
        if value is False:
            return "off"
        return value

    @field_validator("nft_prefix")
    @classmethod
    def validate_nft_prefix(cls, value: str) -> str:
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]{0,31}$", value):
            raise ValueError("routing.nft_prefix must be a short nftables-safe identifier")
        return value

    @field_validator("fwmark")
    @classmethod
    def validate_fwmark(cls, value: str) -> str:
        parsed = int(value, 0)
        if parsed == 0:
            # An unmarked packet's implicit mark is 0, so a fwmark of 0 would
            # make the forward kill-switch's "oifname != <tunnel> drop" rule
            # (templates/nftables.nft.j2) match virtually all forwarded
            # traffic, not just the traffic kornode actually marked.
            raise ValueError("routing.fwmark must not be 0")
        return value

    @field_validator("table_id")
    @classmethod
    def validate_table_id(cls, value: int) -> int:
        return _validate_routing_table_id(value, field_name="routing.table_id")


class InternalDnsConfig(StrictModel):
    resolver_enabled: bool = False
    listen: str = "10.10.10.1"
    port: int = Field(default=53, ge=1, le=65535)
    blocklist_enabled: bool = False
    local_records_enabled: bool = False
    blocklist_domains: list[str] = Field(default_factory=list)
    blocklist_files: list[Path] = Field(default_factory=list)
    blocklist_urls: list[str] = Field(default_factory=list)
    cache_size: int = Field(default=150, ge=0, le=10000)
    log_queries: bool = False
    local_records: list[str] = Field(default_factory=list)
    # What the built-in resolver forwards unmatched queries to. Falls back to
    # server.dns when empty -- see DnsmasqConfigRenderer. Distinct from
    # server.dns's other job (DNS pushed straight to VPN clients when the
    # resolver isn't in play, AppConfig.client_dns_servers()), which stays
    # tied to server.dns regardless of this field.
    default_upstreams: list[str] = Field(default_factory=list)
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

    @field_validator("default_upstreams")
    @classmethod
    def validate_default_upstreams(cls, value: list[str]) -> list[str]:
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
    # Serves GET /api/client/routing (api/routes_client_sync.py), polled by
    # upstream profiles' sync_url -- either this kornode acting as a client,
    # or a Korvus Client -- for mid-session route/split-DNS refresh. That
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


class AppConfig(StrictModel):
    system: SystemConfig = Field(default_factory=SystemConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    certificates: CertificatesConfig = Field(default_factory=CertificatesConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    internal_dns: InternalDnsConfig = Field(default_factory=InternalDnsConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    cli: CliConfig = Field(default_factory=CliConfig)
    advanced: AdvancedConfig = Field(default_factory=AdvancedConfig)

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
        if self.server.enabled:
            for route in self.routing.split.routes:
                if ipaddress.ip_network(route, strict=False) == vpn_network:
                    raise ValueError(
                        "routing.split.routes must not contain the VPN client subnet itself"
                    )
        if self.upstream.enabled:
            profile = self.upstream.selected_profile()
            if self.server.enabled and profile and profile.check_host:
                check_ip = ipaddress.ip_address(profile.check_host)
                if check_ip in vpn_network:
                    raise ValueError("upstream.check_host must not be inside the VPN client subnet")
            # Each profile's own named routing target (RoutingService.
            # list_targets()) uses routing.table_id + its offset -- reject
            # any derived table landing on a kernel-reserved ID, the same
            # check routing.table_id itself already gets. Independent of
            # server.enabled: a client-only deployment still derives real
            # policy-routing tables for its profiles.
            for target_profile in self.upstream.profiles:
                derived_table_id = self.routing.table_id + self.upstream.profile_routing_offset(
                    target_profile
                )
                _validate_routing_table_id(
                    derived_table_id,
                    field_name=f"upstream.profiles[{target_profile.name!r}]'s derived table_id",
                )
        # client_dns_reasons() (not the broader dns_tunnel_active()) is the
        # precise signal here: dnsmasq can be active for host-only reasons
        # (host_split_domains, profile_host_domains, profile_server_routes)
        # that never get pushed to a VPN client at all -- client_dns_servers()
        # itself only returns internal_dns.listen when client_dns_reasons()
        # is non-empty, falling back to server.dns otherwise (renderers/
        # ocserv.py). Gating on server.enabled too covers the same
        # client-only case as above.
        if self.server.enabled and self.client_dns_reasons():
            listen_ip = ipaddress.ip_address(self.internal_dns.listen)
            if listen_ip not in vpn_network:
                raise ValueError(
                    "internal_dns.listen must be inside server.ipv4_network "
                    "when internal_dns or split-mode DNS tunneling is enabled "
                    "so VPN clients can reach the DNS server"
                )
        return self

    def dnsmasq_active_reasons(self) -> list[str]:
        """Return the configured features that require project-owned dnsmasq."""
        reasons: list[str] = []
        settings = self.internal_dns
        if settings.resolver_enabled:
            reasons.append("resolver_enabled")
        if settings.blocklist_enabled:
            reasons.append("blocklist_enabled")
        if settings.local_records_enabled:
            reasons.append("local_records_enabled")
        if settings.forward_domains:
            reasons.append("forward_domains")
        if (
            self.routing.client_traffic
            and self.routing.mode == "split"
            and self.routing.split.tunnel_dns
        ):
            reasons.append("split_dns")
        if self.upstream.enabled and any(
            profile.enabled and profile.route_clients_enabled and profile.domains
            for profile in self.upstream.profiles
        ):
            reasons.append("profile_domains")
        if (
            self.routing.host_traffic
            and self.routing.host_mode == "split"
            and (
                self.routing.host_split.domains
                or self.routing.host_split.domains_files
                or self.routing.host_split.domains_urls
                or self.routing.host_split.domains_file.exists()
            )
        ):
            reasons.append("host_split_domains")
        if self.upstream.enabled and any(
            profile.enabled and profile.route_host_enabled and profile.host_domains
            for profile in self.upstream.profiles
        ):
            reasons.append("profile_host_domains")
        # Pushed split-DNS domains aren't known until the upstream sends
        # them, so a profile accepting them keeps dnsmasq running up front
        # (see services/upstream_pushed.py).
        if self.upstream.enabled and any(
            profile.enabled and profile.route_host_enabled and profile.accept_server_routes
            for profile in self.upstream.profiles
        ):
            reasons.append("profile_server_routes")
        return reasons

    def client_dns_reasons(self) -> list[str]:
        """Return active reasons for which VPN clients must query dnsmasq."""
        client_relevant = {
            "resolver_enabled",
            "blocklist_enabled",
            "local_records_enabled",
            "split_dns",
            "profile_domains",
        }
        return [reason for reason in self.dnsmasq_active_reasons() if reason in client_relevant]

    def dns_tunnel_active(self) -> bool:
        """Whether the project-owned dnsmasq instance must run."""
        return bool(self.dnsmasq_active_reasons())

    def client_dns_servers(self) -> list[str]:
        """DNS servers pushed to VPN clients by ocserv."""
        if self.client_dns_reasons():
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
