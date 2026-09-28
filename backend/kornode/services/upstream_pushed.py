"""Routes/split-DNS domains an upstream server pushes to one of our profiles.

This is what used to be korclient: an ocserv/kornode upstream delivers
per-user and per-group `route =` / `split-dns =` lines to its clients inside
the AnyConnect handshake, and openconnect hands them to the vpnc-script as
environment variables (CISCO_SPLIT_INC_*, CISCO_IPV6_SPLIT_INC_*,
CISCO_SPLIT_DNS, INTERNAL_IP4_DNS/INTERNAL_IP6_DNS). The interface-only
vpnc-script-kornode passes that environment to `korctl upstream hook`,
which stores it here per profile; a profile with accept_server_routes then
routes the host's traffic for those lists through its own tunnel (see
RoutingService.list_targets()).

A profile's sync_url refreshes the same lists mid-session from the upstream
panel's GET /api/client/routing (see UpstreamService.sync_server_routes()).

Storage only -- nothing in this module touches nftables, dnsmasq or the
upstream lock, because the hook runs inside openconnect's own connect
sequence while UpstreamService.connect() still holds that lock.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from kornode.config.models import DOMAIN_RE, AppConfig, UpstreamProfileConfig, profile_safe_name
from kornode.services.files import FileManager

PUSHED_DIR_NAME = "upstream-pushed"
APPLIED_FINGERPRINT_NAME = ".upstream-pushed.applied"


@dataclass(frozen=True)
class PushedRouting:
    routes: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    # The upstream's own DNS servers (INTERNAL_IP4_DNS/INTERNAL_IP6_DNS):
    # pushed split-DNS domains resolve through them.
    dns: list[str] = field(default_factory=list)
    # "handshake" (vpnc-script at connect) or "sync" (panel endpoint).
    source: str = ""
    # The sync endpoint's content hash; empty for handshake data.
    version: str = ""
    interface: str = ""
    updated_at: int = 0
    # Last sync attempt, successful or not -- paces sync_interval across
    # watchdog restarts.
    synced_at: int = 0
    sync_error: str = ""

    def is_empty(self) -> bool:
        return not (self.routes or self.domains)

    def dns_host_routes(self) -> list[str]:
        """The upstream DNS servers as /32 or /128 routes: pushed domains
        resolve through them, so dnsmasq's own queries must go through the
        tunnel too, not out of the host's uplink."""
        routes: list[str] = []
        for server in self.dns:
            try:
                routes.append(str(ipaddress.ip_network(server)))
            except ValueError:
                continue
        return routes


def parse_vpnc_environment(environ: Mapping[str, str]) -> PushedRouting:
    """Build a PushedRouting from the environment openconnect passes to the
    vpnc-script. Malformed entries are skipped, never fatal: this runs on the
    tunnel's connect path."""
    routes: list[str] = []
    for prefix in ("CISCO_SPLIT_INC", "CISCO_IPV6_SPLIT_INC"):
        for index in range(_parse_count(environ.get(prefix, ""))):
            address = environ.get(f"{prefix}_{index}_ADDR", "").strip()
            masklen = environ.get(f"{prefix}_{index}_MASKLEN", "").strip()
            if not address or not masklen:
                continue
            _append_unique(routes, _normalize_route(f"{address}/{masklen}"))
    domains: list[str] = []
    for item in environ.get("CISCO_SPLIT_DNS", "").split(","):
        _append_unique(domains, _normalize_domain(item))
    dns: list[str] = []
    for key in ("INTERNAL_IP4_DNS", "INTERNAL_IP6_DNS"):
        for item in environ.get(key, "").split():
            _append_unique(dns, _normalize_ip(item))
    return PushedRouting(
        routes=routes,
        domains=domains,
        dns=dns,
        source="handshake",
        interface=environ.get("TUNDEV", ""),
        updated_at=int(time.time()),
    )


def parse_sync_payload(payload: object) -> tuple[list[str], list[str], str]:
    """(routes, domains, version) from GET /api/client/routing's JSON.

    Same tolerance as the handshake parser: a bad entry is dropped rather
    than failing the whole update.
    """
    if not isinstance(payload, dict):
        raise ValueError("sync response must be a JSON object")
    routes: list[str] = []
    raw_routes = payload.get("routes")
    for item in raw_routes if isinstance(raw_routes, list) else []:
        if isinstance(item, str):
            _append_unique(routes, _normalize_route(item))
    domains: list[str] = []
    raw_domains = payload.get("split_dns")
    for item in raw_domains if isinstance(raw_domains, list) else []:
        if isinstance(item, str):
            _append_unique(domains, _normalize_domain(item))
    version = payload.get("version")
    return routes, domains, str(version) if version else ""


class PushedRoutingStore:
    def __init__(self, config: AppConfig, files: FileManager | None = None) -> None:
        self.config = config
        self.files = files or FileManager()

    @property
    def directory(self) -> Path:
        return self.config.system.generated_dir / PUSHED_DIR_NAME

    def path(self, profile: UpstreamProfileConfig) -> Path:
        return self.directory / f"{profile_safe_name(profile.name)}.json"

    def load(self, profile: UpstreamProfileConfig) -> PushedRouting:
        try:
            loaded = json.loads(self.path(profile).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return PushedRouting()
        if not isinstance(loaded, dict):
            return PushedRouting()
        known = PushedRouting.__dataclass_fields__
        try:
            return PushedRouting(**{key: value for key, value in loaded.items() if key in known})
        except TypeError:
            return PushedRouting()

    def save(self, profile: UpstreamProfileConfig, pushed: PushedRouting) -> None:
        self.files.ensure_dir(self.directory)
        self.files.atomic_write_text(
            self.path(profile),
            json.dumps(asdict(pushed), indent=2, sort_keys=True) + "\n",
        )

    def save_handshake(self, profile: UpstreamProfileConfig, pushed: PushedRouting) -> None:
        """Store fresh handshake data, keeping the sync pacing timestamp so a
        reconnect doesn't trigger an immediate extra sync request."""
        previous = self.load(profile)
        self.save(profile, replace(pushed, synced_at=previous.synced_at))

    def effective(self, profile: UpstreamProfileConfig) -> PushedRouting:
        """What routing should actually use for `profile`: nothing unless it
        accepts server routes for its host traffic."""
        if not (profile.accept_server_routes and profile.route_host_enabled):
            return PushedRouting()
        return self.load(profile)

    def fingerprint(self) -> str:
        """Hash of every profile's effective pushed lists -- changes exactly
        when rendered nftables/dnsmasq content derived from them would.

        Empty when no profile has any pushed data in effect, which matches
        a never-written applied marker: a setup that doesn't use server
        routes never triggers an extra reload.
        """
        parts = []
        for profile in self.config.upstream.profiles:
            pushed = self.effective(profile)
            if not pushed.is_empty():
                parts.append([profile.name, pushed.routes, pushed.domains, pushed.dns])
        if not parts:
            return ""
        return hashlib.sha256(json.dumps(parts, sort_keys=True).encode("utf-8")).hexdigest()[:16]

    @property
    def _applied_path(self) -> Path:
        return self.config.system.generated_dir / APPLIED_FINGERPRINT_NAME

    def applied_fingerprint(self) -> str:
        try:
            return self._applied_path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def mark_applied(self, fingerprint: str) -> None:
        self.files.ensure_dir(self._applied_path.parent)
        self.files.atomic_write_text(self._applied_path, f"{fingerprint}\n")


def _parse_count(value: str) -> int:
    try:
        return max(0, int(value.strip() or "0"))
    except ValueError:
        return 0


def _append_unique(items: list[str], value: str | None) -> None:
    if value and value not in items:
        items.append(value)


def _normalize_route(value: str) -> str | None:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def _normalize_domain(value: str) -> str | None:
    candidate = value.strip().lower().rstrip(".")
    if candidate and DOMAIN_RE.match(candidate):
        return candidate
    return None


def _normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None
