from __future__ import annotations

import ipaddress
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from kornode.config.models import (
    AppConfig,
    HostSplitConfig,
    RoutingSplitConfig,
    UpstreamProfileConfig,
    profile_safe_name,
)
from kornode.services.external_lists import (
    ExternalListCache,
    ExternalListFetchResult,
    parse_list_text,
)
from kornode.services.files import FileManager
from kornode.services.upstream_pushed import PushedRoutingStore

DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_FETCH_USER_AGENT = "kornode-routing/1.0"

# Serializes the read-modify-write cycle on routes.txt/domains.txt, the same
# hazard users.py's _PASSWD_REWRITE_LOCK protects against for ocpasswd: two
# concurrent route/domain edits (e.g. two admin browser tabs) would
# otherwise each read the same original file and the last write would
# silently discard the other's change.
_ROUTING_FILE_REWRITE_LOCK = threading.Lock()


@dataclass(frozen=True)
class RoutingTarget:
    """One fwmark/table/kill-switch worth of routing: either the "default"
    bucket (whichever profile is active, governed by routing.client_policy) or one
    profile with its own explicit routes/domains, which always gets that
    traffic regardless of which profile is currently active."""

    name: str
    fwmark: str
    table_id: int
    interface: str
    # Each family is a static/dynamic pair, not a single set: `_static` holds
    # this target's config-known routes (profile `routes`, `routing.split`),
    # rebuilt on every apply; `_dynamic` holds whatever DomainResolverService
    # (services/domain_resolver.py) last resolved this target's own domains
    # into, on its own schedule, and is never touched by a routes/domains-only
    # config refresh. A naive single-set design that gets flushed on every
    # refresh would wipe out every resolved domain IP each time a reload
    # happens (profile edit, host DNS toggle, pushed-routes sync, panel
    # Reload) -- silently breaking any long-lived connection still using one
    # between resolver cycles. See NftablesService.apply()'s docstring.
    set_v4_static: str
    set_v4_dynamic: str
    set_v6_static: str
    set_v6_dynamic: str
    mode: str  # "full", "split" or "off" -- only the default target can be "full" or "off"
    routes: list[str]
    domains: list[str]
    # Whether this target's own profile is actually expected to be
    # connected right now (enabled profiles are kept dialed by the watchdog
    # regardless of being active) -- gates the kill-switch/masquerade rules
    # the same way upstream_active already did for the single-target case.
    killswitch: bool
    profile: UpstreamProfileConfig | None
    # Per-profile HOST routing (UpstreamProfileConfig.route_host_enabled):
    # the host's own traffic matching these routes/domains is marked and
    # sent through this target's own tunnel, on its own dedicated nft sets
    # -- independent of routing.host_policy, which only ever
    # covers the default target. Always empty/None for the default target;
    # that one's host marking is handled separately in the template (see
    # host_traffic_enabled).
    host_routes: list[str]
    host_domains: list[str]
    # Same static/dynamic pairing as set_v4_static/set_v4_dynamic above.
    host_set_v4_static: str | None
    host_set_v4_dynamic: str | None
    host_set_v6_static: str | None
    host_set_v6_dynamic: str | None
    # IPv6 part of the host routes (host_routes above is IPv4 only): each
    # family goes into its own typed nft set.
    host_routes_v6: list[str] = field(default_factory=list)
    # Split-DNS domains the upstream server pushed (accept_server_routes),
    # already included in host_domains; unlike the admin's own
    # host_domains they resolve through the upstream's DNS (server_dns),
    # since they're typically internal names only that DNS knows.
    server_domains: list[str] = field(default_factory=list)
    server_dns: list[str] = field(default_factory=list)

    @property
    def host_enabled(self) -> bool:
        return bool(self.host_set_v4_static)


class RoutingService:
    def __init__(self, config: AppConfig, files: FileManager | None = None) -> None:
        self.config = config
        self.files = files or FileManager()
        self.route_urls = ExternalListCache(
            config.system.data_dir / "routing" / "route-urls",
            self.files,
            user_agent=_FETCH_USER_AGENT,
        )
        self.domain_urls = ExternalListCache(
            config.system.data_dir / "routing" / "domain-urls",
            self.files,
            user_agent=_FETCH_USER_AGENT,
        )
        # Same shape, separate cache directories: routing.host_split's
        # routes/domains are an entirely independent list from
        # routing.split's (host vs. client traffic), not merged with it.
        self.host_route_urls = ExternalListCache(
            config.system.data_dir / "routing" / "host-route-urls",
            self.files,
            user_agent=_FETCH_USER_AGENT,
        )
        self.host_domain_urls = ExternalListCache(
            config.system.data_dir / "routing" / "host-domain-urls",
            self.files,
            user_agent=_FETCH_USER_AGENT,
        )

    def list_routes(self) -> list[str]:
        return self._list_routes(self.config.routing.split, self.route_urls)

    def list_domains(self) -> list[str]:
        return self._list_domains(self.config.routing.split, self.domain_urls)

    def list_host_routes(self) -> list[str]:
        return self._list_routes(self.config.routing.host_split, self.host_route_urls)

    def list_host_domains(self) -> list[str]:
        return self._list_domains(self.config.routing.host_split, self.host_domain_urls)

    def _profile_route_url_cache(self, profile: UpstreamProfileConfig) -> ExternalListCache:
        return ExternalListCache(
            self.config.system.data_dir
            / "routing"
            / "profile-route-urls"
            / profile_safe_name(profile.name),
            self.files,
            user_agent=_FETCH_USER_AGENT,
        )

    def _profile_domain_url_cache(self, profile: UpstreamProfileConfig) -> ExternalListCache:
        return ExternalListCache(
            self.config.system.data_dir
            / "routing"
            / "profile-domain-urls"
            / profile_safe_name(profile.name),
            self.files,
            user_agent=_FETCH_USER_AGENT,
        )

    def list_profile_routes(self, profile: UpstreamProfileConfig) -> list[str]:
        return self._merge_unique(
            profile.routes,
            self._all_file_routes(profile),
            self._all_url_cache_routes(profile, self._profile_route_url_cache(profile)),
        )

    def list_profile_domains(self, profile: UpstreamProfileConfig) -> list[str]:
        return self._merge_unique(
            profile.domains,
            self._all_file_domains(profile),
            self._all_url_cache_domains(profile, self._profile_domain_url_cache(profile)),
        )

    def _list_routes(
        self,
        split: RoutingSplitConfig | HostSplitConfig,
        url_cache: ExternalListCache,
    ) -> list[str]:
        return self._merge_unique(
            split.routes,
            self.files.read_lines(split.routes_file),
            self._all_file_routes(split),
            self._all_url_cache_routes(split, url_cache),
        )

    def _list_domains(
        self,
        split: RoutingSplitConfig | HostSplitConfig,
        url_cache: ExternalListCache,
    ) -> list[str]:
        return self._merge_unique(
            split.domains,
            self.files.read_lines(split.domains_file),
            self._all_file_domains(split),
            self._all_url_cache_domains(split, url_cache),
        )

    def file_routes(self, path: Path) -> list[str]:
        # Tolerant (skips malformed lines instead of raising), unlike
        # add_route()/set_routes(): a statically configured file
        # (admin-managed, possibly hand-edited or third-party) shouldn't
        # have a single bad line invalidate the rest -- same philosophy as
        # internal_dns's blocklist file/URL parsing.
        text = "\n".join(self.files.read_lines(path))
        return parse_list_text(text, normalize=self._normalize_route).items

    def _all_file_routes(
        self, split: RoutingSplitConfig | HostSplitConfig | UpstreamProfileConfig
    ) -> list[str]:
        merged: list[str] = []
        for path in split.routes_files:
            merged.extend(self.file_routes(path))
        return merged

    def all_file_routes(self) -> list[str]:
        return self._all_file_routes(self.config.routing.split)

    def all_file_host_routes(self) -> list[str]:
        return self._all_file_routes(self.config.routing.host_split)

    def file_domains(self, path: Path) -> list[str]:
        text = "\n".join(self.files.read_lines(path))
        return parse_list_text(text, normalize=self._normalize_domain).items

    def _all_file_domains(
        self, split: RoutingSplitConfig | HostSplitConfig | UpstreamProfileConfig
    ) -> list[str]:
        merged: list[str] = []
        for path in split.domains_files:
            merged.extend(self.file_domains(path))
        return merged

    def all_file_domains(self) -> list[str]:
        return self._all_file_domains(self.config.routing.split)

    def all_file_host_domains(self) -> list[str]:
        return self._all_file_domains(self.config.routing.host_split)

    def url_cache_routes(self, url: str) -> list[str]:
        return self.route_urls.cached_items(url, normalize=self._normalize_route)

    def url_cache_host_routes(self, url: str) -> list[str]:
        return self.host_route_urls.cached_items(url, normalize=self._normalize_route)

    def _all_url_cache_routes(
        self,
        split: RoutingSplitConfig | HostSplitConfig | UpstreamProfileConfig,
        url_cache: ExternalListCache,
    ) -> list[str]:
        merged: list[str] = []
        for url in split.routes_urls:
            merged.extend(url_cache.cached_items(url, normalize=self._normalize_route))
        return merged

    def all_url_cache_routes(self) -> list[str]:
        return self._all_url_cache_routes(self.config.routing.split, self.route_urls)

    def all_url_cache_host_routes(self) -> list[str]:
        return self._all_url_cache_routes(self.config.routing.host_split, self.host_route_urls)

    def url_cache_domains(self, url: str) -> list[str]:
        return self.domain_urls.cached_items(url, normalize=self._normalize_domain)

    def url_cache_host_domains(self, url: str) -> list[str]:
        return self.host_domain_urls.cached_items(url, normalize=self._normalize_domain)

    def _all_url_cache_domains(
        self,
        split: RoutingSplitConfig | HostSplitConfig | UpstreamProfileConfig,
        url_cache: ExternalListCache,
    ) -> list[str]:
        merged: list[str] = []
        for url in split.domains_urls:
            merged.extend(url_cache.cached_items(url, normalize=self._normalize_domain))
        return merged

    def all_url_cache_domains(self) -> list[str]:
        return self._all_url_cache_domains(self.config.routing.split, self.domain_urls)

    def all_url_cache_host_domains(self) -> list[str]:
        return self._all_url_cache_domains(self.config.routing.host_split, self.host_domain_urls)

    def routes_files_status(self) -> list[dict[str, object]]:
        return self._files_status(self.config.routing.split.routes_files, self.file_routes)

    def host_routes_files_status(self) -> list[dict[str, object]]:
        return self._files_status(self.config.routing.host_split.routes_files, self.file_routes)

    def domains_files_status(self) -> list[dict[str, object]]:
        return self._files_status(self.config.routing.split.domains_files, self.file_domains)

    def host_domains_files_status(self) -> list[dict[str, object]]:
        return self._files_status(self.config.routing.host_split.domains_files, self.file_domains)

    def profile_routes_files_status(
        self, profile: UpstreamProfileConfig
    ) -> list[dict[str, object]]:
        return self._files_status(profile.routes_files, self.file_routes)

    def profile_domains_files_status(
        self, profile: UpstreamProfileConfig
    ) -> list[dict[str, object]]:
        return self._files_status(profile.domains_files, self.file_domains)

    def _files_status(
        self, paths: list[Path], reader: Callable[[Path], list[str]]
    ) -> list[dict[str, object]]:
        return [
            {"path": str(path), "exists": path.exists(), "count": len(reader(path))}
            for path in paths
        ]

    def routes_urls_status(self) -> list[dict[str, object]]:
        return self._urls_status(
            self.config.routing.split.routes_urls, self.route_urls, self.url_cache_routes
        )

    def host_routes_urls_status(self) -> list[dict[str, object]]:
        return self._urls_status(
            self.config.routing.host_split.routes_urls,
            self.host_route_urls,
            self.url_cache_host_routes,
        )

    def domains_urls_status(self) -> list[dict[str, object]]:
        return self._urls_status(
            self.config.routing.split.domains_urls, self.domain_urls, self.url_cache_domains
        )

    def host_domains_urls_status(self) -> list[dict[str, object]]:
        return self._urls_status(
            self.config.routing.host_split.domains_urls,
            self.host_domain_urls,
            self.url_cache_host_domains,
        )

    def profile_routes_urls_status(self, profile: UpstreamProfileConfig) -> list[dict[str, object]]:
        cache = self._profile_route_url_cache(profile)
        return self._urls_status(
            profile.routes_urls,
            cache,
            lambda url: cache.cached_items(url, normalize=self._normalize_route),
        )

    def profile_domains_urls_status(
        self, profile: UpstreamProfileConfig
    ) -> list[dict[str, object]]:
        cache = self._profile_domain_url_cache(profile)
        return self._urls_status(
            profile.domains_urls,
            cache,
            lambda url: cache.cached_items(url, normalize=self._normalize_domain),
        )

    def _urls_status(
        self,
        urls: list[str],
        url_cache: ExternalListCache,
        counter: Callable[[str], list[str]],
    ) -> list[dict[str, object]]:
        return [
            {"url": url, "count": len(counter(url)), "meta": url_cache.meta(url)} for url in urls
        ]

    def refresh_route_url(self, url: str, *, preview: bool = False) -> ExternalListFetchResult:
        if url not in self.config.routing.split.routes_urls:
            raise ValueError(f"routing.split.routes_urls does not contain: {url}")
        return self.route_urls.refresh(url, normalize=self._normalize_route, preview=preview)

    def refresh_host_route_url(self, url: str, *, preview: bool = False) -> ExternalListFetchResult:
        if url not in self.config.routing.host_split.routes_urls:
            raise ValueError(f"routing.host_split.routes_urls does not contain: {url}")
        return self.host_route_urls.refresh(url, normalize=self._normalize_route, preview=preview)

    def refresh_domain_url(self, url: str, *, preview: bool = False) -> ExternalListFetchResult:
        if url not in self.config.routing.split.domains_urls:
            raise ValueError(f"routing.split.domains_urls does not contain: {url}")
        return self.domain_urls.refresh(url, normalize=self._normalize_domain, preview=preview)

    def refresh_host_domain_url(
        self, url: str, *, preview: bool = False
    ) -> ExternalListFetchResult:
        if url not in self.config.routing.host_split.domains_urls:
            raise ValueError(f"routing.host_split.domains_urls does not contain: {url}")
        return self.host_domain_urls.refresh(url, normalize=self._normalize_domain, preview=preview)

    def refresh_profile_route_url(
        self, profile: UpstreamProfileConfig, url: str, *, preview: bool = False
    ) -> ExternalListFetchResult:
        if url not in profile.routes_urls:
            raise ValueError(
                f"upstream profile {profile.name!r} routes_urls does not contain: {url}"
            )
        return self._profile_route_url_cache(profile).refresh(
            url, normalize=self._normalize_route, preview=preview
        )

    def refresh_profile_domain_url(
        self, profile: UpstreamProfileConfig, url: str, *, preview: bool = False
    ) -> ExternalListFetchResult:
        if url not in profile.domains_urls:
            raise ValueError(
                f"upstream profile {profile.name!r} domains_urls does not contain: {url}"
            )
        return self._profile_domain_url_cache(profile).refresh(
            url, normalize=self._normalize_domain, preview=preview
        )

    def list_targets(self, *, default_interface: str) -> list[RoutingTarget]:
        """Every routing target that needs its own nftables set/fwmark/table:
        the default bucket first, then one per profile that has its own
        routes/domains assigned. `default_interface` is the caller's already-
        resolved outbound interface for the default bucket (the active
        profile's tunnel device, or routing.main_interface without one) --
        kept a parameter rather than recomputed here so callers that pass an
        explicit override (e.g. NftablesConfigRenderer.render's own
        outbound_interface argument) keep working exactly as before.
        """
        config = self.config
        upstream_active = config.upstream.enabled and config.upstream.selected_profile() is not None
        # With client_policy "off", unmarked client packets keep using the
        # kernel's normal route (the host's own uplink), not the tunnel --
        # default_interface reflects the active profile's tunnel regardless
        # of client_policy (it's also used for the HOST's own masquerade
        # via host_policy, which is independent), so this target's own
        # NAT/killswitch interface must fall back to main_interface here.
        client_on = config.routing.client_policy != "off"
        default_target_interface = default_interface if client_on else config.routing.main_interface
        targets = [
            RoutingTarget(
                name="default",
                fwmark=config.routing.fwmark,
                table_id=config.routing.table_id,
                interface=default_target_interface,
                set_v4_static="split_v4_static",
                set_v4_dynamic="split_v4_dynamic",
                set_v6_static="split_v6_static",
                set_v6_dynamic="split_v6_dynamic",
                mode=config.routing.client_policy,
                routes=self.list_routes(),
                domains=self.list_domains() if config.routing.client_policy == "split" else [],
                # routes/domains stay populated regardless of client_policy
                # -- only the kill-switch, and the client-facing marking
                # rendered in the template, are gated on it. (Host's own
                # split-mode marking uses its own separate
                # routing.host_split routes/domains -- see
                # NftablesConfigRenderer.render's host_split_routes/domains.)
                killswitch=upstream_active and client_on,
                profile=config.upstream.selected_profile(),
                host_routes=[],
                host_domains=[],
                host_set_v4_static=None,
                host_set_v4_dynamic=None,
                host_set_v6_static=None,
                host_set_v6_dynamic=None,
            )
        ]
        # Named per-profile targets only exist at all when upstream is
        # globally enabled -- targeting a specific profile is meaningless
        # otherwise, and this keeps the "upstream disabled -> everything is
        # inert, clients just get plain NAT" invariant from Phase 1 exactly
        # true without a maze of per-target fallback branches. Once a target
        # exists, its kill-switch is unconditional (not gated on this one
        # profile's own `enabled`): it was explicitly assigned traffic, so a
        # disabled profile blocks that traffic rather than silently leaking
        # it out the host's own connection -- the same philosophy as the
        # default target's kill-switch, just without a "no upstream at all"
        # fallback state to also account for.
        if config.upstream.enabled:
            base_fwmark = int(config.routing.fwmark, 0)
            # Zero-pad to the same width as the configured fwmark (e.g.
            # "0x0c01" -> 4 hex digits) purely for readable, consistent
            # output in the generated file -- the numeric value is what
            # actually matters to nftables/ip rule.
            fwmark_width = len(config.routing.fwmark) - 2
            pushed_store = PushedRoutingStore(config, self.files)
            for profile in config.upstream.profiles:
                profile_routes = self.list_profile_routes(profile)
                profile_domains = self.list_profile_domains(profile)
                client_active = profile.route_clients_enabled and bool(
                    profile_routes or profile_domains
                )
                # Admin-configured host lists plus, with accept_server_routes,
                # whatever the upstream server pushed/synced for this
                # profile (empty otherwise -- see PushedRoutingStore.effective).
                pushed = pushed_store.effective(profile)
                host_route_list = self._merge_unique(
                    profile.host_routes,
                    pushed.routes,
                    pushed.dns_host_routes() if pushed.domains else [],
                )
                host_domain_list = self._merge_unique(profile.host_domains, pushed.domains)
                host_routes_v4, host_routes_v6 = _split_by_family(host_route_list)
                host_active = profile.route_host_enabled and bool(
                    host_route_list or host_domain_list
                )
                if not client_active and not host_active:
                    continue
                # Derived from this profile's own fixed position in
                # upstream.profiles (or its explicit routing_offset
                # override), NOT from a running count of profiles that
                # currently have routes/domains -- see
                # UpstreamConfig.profile_routing_offset(). That keeps this
                # profile's fwmark/table stable even when another profile's
                # routes/domains are added, removed, or reordered.
                offset = config.upstream.profile_routing_offset(profile)
                safe_name = profile_safe_name(profile.name)
                targets.append(
                    RoutingTarget(
                        name=profile.name,
                        fwmark=f"0x{base_fwmark + offset:0{fwmark_width}x}",
                        table_id=config.routing.table_id + offset,
                        interface=config.upstream.profile_interface(profile),
                        set_v4_static=f"split_v4_{safe_name}_static",
                        set_v4_dynamic=f"split_v4_{safe_name}_dynamic",
                        set_v6_static=f"split_v6_{safe_name}_static",
                        set_v6_dynamic=f"split_v6_{safe_name}_dynamic",
                        mode="split",
                        routes=profile_routes if profile.route_clients_enabled else [],
                        domains=profile_domains if profile.route_clients_enabled else [],
                        killswitch=True,
                        profile=profile,
                        host_routes=host_routes_v4 if host_active else [],
                        host_domains=host_domain_list if host_active else [],
                        host_set_v4_static=f"host_v4_{safe_name}_static" if host_active else None,
                        host_set_v4_dynamic=(
                            f"host_v4_{safe_name}_dynamic" if host_active else None
                        ),
                        host_set_v6_static=f"host_v6_{safe_name}_static" if host_active else None,
                        host_set_v6_dynamic=(
                            f"host_v6_{safe_name}_dynamic" if host_active else None
                        ),
                        host_routes_v6=host_routes_v6 if host_active else [],
                        server_domains=pushed.domains if host_active else [],
                        server_dns=pushed.dns if host_active else [],
                    )
                )
        return targets

    def add_route(self, cidr_or_ip: str) -> None:
        item = self._normalize_route(cidr_or_ip)
        self._add_line(self.config.routing.split.routes_file, item)

    def delete_route(self, cidr_or_ip: str) -> None:
        item = self._normalize_route(cidr_or_ip)
        self._delete_line(self.config.routing.split.routes_file, item)

    def add_domain(self, domain: str) -> None:
        item = self._normalize_domain(domain)
        self._add_line(self.config.routing.split.domains_file, item)

    def delete_domain(self, domain: str) -> None:
        item = self._normalize_domain(domain)
        self._delete_line(self.config.routing.split.domains_file, item)

    def set_routes(self, items: list[str]) -> None:
        """Replace the whole runtime routes list at once (bulk paste from
        the web UI), instead of one add_route() call per line."""
        normalized = [self._normalize_route(item) for item in items]
        with _ROUTING_FILE_REWRITE_LOCK:
            self.files.write_unique_lines(self.config.routing.split.routes_file, normalized)

    def set_domains(self, items: list[str]) -> None:
        """Replace the whole runtime domains list at once (bulk paste from
        the web UI), instead of one add_domain() call per line."""
        normalized = [self._normalize_domain(item) for item in items]
        with _ROUTING_FILE_REWRITE_LOCK:
            self.files.write_unique_lines(self.config.routing.split.domains_file, normalized)

    def set_host_routes(self, items: list[str]) -> None:
        normalized = [self._normalize_route(item) for item in items]
        with _ROUTING_FILE_REWRITE_LOCK:
            self.files.write_unique_lines(self.config.routing.host_split.routes_file, normalized)

    def set_host_domains(self, items: list[str]) -> None:
        normalized = [self._normalize_domain(item) for item in items]
        with _ROUTING_FILE_REWRITE_LOCK:
            self.files.write_unique_lines(self.config.routing.host_split.domains_file, normalized)

    def _merge_unique(self, *sources: list[str]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for source in sources:
            for item in source:
                stripped = item.strip()
                if stripped and not stripped.startswith("#") and stripped not in seen:
                    result.append(stripped)
                    seen.add(stripped)
        return result

    def _add_line(self, path: Path, item: str) -> None:
        with _ROUTING_FILE_REWRITE_LOCK:
            lines = self.files.read_lines(path)
            if item not in [line.strip() for line in lines]:
                self.files.write_unique_lines(path, [*lines, item])

    def _delete_line(self, path: Path, item: str) -> None:
        with _ROUTING_FILE_REWRITE_LOCK:
            kept = [line for line in self.files.read_lines(path) if line.strip() != item]
            self.files.write_unique_lines(path, kept)

    def _normalize_route(self, value: str) -> str:
        try:
            if "/" in value:
                return str(ipaddress.ip_network(value, strict=False))
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(f"invalid route or IP: {value}") from exc

    def _normalize_domain(self, value: str) -> str:
        domain = value.strip().lower().rstrip(".")
        if not domain or not DOMAIN_RE.match(domain):
            raise ValueError(f"invalid domain: {value}")
        return domain


def _split_by_family(routes: list[str]) -> tuple[list[str], list[str]]:
    """Split CIDRs/addresses into (IPv4, IPv6) lists for the typed nft sets."""
    v4: list[str] = []
    v6: list[str] = []
    for route in routes:
        try:
            network = ipaddress.ip_network(route, strict=False)
        except ValueError:
            continue
        (v4 if network.version == 4 else v6).append(route)
    return v4, v6
