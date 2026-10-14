"""The hub's inputs to kornode.net: EgressPolicy + NodeFacts -> DesiredState.

Reads config, runtime lists and the current runtime facts (tunnels up,
carrier addresses, connected networks, uplink) but never changes kernel
state -- that is the reconciler's job alone.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from kornode.config.legacy import legacy_policy, profile_slug, upstream_exit
from kornode.config.models import AppConfig, UpstreamProfileConfig
from kornode.net.addressing import derive_addresses
from kornode.net.compile import Compiled, EnrollGuard, NodeFacts, TunnelFact, compile_policy
from kornode.net.model import EgressPolicy
from kornode.net.state import DesiredState
from kornode.services.command import CommandRunner
from kornode.services.files import FileManager
from kornode.services.network_stats import NetworkStatsService
from kornode.services.routing import RoutingService
from kornode.services.upstream_pushed import PushedRoutingStore

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def resolved_state_dir(config: AppConfig) -> Path:
    """Where DomainResolverService records resolved addresses per egress set
    (one `<set>.txt` per set); read back into NodeFacts.resolved (D-25)."""
    return config.system.generated_dir / "resolved"


def carrier_state_dir(config: AppConfig) -> Path:
    """Per-profile `<profile>.addrs` files: the literal addresses each
    profile's carrier connection dials (excluded from marking, D-20)."""
    return config.system.generated_dir / "upstream-carrier"


def active_profile_file(config: AppConfig) -> Path:
    """Runtime-switched active profile (written by UpstreamService.switch_profile)."""
    return config.system.generated_dir / "active-upstream"


def selected_profile(config: AppConfig, files: FileManager) -> UpstreamProfileConfig | None:
    """The runtime-switched active profile, or the config's default if nothing
    was switched at runtime. A disabled profile is never returned, even if it
    is still the on-disk marker (see UpstreamConfig.selected_profile)."""
    profiles = {profile.name: profile for profile in config.upstream.profiles}
    for line in files.read_lines(active_profile_file(config)):
        name = line.strip()
        if name and name in profiles:
            profile = profiles[name]
            return profile if profile.enabled else None
    return config.upstream.selected_profile()


class RoutingLists:
    """LegacyLists backed by RoutingService: inline config + runtime files +
    URL caches + (for host lists) what an upstream pushed, exactly the lists
    v1 rendered into its nft sets."""

    def __init__(self, config: AppConfig, files: FileManager | None = None) -> None:
        self.routing = RoutingService(config, files)
        self.pushed = PushedRoutingStore(config, self.routing.files)

    def split_routes(self) -> list[str]:
        return self.routing.list_routes()

    def split_domains(self) -> list[str]:
        return self.routing.list_domains()

    def host_split_routes(self) -> list[str]:
        return self.routing.list_host_routes()

    def host_split_domains(self) -> list[str]:
        return self.routing.list_host_domains()

    def profile_routes(self, profile: UpstreamProfileConfig) -> list[str]:
        return self.routing.list_profile_routes(profile)

    def profile_domains(self, profile: UpstreamProfileConfig) -> list[str]:
        return self.routing.list_profile_domains(profile)

    def profile_host_routes(self, profile: UpstreamProfileConfig) -> list[str]:
        pushed = self.pushed.effective(profile)
        return _merge(
            profile.host_routes,
            pushed.routes,
            pushed.dns_host_routes() if pushed.domains else [],
        )

    def profile_host_domains(self, profile: UpstreamProfileConfig) -> list[str]:
        return _merge(profile.host_domains, self.pushed.effective(profile).domains)


def _merge(*sources: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for source in sources:
        for item in source:
            stripped = item.strip()
            if stripped and not stripped.startswith("#"):
                seen.setdefault(stripped, None)
    return list(seen)


class HubNetInputs:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
        proc_sys: Path = Path("/proc/sys"),
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.proc_sys = proc_sys

    def policy(self) -> EgressPolicy:
        return legacy_policy(
            self.config,
            RoutingLists(self.config, self.files),
            selected_profile(self.config, self.files),
        )

    def facts(self) -> NodeFacts:
        config = self.config
        pool = ipaddress.IPv4Network(config.server.ipv4_network, strict=False)
        node_id = 1
        tunnels: dict[str, TunnelFact] = {}
        upstreams: list[str] = []
        links = self._links()
        if config.upstream.enabled:
            for profile in config.upstream.profiles:
                interface = config.upstream.profile_interface(profile)
                tunnels[upstream_exit(profile)] = TunnelFact(
                    interface=interface,
                    up=links.get(interface, False),
                    carrier=tuple(self._carrier(profile)),
                )
                upstreams.append(profile_slug(profile.name))
        tunnel_ifaces = {tunnel.interface for tunnel in tunnels.values()}
        return NodeFacts(
            node_id=node_id,
            client_pool=pool,
            tunnels=tunnels,
            local_networks=tuple(self._local_networks(exclude=tunnel_ifaces)),
            resolved=self._resolved(),
            upstreams=tuple(upstreams),
            node_prefixes={node_id: (pool,)},
            uplink=NetworkStatsService(config, runner=self.runner).resolve_interface(),
            all_rp_filter=self._read_sysctl("net.ipv4.conf.all.rp_filter"),
            enroll=self._enroll_guard(),
            service_address=self._service_address(),
        )

    def compiled(self) -> Compiled:
        return compile_policy(self.policy(), self.facts())

    def desired(self) -> DesiredState:
        return self.compiled().desired

    # -- runtime facts ------------------------------------------------------

    def _links(self) -> dict[str, bool]:
        """Interface name -> administratively up (openconnect tuns report
        operstate UNKNOWN, so the UP flag is what counts)."""
        result = self.runner.run(["ip", "-j", "link", "show"], check=False, timeout=5)
        if not result.ok:
            return {}
        try:
            links: list[dict[str, Any]] = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return {}
        return {
            str(link.get("ifname")): "UP" in link.get("flags", [])
            for link in links
            if link.get("ifname")
        }

    def _carrier(self, profile: UpstreamProfileConfig) -> list[str]:
        path = carrier_state_dir(self.config) / f"{profile.name}.addrs"
        return [line.strip() for line in self.files.read_lines(path) if line.strip()]

    def _local_networks(self, *, exclude: set[str]) -> list[Network]:
        networks: list[Network] = []
        for family in ("-4", "-6"):
            result = self.runner.run(
                ["ip", "-j", family, "route", "show", "table", "main", "scope", "link"],
                check=False,
                timeout=5,
            )
            if not result.ok:
                continue
            try:
                routes: list[dict[str, Any]] = json.loads(result.stdout or "[]")
            except json.JSONDecodeError:
                continue
            for route in routes:
                dst = route.get("dst", "")
                if dst in ("", "default") or route.get("dev") in exclude:
                    continue
                try:
                    networks.append(ipaddress.ip_network(dst, strict=False))
                except ValueError:
                    continue
        return sorted(set(networks), key=lambda net: (net.version, net))

    def _resolved(self) -> dict[str, frozenset[str]]:
        directory = resolved_state_dir(self.config)
        if not directory.is_dir():
            return {}
        return {
            path.stem: frozenset(line.strip() for line in self.files.read_lines(path) if line)
            for path in sorted(directory.glob("*.txt"))
        }

    def _read_sysctl(self, key: str) -> str | None:
        try:
            return self.proc_sys.joinpath(*key.split(".")).read_text(encoding="utf-8").strip()
        except OSError:
            return None

    def _hub_fabric_address(self) -> ipaddress.IPv4Address:
        return derive_addresses(
            1,
            fabric_cidr=self.config.fabric.cidr,
            client_pool=self.config.fabric.client_pool,
            source_pool=self.config.fabric.source_pool,
            domain=self.config.fabric.domain,
        ).fabric_address

    def _service_address(self) -> ipaddress.IPv4Address | None:
        if not (self.config.control.enabled and self.config.node.id == 1):
            return None
        return self._hub_fabric_address()

    def _enroll_guard(self) -> EnrollGuard | None:
        if not self.config.fabric.enabled:
            return None
        return EnrollGuard(
            pool=ipaddress.IPv4Network(self.config.fabric.enroll_pool, strict=True),
            address=self._hub_fabric_address(),
            port=self.config.control.port,
            session_iface=f"{self.config.server.device}*",
        )
