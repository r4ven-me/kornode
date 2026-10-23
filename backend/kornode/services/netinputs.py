"""The hub's inputs to kornode.net: EgressPolicy + NodeFacts -> DesiredState.

Reads config, runtime lists and the current runtime facts (tunnels up,
carrier addresses, connected networks, uplink) but never changes kernel
state -- that is the reconciler's job alone.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig, UpstreamProfileConfig, profile_slug
from kornode.net.addressing import derive_addresses
from kornode.net.compile import (
    Compiled,
    EnrollGuard,
    NodeFacts,
    SourceFact,
    TransitExit,
    TunnelFact,
    compile_policy,
    dest_members,
)
from kornode.net.lists import parse_gateway_sets, report_gateway_sets
from kornode.net.model import EgressPolicy, InlineDest, SetRef
from kornode.net.state import DesiredState
from kornode.registry.db import migrate, open_registry
from kornode.registry.models import Node, NodePrefix
from kornode.registry.repository import Registry
from kornode.services.bundle import policy_with_implicit_rules
from kornode.services.command import CommandRunner
from kornode.services.files import FileManager
from kornode.services.network_stats import NetworkStatsService

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
        if name:
            profile = profiles.get(name)
            return profile if profile and profile.enabled else None
    return config.upstream.selected_profile()


@dataclass(frozen=True)
class InterlinkView:
    """The registry and the connected sessions, read once per pass."""

    nodes: list[Node] = field(default_factory=list)
    prefixes: list[NodePrefix] = field(default_factory=list)
    # node id -> ocserv session device while the node is connected
    sessions: dict[int, str] = field(default_factory=dict)
    # node id -> addresses the agent resolved for the destinations of its exit rules (D-79)
    gateway_sets: dict[int, dict[str, frozenset[str]]] = field(default_factory=dict)


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
        return self.config.egress_policy()

    def facts(self) -> NodeFacts:
        config = self.config
        pool = ipaddress.IPv4Network(config.server.ipv4_network, strict=False)
        node_id = 1
        tunnels: dict[str, TunnelFact] = {}
        upstreams: list[str] = []
        links = self._links()
        # Declaration and availability are different: disabled upstreams are
        # still known references and retain their fail-closed exit tables.
        for profile in config.upstream.profiles:
            interface = config.upstream.profile_interface(profile)
            tunnels[f"upstream:{profile_slug(profile.name)}"] = TunnelFact(
                interface=interface,
                up=config.upstream.enabled and profile.enabled and links.get(interface, False),
                carrier=tuple(self._carrier(profile)),
            )
            upstreams.append(profile_slug(profile.name))
        active = selected_profile(config, self.files)
        tunnel_ifaces = {tunnel.interface for tunnel in tunnels.values()}
        view = self._interlink_view()
        policy = self.policy()
        # `node:<n>` of the hub's own policy leaves through node n's ocserv session; while
        # that session is down there is no fact and the exit only fails closed.
        for rule in policy.egress:
            via = rule.parsed_via
            device = view.sessions.get(int(via.target or 0)) if via.kind == "node" else None
            if device is not None:
                tunnels[via.name] = TunnelFact(interface=device, up=True)
        return NodeFacts(
            node_id=node_id,
            client_pool=pool,
            tunnels=tunnels,
            local_networks=tuple(self._local_networks(exclude=tunnel_ifaces)),
            resolved=self._resolved(),
            upstreams=tuple(upstreams),
            active_upstream=profile_slug(active.name) if active else None,
            disabled_upstreams=tuple(
                profile_slug(profile.name)
                for profile in config.upstream.profiles
                if not config.upstream.enabled or not profile.enabled
            ),
            sources={
                source.name: SourceFact(present=source.interface in links)
                for source in policy.sources
            },
            node_prefixes=self._node_prefixes(pool, view),
            interlink_ifaces=tuple(sorted(set(view.sessions.values()))),
            interlink_guard=True,
            transit_exits=tuple(self._transit_exits(view, policy)),
            session_routes=tuple(self._session_routes(view)),
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

    def _interlink_view(self) -> InterlinkView:
        """Active nodes, their prefixes and the session device of each connected one.

        A session is connected while the node's interlink address is a route on a `vpns*`
        device in main (ocserv installs it from `explicit-ipv4`); the same fact removes
        the node's routes again when the session ends.
        """
        config = self.config
        db = config.system.data_dir / "registry.db"
        if not db.exists():
            return InterlinkView()
        result = self.runner.run(
            ["ip", "-j", "-4", "route", "show", "table", "main"], check=False, timeout=5
        )
        routes: list[dict[str, Any]] = []
        if result.ok:
            try:
                routes = json.loads(result.stdout or "[]")
            except json.JSONDecodeError:
                routes = []
        device_of = {
            str(route["dst"]).removesuffix("/32"): str(route["dev"])
            for route in routes
            if route.get("dst") and str(route.get("dev", "")).startswith(config.server.device)
        }
        conn = open_registry(db)
        try:
            migrate(conn)
            registry = Registry(conn)
            nodes = [node for node in registry.list_nodes() if node.state == "active"]
            prefixes = registry.list_prefixes()
            gateway_sets = {}
            for node in nodes:
                reports = registry.list_reports(node.id, 1) if node.id != 1 else []
                if reports:
                    gateway_sets[node.id] = parse_gateway_sets(report_gateway_sets(reports[0].body))
        finally:
            conn.close()
        sessions: dict[int, str] = {}
        for node in nodes:
            device = device_of.get(str(self._interlink_address(node.id)))
            if device is not None and node.id != 1:
                sessions[node.id] = device
        return InterlinkView(
            nodes=nodes, prefixes=prefixes, sessions=sessions, gateway_sets=gateway_sets
        )

    def _interlink_address(self, node_id: int) -> ipaddress.IPv4Address:
        interlink = self.config.interlink
        return derive_addresses(
            node_id,
            interlink_cidr=interlink.cidr,
            client_pool=interlink.client_pool,
            source_pool=interlink.source_pool,
            domain=interlink.domain,
        ).interlink_address

    def _node_prefixes(self, pool: Network, view: InterlinkView) -> dict[int, tuple[Network, ...]]:
        """Every active node's exported prefixes; the hub's are its pool and the interlink."""
        hub: list[Network] = [pool, ipaddress.ip_network(self.config.interlink.cidr, strict=False)]
        hub += [ipaddress.ip_network(cidr) for cidr in self.config.exported_source_cidrs()]
        result: dict[int, tuple[Network, ...]] = {1: tuple(hub)}
        active = {node.id for node in view.nodes}
        # A node without exported prefixes is still a valid `node:<n>` target.
        for node_id in sorted(active - {1}):
            result[node_id] = ()
        for item in view.prefixes:
            if item.export and item.node_id in active and item.node_id != 1:
                result[item.node_id] = (
                    *result.get(item.node_id, ()),
                    ipaddress.ip_network(item.prefix, strict=False),
                )
        return result

    def _transit_exits(self, view: InterlinkView, own: EgressPolicy) -> list[TransitExit]:
        """Exits that agents declare for their own traffic (D-69): `from` classes of a
        rule `to: any via node:<n>` become the source prefixes the hub marks for node
        n's table. Only an active node with role `gateway` is honoured; anything else stays
        unmarked and is rejected by the agent guard."""
        interlink = self.config.interlink
        roles = {node.id: node.roles for node in view.nodes}
        found: list[TransitExit] = []
        # The hub's own exits (egress.hub) have no agent sources to mark; they are listed
        # for the strict reverse path, which must let the answers through (D-69).
        for rule in own.egress:
            via = rule.parsed_via
            if via.kind != "node":
                continue
            target = int(via.target or 0)
            if "gateway" in roles.get(target, []):
                found.append(TransitExit(target, (), view.sessions.get(target)))
        for node in view.nodes:
            if node.id == 1:
                continue
            try:
                # The agent numbers inline destinations (`rule<N>`) in the policy it was
                # given, implicit rules included: the hub must index the same list (D-79).
                policy = EgressPolicy.model_validate(
                    policy_with_implicit_rules(node.policy, node.roles)
                )
            except ValueError:
                continue
            addresses = derive_addresses(
                node.id,
                interlink_cidr=interlink.cidr,
                client_pool=interlink.client_pool,
                source_pool=interlink.source_pool,
                domain=interlink.domain,
            )
            cidrs = {
                item.name: ipaddress.ip_network(item.cidr, strict=False) for item in policy.sources
            }
            for index, rule in enumerate(policy.egress):
                via = rule.parsed_via
                if via.kind != "node":
                    continue
                is_dest = isinstance(rule.to, SetRef | InlineDest)
                if rule.to != "any" and not is_dest:
                    continue
                target = int(via.target or 0)
                if "gateway" not in roles.get(target, []) or target == node.id:
                    continue
                sources: list[Network] = []
                for name in rule.from_:
                    if name == "clients":
                        sources.append(addresses.client_pool)
                    elif name in cidrs:
                        sources.append(cidrs[name])
                if not sources:
                    continue
                dest: frozenset[str] | None = None
                if is_dest:
                    # The agent classified by the addresses it resolved itself: the hub
                    # matches the same ones (static routes come from the policy).
                    reported = NodeFacts(
                        node_id=node.id,
                        client_pool=None,
                        resolved=view.gateway_sets.get(node.id, {}),
                    )
                    dest, _ = dest_members(rule, index, policy, reported)
                found.append(TransitExit(target, tuple(sources), view.sessions.get(target), dest))
        return found

    def _session_routes(self, view: InterlinkView) -> list[tuple[Network, str]]:
        """Exported prefixes of connected agents -> their ocserv session device.

        ocserv does not install `iroute` routes itself (S-03), so the reconciler does.
        """
        session_routes: list[tuple[Network, str]] = []
        for item in view.prefixes:
            device = view.sessions.get(item.node_id)
            if item.export and device is not None and item.node_id != 1:
                session_routes.append((ipaddress.ip_network(item.prefix), device))
        return sorted(session_routes, key=lambda entry: (str(entry[0]), entry[1]))

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

    def _hub_interlink_address(self) -> ipaddress.IPv4Address:
        return derive_addresses(
            1,
            interlink_cidr=self.config.interlink.cidr,
            client_pool=self.config.interlink.client_pool,
            source_pool=self.config.interlink.source_pool,
            domain=self.config.interlink.domain,
        ).interlink_address

    def _service_address(self) -> ipaddress.IPv4Address | None:
        if not (self.config.control.enabled and self.config.node.id == 1):
            return None
        return self._hub_interlink_address()

    def _enroll_guard(self) -> EnrollGuard | None:
        return EnrollGuard(
            pool=ipaddress.IPv4Network(self.config.interlink.enroll_pool, strict=True),
            address=self._hub_interlink_address(),
            port=self.config.control.port,
            session_iface=f"{self.config.server.device}*",
        )
