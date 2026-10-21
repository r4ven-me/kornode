"""AgentNetInputs: active bundle + runtime facts -> DesiredState (spec 06).

The agent's counterpart of the hub's ``HubNetInputs``; the provider handed to
``kornode.net.Reconciler``. It only reads the system, never changes it.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import subprocess
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from kornode.bundle.validator import Validated
from kornode.net.compile import NodeFacts, SourceFact, TunnelFact, compile_policy, node_exit_tunnels
from kornode.net.model import EgressPolicy, Rule
from kornode.net.state import DesiredState
from kornode_agent.access import DEVICE as ACCESS_DEVICE
from kornode_agent.config import AgentConfig

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
FABRIC = "fabric"
HUB_NODE_ID = 1
# Bootstrap policy: the host reaches the hub (control API) through the fabric
# tunnel and nothing else is marked, so nothing can leak.
BOOTSTRAP_POLICY = EgressPolicy(
    egress=(
        Rule.model_validate({"id": "to-fabric", "from": ["host"], "to": "fabric", "via": "fabric"}),
    )
)


class Probes(Protocol):
    def links(self) -> dict[str, bool]: ...

    def local_networks(self, exclude: set[str]) -> tuple[Network, ...]: ...

    def uplink(self, exclude: set[str]) -> str | None: ...

    def rp_filter(self) -> str | None: ...


class Carriers(Protocol):
    def carrier(self, exit_name: str) -> tuple[str, ...]: ...


def _run_json(argv: Sequence[str]) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False)
        data = json.loads(result.stdout or "[]") if result.returncode == 0 else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []
    return [item for item in data if isinstance(item, dict)]


class SystemProbes:
    def __init__(self, proc_sys: Path = Path("/proc/sys")) -> None:
        self.proc_sys = proc_sys

    def links(self) -> dict[str, bool]:
        """Interface -> administratively UP (openconnect tuns report operstate UNKNOWN)."""
        return {
            str(link["ifname"]): "UP" in link.get("flags", [])
            for link in _run_json(["ip", "-j", "link", "show"])
            if link.get("ifname")
        }

    def local_networks(self, exclude: set[str]) -> tuple[Network, ...]:
        found: set[Network] = set()
        for family in ("-4", "-6"):
            for route in _run_json(
                ["ip", "-j", family, "route", "show", "table", "main", "scope", "link"]
            ):
                dst = str(route.get("dst", ""))
                if dst in ("", "default") or route.get("dev") in exclude:
                    continue
                try:
                    found.add(ipaddress.ip_network(dst, strict=False))
                except ValueError:
                    continue
        return tuple(sorted(found, key=lambda net: (net.version, net)))

    def uplink(self, exclude: set[str]) -> str | None:
        """Device of the best default route that is not one of our tunnels."""
        routes = [
            route
            for route in _run_json(["ip", "-j", "-4", "route", "show", "default"])
            if route.get("dev") and route["dev"] not in exclude
        ]
        routes.sort(key=lambda route: int(route.get("metric", 0)))
        return str(routes[0]["dev"]) if routes else None

    def address(self, interface: str) -> str | None:
        for link in _run_json(["ip", "-j", "-4", "addr", "show", "dev", interface]):
            for info in link.get("addr_info", []):
                if info.get("family") == "inet" and info.get("local"):
                    return str(info["local"])
        return None

    def rp_filter(self) -> str | None:
        try:
            return (self.proc_sys / "net/ipv4/conf/all/rp_filter").read_text().strip()
        except OSError:
            return None


class AgentNetInputs:
    def __init__(
        self,
        config: AgentConfig,
        probes: Probes,
        carriers: Carriers,
        *,
        on_change: Callable[[], None] = lambda: None,
    ) -> None:
        self.config = config
        self.probes = probes
        self.carriers = carriers
        self._on_change = on_change
        self._lock = threading.Lock()
        self._active: Validated | None = None

    def set_bundle(self, validated: Validated | None) -> None:
        with self._lock:
            self._active = validated
        self._on_change()

    @property
    def active(self) -> Validated | None:
        with self._lock:
            return self._active

    def policy(self) -> EgressPolicy:
        active = self.active
        return active.bundle.policy if active else BOOTSTRAP_POLICY

    def facts(self) -> NodeFacts:
        active = self.active
        links = self.probes.links()
        tunnels: dict[str, TunnelFact] = {}
        fabric_iface = (
            active.bundle.tunnels.fabric.interface if active else self.config.fabric.interface
        )
        tunnels[FABRIC] = TunnelFact(
            interface=fabric_iface,
            up=links.get(fabric_iface, False),
            carrier=self.carriers.carrier(FABRIC),
        )
        if active:
            # `exit:<node>` goes through the hub tunnel: same device, same carrier (D-69).
            tunnels.update(
                node_exit_tunnels(
                    active.bundle.policy, fabric_iface, links.get(fabric_iface, False)
                )
            )
        upstreams: list[str] = []
        sources: dict[str, SourceFact] = {}
        node_prefixes: dict[int, tuple[Network, ...]] = {}
        if not active:
            with contextlib.suppress(ValueError):
                hub_address = ipaddress.ip_address(
                    urlsplit(self.config.hub.control_url).hostname or ""
                )
                node_prefixes[HUB_NODE_ID] = (ipaddress.ip_network(f"{hub_address}/32"),)
        client_pool: ipaddress.IPv4Network | None = None
        session_routes: tuple[tuple[Network, str], ...] = ()
        local_addresses: tuple[ipaddress.IPv4Address, ...] = ()
        access_ifaces: tuple[str, ...] = ()
        node_id = self.config.node_id
        if active:
            bundle = active.bundle
            node_id = bundle.node_id
            client_pool = ipaddress.IPv4Network(bundle.node.client_pool, strict=False)
            if bundle.dns is not None and bundle.dns.enabled:
                # The node resolver listens on the service address (D-66).
                local_addresses = (ipaddress.IPv4Address(bundle.node.service_address),)
            if bundle.access is not None and "access" in bundle.node.roles:
                access_ifaces = (f"{ACCESS_DEVICE}*",)
            for upstream in bundle.tunnels.upstreams:
                if not upstream.enabled:
                    continue
                exit_name = f"upstream:{upstream.name}"
                tunnels[exit_name] = TunnelFact(
                    interface=upstream.interface,
                    up=links.get(upstream.interface, False),
                    carrier=self.carriers.carrier(exit_name),
                )
                upstreams.append(upstream.name)
            for source in bundle.policy.sources:
                sources[source.name] = SourceFact(present=source.interface in links)
            grouped: dict[int, list[Network]] = {}
            for item in bundle.fabric.prefixes:
                grouped.setdefault(item.node_id, []).append(
                    ipaddress.ip_network(item.prefix, strict=False)
                )
            node_prefixes = {key: tuple(value) for key, value in grouped.items()}
            if links.get(fabric_iface, False) and any(
                "fabric" in rule.from_ for rule in bundle.policy.egress
            ):
                # The node takes traffic from the fabric (an exit node, D-69): its answers
                # come back from the internet addressed to fabric prefixes and must return
                # through the tunnel, whatever mark they carry. Prefix routes in main (owned
                # by protocol 77, gone with the tunnel) do that without touching the
                # reverse-path check, which honours the packet mark.
                session_routes = tuple(
                    (net, fabric_iface) for nets in node_prefixes.values() for net in nets
                )
        tunnel_ifaces = {tunnel.interface for tunnel in tunnels.values()}
        return NodeFacts(
            node_id=node_id,
            client_pool=client_pool,
            tunnels=tunnels,
            sources=sources,
            local_networks=self.probes.local_networks(tunnel_ifaces),
            upstreams=tuple(upstreams),
            node_prefixes=node_prefixes,
            fabric_ifaces=(fabric_iface,),
            uplink=self.probes.uplink(tunnel_ifaces),
            all_rp_filter=self.probes.rp_filter(),
            local_addresses=local_addresses,
            access_ifaces=access_ifaces,
            session_routes=session_routes,
        )

    def desired(self) -> DesiredState:
        return compile_policy(self.policy(), self.facts()).desired
