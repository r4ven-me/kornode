from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig
from kornode.net.compile import EnrollGuard, TunnelFact
from kornode.services.command import CommandResult
from kornode.services.netinputs import (
    HubNetInputs,
    carrier_state_dir,
    resolved_state_dir,
)

LINKS = [
    {"ifname": "lo", "flags": ["LOOPBACK", "UP"]},
    {"ifname": "eth0", "flags": ["BROADCAST", "UP", "LOWER_UP"]},
    {"ifname": "oc-middle0", "flags": ["POINTOPOINT", "UP"]},
    {"ifname": "oc-backup", "flags": ["POINTOPOINT"]},
    {"ifname": "docker0", "flags": ["BROADCAST", "UP"]},
]
ROUTES_V4 = [
    {"dst": "192.168.1.0/24", "dev": "eth0", "scope": "link"},
    {"dst": "172.17.0.0/16", "dev": "docker0", "scope": "link"},
    {"dst": "10.250.0.1", "dev": "oc-middle0", "scope": "link"},
]


class FakeRunner:
    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        if argv[:3] == ["ip", "-j", "link"]:
            return CommandResult(tuple(argv), 0, json.dumps(LINKS), "")
        if argv[:3] == ["ip", "-j", "-4"]:
            return CommandResult(tuple(argv), 0, json.dumps(ROUTES_V4), "")
        if argv[:3] == ["ip", "-j", "-6"]:
            return CommandResult(tuple(argv), 0, "[]", "")
        if argv[:4] == ["ip", "route", "show", "default"]:
            return CommandResult(tuple(argv), 0, "default via 192.168.1.1 dev eth0", "")
        return CommandResult(tuple(argv), 1, "", "unexpected")


def _config(tmp_path: Path, **extra: Any) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
                "log_dir": tmp_path / "logs",
            },
            **extra,
        }
    )


def _proc(tmp_path: Path, rp_filter: str) -> Path:
    path = tmp_path / "proc" / "net" / "ipv4" / "conf" / "all"
    path.mkdir(parents=True)
    (path / "rp_filter").write_text(rp_filter + "\n", encoding="utf-8")
    return tmp_path / "proc"


UPSTREAM = {
    "enabled": True,
    "active_profile": "main",
    "profiles": [
        {"name": "main", "server": "203.0.113.2", "username": "u"},
        {"name": "backup", "server": "203.0.113.3", "username": "u", "interface": "oc-backup"},
    ],
}


def test_facts_from_runtime(tmp_path: Path) -> None:
    config = _config(tmp_path, upstream=UPSTREAM, routing={"client_policy": "full"})
    carrier = carrier_state_dir(config)
    carrier.mkdir(parents=True)
    (carrier / "main.addrs").write_text("203.0.113.2\n", encoding="utf-8")

    facts = HubNetInputs(config, runner=FakeRunner(), proc_sys=_proc(tmp_path, "1")).facts()

    assert facts.client_pool == ipaddress.IPv4Network(config.server.ipv4_network)
    assert facts.tunnels == {
        "upstream:main": TunnelFact("oc-middle0", True, ("203.0.113.2",)),
        "upstream:backup": TunnelFact("oc-backup", False, ()),
    }
    assert facts.upstreams == ("main", "backup")
    # Tunnel peers are not "local networks"; LAN and docker are.
    assert [str(net) for net in facts.local_networks] == ["172.17.0.0/16", "192.168.1.0/24"]
    assert facts.uplink == "eth0"
    assert facts.all_rp_filter == "1"
    assert facts.enroll is not None


def test_facts_include_enroll_guard(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        auth={"password": {"enabled": True}},
    )

    facts = HubNetInputs(config, runner=FakeRunner(), proc_sys=_proc(tmp_path, "1")).facts()

    assert facts.enroll == EnrollGuard(
        pool=ipaddress.IPv4Network("10.99.255.240/28"),
        address=ipaddress.IPv4Address("10.99.0.1"),
        port=8444,
    )


def test_desired_state_for_a_full_tunnel_config(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        upstream=UPSTREAM,
        egress=[{"from": ["clients", "host"], "to": "any", "via": "upstream:main"}],
    )
    inputs = HubNetInputs(config, runner=FakeRunner(), proc_sys=_proc(tmp_path, "0"))

    compiled = inputs.compiled()

    assert [exit_.name for exit_ in compiled.exits] == ["upstream:main"]
    tables = {route.table for route in compiled.desired.routes}
    assert tables == {12001}
    assert 'oifname "eth0"' in compiled.script  # kill-switch on the uplink


def test_resolved_domains_are_read_back_per_set(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        upstream=UPSTREAM,
        sets={"split": {"domains": ["corp.example.com"]}},
        egress=[{"from": ["clients"], "to": {"set": "split"}, "via": "upstream:main"}],
    )
    resolved = resolved_state_dir(config)
    resolved.mkdir(parents=True)
    (resolved / "split.txt").write_text("10.60.1.1\n10.60.1.2\n", encoding="utf-8")
    inputs = HubNetInputs(config, runner=FakeRunner(), proc_sys=_proc(tmp_path, "0"))

    elements = {item.set_name: item.elements for item in inputs.desired().elements}

    assert elements["split_v4"] == {"10.60.1.1/32", "10.60.1.2/32"}


def test_upstream_disabled_has_no_tunnels(tmp_path: Path) -> None:
    config = _config(tmp_path)
    inputs = HubNetInputs(config, runner=FakeRunner(), proc_sys=_proc(tmp_path, "0"))

    compiled = inputs.compiled()

    assert inputs.facts().tunnels == {}
    assert [exit_.name for exit_ in compiled.exits] == ["local"]


def test_session_routes_follow_connected_agents_and_exported_prefixes(tmp_path: Path) -> None:
    from kornode.registry.db import migrate, open_registry
    from kornode.registry.repository import Registry

    config = _config(tmp_path, auth={"password": {"enabled": True}})
    config.system.data_dir.mkdir(parents=True)
    registry = Registry(open_registry(config.system.data_dir / "registry.db"))
    migrate(registry.conn)
    registry.create_node(id=1, name="hub", state="active")
    for node_id in (2, 3, 4):
        registry.create_node(id=node_id, name=f"n{node_id}", state="active")
    registry.set_prefixes(2, [{"prefix": "192.168.2.0/24", "kind": "lan", "export": True}])
    registry.set_prefixes(3, [{"prefix": "192.168.3.0/24", "kind": "lan", "export": True}])
    registry.set_prefixes(4, [{"prefix": "192.168.4.0/24", "kind": "lan", "export": False}])

    class Runner(FakeRunner):
        def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
            if argv == ["ip", "-j", "-4", "route", "show", "table", "main"]:
                routes = [
                    {"dst": "10.99.0.3", "dev": "vpns0", "scope": "link"},
                    {"dst": "10.99.0.4", "dev": "vpns1", "scope": "link"},
                    {"dst": "10.99.0.9", "dev": "eth0", "scope": "link"},
                ]
                return CommandResult(tuple(argv), 0, json.dumps(routes), "")
            return super().run(argv, **kwargs)

    facts = HubNetInputs(config, runner=Runner(), proc_sys=_proc(tmp_path, "1")).facts()

    # node 2 is not connected, node 4 does not export.
    assert facts.session_routes == ((ipaddress.ip_network("192.168.3.0/24"), "vpns0"),)


def _exit_inputs(tmp_path: Path, connected: bool, **extra: Any) -> HubNetInputs:
    from kornode.registry.db import migrate, open_registry
    from kornode.registry.repository import Registry

    config = _config(
        tmp_path,
        sources=[{"name": "wg", "interface": "wg0", "cidr": "10.8.1.0/24"}],
        egress=[{"from": ["clients", "wg"], "to": "any", "via": "exit:2"}],
        **extra,
    )
    config.system.data_dir.mkdir(parents=True)
    registry = Registry(open_registry(config.system.data_dir / "registry.db"))
    migrate(registry.conn)
    registry.create_node(id=1, name="hub", state="active")
    registry.create_node(id=2, name="out", state="active", roles=["exit"])

    class Runner(FakeRunner):
        def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
            if argv == ["ip", "-j", "-4", "route", "show", "table", "main"]:
                routes = [{"dst": "10.99.0.2", "dev": "vpns0", "scope": "link"}] * connected
                return CommandResult(tuple(argv), 0, json.dumps(routes), "")
            return super().run(argv, **kwargs)

    return HubNetInputs(config, runner=Runner(), proc_sys=_proc(tmp_path, "1"))


def test_hub_source_is_a_local_prefix_exported_to_the_fabric(tmp_path: Path) -> None:
    facts = _exit_inputs(tmp_path, connected=True).facts()

    assert ipaddress.ip_network("10.8.1.0/24") in facts.node_prefixes[1]
    assert facts.sources["wg"].present is False  # no wg0 link in the fake host


def test_hub_exit_goes_through_the_node_session_and_fails_closed_without_it(
    tmp_path: Path,
) -> None:
    up = _exit_inputs(tmp_path / "up", connected=True).compiled()
    down = _exit_inputs(tmp_path / "down", connected=False).compiled()

    (exit_up,) = [e for e in up.exits if e.name == "exit:2"]
    (exit_down,) = [e for e in down.exits if e.name == "exit:2"]
    assert (exit_up.interface, exit_up.up, exit_up.nat) == ("vpns0", True, False)
    assert (exit_down.interface, exit_down.up) == (None, False)
    default = [r for r in down.desired.routes if r.table == exit_down.table and r.dst == "default"]
    assert [r.type for r in default] == ["unreachable", "unreachable"]
    # answers of the exit node pass the strict reverse path
    assert "@transit_ifaces" in up.script
