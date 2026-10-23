from __future__ import annotations

import ipaddress
from pathlib import Path

from tests.test_agent_apply import World

from kornode.bundle.signing import key_id, raw_public_bytes
from kornode.bundle.validator import Validated, validate
from kornode_agent.config import AgentConfig, HubConfig, InterlinkConfig
from kornode_agent.health import AgentHealth
from kornode_agent.inputs import AgentNetInputs, Network
from kornode_agent.tunnels import specs_for

CONFIG = AgentConfig(
    node_id=3,
    hub=HubConfig(
        host="hub.example", port=443, pin="pin-sha256:AAA", control_url="https://10.99.0.1:8444"
    ),
    interlink=InterlinkConfig(),
)


class FakeProbes:
    def __init__(self, links: dict[str, bool]) -> None:
        self._links = links

    def links(self) -> dict[str, bool]:
        return self._links

    def local_networks(self, exclude: set[str]) -> tuple[Network, ...]:
        return (ipaddress.ip_network("192.168.1.0/24"),)

    def uplink(self, exclude: set[str]) -> str | None:
        return "eth0"

    def rp_filter(self) -> str | None:
        return "2"


class FakeCarriers:
    def carrier(self, exit_name: str) -> tuple[str, ...]:
        return ("203.0.113.10",)


def _validated(tmp_path: Path) -> Validated:
    world = World(tmp_path)
    body, sig = world.bundle(5)
    pub = raw_public_bytes(world.signer.public_key())
    return validate(
        body,
        sig,
        trusted={key_id(pub): world.signer.public_key()},
        high_water_version=0,
        agent_version="2.1.0",
        expected_node_id=3,
        seal_private_key=world.seal,
    )


def test_bootstrap_marks_nothing_and_keeps_the_kill_switch_state_empty() -> None:
    inputs = AgentNetInputs(CONFIG, FakeProbes({"oc-hub0": True}), FakeCarriers())
    desired = inputs.desired()
    assert desired.nft is not None
    assert "oc-office" not in str(desired.nft)


def test_bundle_facts_follow_the_links(tmp_path: Path) -> None:
    validated = _validated(tmp_path)
    inputs = AgentNetInputs(
        CONFIG, FakeProbes({"oc-hub0": True, "oc-office": False, "awg0": True}), FakeCarriers()
    )
    inputs.set_bundle(validated)
    facts = inputs.facts()
    assert facts.node_id == 3 and facts.uplink == "eth0"
    assert facts.tunnels["interlink"].up and facts.tunnels["interlink"].carrier == ("203.0.113.10",)
    assert not facts.tunnels["upstream:office"].up
    assert facts.sources["amnezia"].present
    assert facts.upstreams == ("office",)
    assert inputs.desired() is not None

    inputs.set_bundle(None)
    assert inputs.facts().upstreams == ()


def test_resolved_set_addresses_reach_the_node_facts(tmp_path: Path) -> None:
    resolved = {"web": frozenset({"203.0.113.5"})}
    inputs = AgentNetInputs(
        CONFIG, FakeProbes({"oc-hub0": True}), FakeCarriers(), resolved=lambda: resolved
    )
    inputs.set_bundle(_validated(tmp_path))
    assert inputs.facts().resolved == resolved


def test_set_bundle_wakes_the_reconciler(tmp_path: Path) -> None:
    woke: list[int] = []
    inputs = AgentNetInputs(
        CONFIG, FakeProbes({}), FakeCarriers(), on_change=lambda: woke.append(1)
    )
    inputs.set_bundle(None)
    assert woke == [1]


def test_specs_pin_the_hub_and_keep_secrets_out_of_repr(tmp_path: Path) -> None:
    validated = _validated(tmp_path)
    specs = specs_for(validated, CONFIG, tmp_path)
    assert set(specs) == {"interlink", "upstream:office"}
    interlink = specs["interlink"].dials[0]
    assert interlink.server_cert_pin and interlink.pfs and interlink.auth_type == "cert"
    office = specs["upstream:office"]
    assert office.password == "pw" and "pw" not in repr(office)
    assert set(specs_for(None, CONFIG, tmp_path)) == {"interlink"}


class FakeTunnels:
    def __init__(self, up: set[str]) -> None:
        self.up = up

    def is_up(self, exit_name: str) -> bool:
        return exit_name in self.up


def test_health_needs_tunnel_hub_ping_and_check_host(tmp_path: Path) -> None:
    validated = _validated(tmp_path)
    probes: list[tuple[str, str]] = []

    def probe(iface: str, host: str) -> bool:
        probes.append((iface, host))
        return False

    health = AgentHealth(FakeTunnels({"interlink", "upstream:office"}), lambda: True, probe)
    result = health.checks(validated)
    assert result["interlink"] is True
    assert result["upstream:office"] is False and probes  # check_host failed through the mark
    assert AgentHealth(FakeTunnels({"interlink"}), lambda: False).checks(None) == {
        "interlink": False
    }


def test_bootstrap_routes_the_hub_through_the_interlink_exit_only() -> None:
    inputs = AgentNetInputs(
        AgentConfig(
            node_id=3,
            hub=HubConfig(
                host="hub.example",
                port=443,
                pin="pin-sha256:AAA",
                control_url="https://10.99.0.1:8444",
            ),
        ),
        FakeProbes({"oc-hub0": True}),
        FakeCarriers(),
    )
    desired = inputs.desired()
    interlink_routes = [r for r in desired.routes if getattr(r, "dev", None) == "oc-hub0"]
    assert [r.dst for r in interlink_routes] == ["10.99.0.1/32"]


def test_a_node_that_takes_interlink_traffic_routes_the_interlink_prefixes_in_main(
    tmp_path: Path,
) -> None:
    """An exit node (D-69): answers come back addressed to interlink prefixes and must return
    through the tunnel; prefix routes (proto 77, in main) do that and disappear with the link."""
    import dataclasses

    from kornode.net.model import EgressPolicy

    validated = _validated(tmp_path)
    exit_policy = EgressPolicy.model_validate(
        {
            "egress": [
                {"id": "to-interlink", "from": ["host"], "to": "interlink", "via": "interlink"},
                {"id": "gateway-local", "from": ["interlink"], "to": "any", "via": "local"},
            ]
        }
    )
    plain = validated
    taking = dataclasses.replace(
        validated, bundle=validated.bundle.model_copy(update={"policy": exit_policy})
    )

    def facts(item: object, links: dict[str, bool]) -> object:
        inputs = AgentNetInputs(CONFIG, FakeProbes(links), FakeCarriers())
        inputs.set_bundle(item)  # type: ignore[arg-type]
        return inputs.facts()

    up = facts(taking, {"oc-hub0": True})
    assert up.session_routes, "an exit node needs the routes"  # type: ignore[attr-defined]
    assert {dev for _, dev in up.session_routes} == {"oc-hub0"}  # type: ignore[attr-defined]
    assert not facts(plain, {"oc-hub0": True}).session_routes  # type: ignore[attr-defined]
    assert not facts(taking, {"oc-hub0": False}).session_routes  # type: ignore[attr-defined]
