"""P4-03: interlink DNS zone in the registry, hub dnsmasq and the bundle (D-66)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from tests.test_agent_management import Enrollment
from tests.test_bundle_service import Env

from kornode.bundle.models import Dns, LocalRecord
from kornode.renderers import DnsmasqConfigRenderer
from kornode.services.agent_models import ManagementError
from kornode.services.agents import AgentService
from kornode.services.interlink_dns import DnsRecordInput, InterlinkDnsService, dnsmasq_lines


class World:
    def __init__(self, tmp_path: Path) -> None:
        self.env = Env(tmp_path)
        self.restarts = 0
        self.agents = AgentService(
            self.env.config,
            bundles=self.env.service,
            enrollment=Enrollment(self.env),
            sync=lambda: None,
            clock=lambda: datetime(2026, 10, 20, tzinfo=UTC),
        )
        self.dns = InterlinkDnsService(
            self.env.config, agents=self.agents, restart_dnsmasq=self._restart
        )

    def _restart(self) -> None:
        self.restarts += 1

    def conf(self) -> str:
        return DnsmasqConfigRenderer().target_path(self.env.config).read_text()

    def fqdns(self) -> dict[str, dict[str, Any]]:
        return {item["fqdn"]: item for item in self.dns.list()["records"]}


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    result = World(tmp_path)
    yield result
    result.env.registry.conn.close()


def record(**kwargs: Any) -> DnsRecordInput:
    return DnsRecordInput.model_validate(kwargs)


def test_generated_names_cover_hub_and_every_registered_node(world: World) -> None:
    world.env.add(3)
    world.env.add(4, active=False)

    records = world.fqdns()

    assert records["hub.kornode.lan"]["value"] == "10.100.1.1"
    assert records["node1.kornode.lan"]["value"] == "10.100.1.1"
    assert records["node3.kornode.lan"]["value"] == "10.100.3.1"
    assert records["node4.kornode.lan"]["node"] == "node4"
    assert all(item["generated"] for item in records.values())


def test_hub_record_is_rendered_into_local_zone_and_restarts_once(world: World) -> None:
    world.dns.add(record(name="monitoring", type="A", value="10.100.1.20"))

    conf = world.conf()
    assert "local=/kornode.lan/" in conf
    assert "host-record=monitoring.kornode.lan,10.100.1.20" in conf
    assert "host-record=hub.kornode.lan,10.100.1.1" in conf
    assert world.restarts == 1
    # Unchanged zone: no rewrite, no restart.
    assert world.dns.sync() is False
    assert world.restarts == 1


def test_node_record_lives_in_node_zone_and_reaches_only_its_bundle(world: World) -> None:
    world.env.add(2)
    world.env.add(3)
    world.dns.add(record(name="cam", type="A", value="192.168.3.7", node="node3"))
    world.dns.add(record(name="monitoring", type="A", value="10.100.1.20"))

    assert world.fqdns()["cam.node3.kornode.lan"]["node"] == "node3"
    dns3 = world.env.check(world.env.registry.latest_bundle(3)).bundle.dns
    dns2 = world.env.check(world.env.registry.latest_bundle(2)).bundle.dns
    assert dns3 is not None and dns2 is not None
    names3 = {(item.name, item.value) for item in dns3.local_records or ()}
    assert names3 == {
        ("node3.kornode.lan", "10.100.3.1"),
        ("cam.node3.kornode.lan", "192.168.3.7"),
    }
    assert {item.name for item in dns2.local_records or ()} == {"node2.kornode.lan"}
    assert dns3.forward_zones is not None
    assert [(z.zone, z.servers) for z in dns3.forward_zones] == [
        ("kornode.lan", ("10.100.1.1",))
    ]
    # Hub-wide records are answered by the hub, never copied into bundles.
    assert "monitoring" not in str(dns2) + str(dns3)


def test_several_addresses_share_one_host_record_line(world: World) -> None:
    world.dns.add(record(name="ha", type="A", value="10.100.1.21"))
    world.dns.add(record(name="ha", type="AAAA", value="fd00::21"))
    world.dns.add(record(name="ha", type="A", value="10.100.1.22"))

    assert "host-record=ha.kornode.lan,10.100.1.21,10.100.1.22,fd00::21" in world.conf()


@pytest.mark.parametrize(
    ("data", "code"),
    [
        ({"name": "hub", "type": "A", "value": "10.100.1.9"}, "reserved"),
        ({"name": "x.node7", "type": "A", "value": "10.100.1.9"}, "reserved"),
        ({"name": "web", "type": "A", "value": "fd00::1"}, "invalid"),
        ({"name": "web", "type": "AAAA", "value": "10.0.0.1"}, "invalid"),
        ({"name": "web", "type": "A", "value": "not-an-ip"}, "invalid"),
        ({"name": "alias", "type": "CNAME", "value": "missing"}, "cname_target"),
        ({"name": "alias", "type": "CNAME", "value": "bad name!"}, "invalid"),
    ],
)
def test_invalid_records_are_refused(world: World, data: dict[str, str], code: str) -> None:
    with pytest.raises(ManagementError) as raised:
        world.dns.add(record(**data))
    assert raised.value.error == code
    assert world.env.registry.dns_records() == []


def test_names_are_validated_before_the_service(world: World) -> None:
    for name in ("a\nserver=/x/1.1.1.1", "-bad", "under_score", "a..b"):
        with pytest.raises(ValidationError):
            record(name=name, type="A", value="10.0.0.1")


def test_cname_rules(world: World) -> None:
    world.env.add(3)
    world.dns.add(record(name="grafana", type="A", value="10.100.1.30"))
    world.dns.add(record(name="dash", type="CNAME", value="grafana.kornode.lan."))
    assert world.fqdns()["dash.kornode.lan"]["value"] == "grafana.kornode.lan"
    assert "cname=dash.kornode.lan,grafana.kornode.lan" in world.conf()

    with pytest.raises(ManagementError) as raised:
        world.dns.add(record(name="dash", type="A", value="10.100.1.31"))
    assert raised.value.error == "cname_conflict"
    with pytest.raises(ManagementError) as raised:
        world.dns.delete(record(name="grafana", type="A", value="10.100.1.30"))
    assert raised.value.error == "cname_target"
    # An agent answers its zone alone: a CNAME out of it would dangle there.
    with pytest.raises(ManagementError) as raised:
        world.dns.add(record(name="g", type="CNAME", value="grafana", node="node3"))
    assert raised.value.error == "cname_target"
    world.dns.add(record(name="box", type="CNAME", value="node3", node="node3"))


def test_delete_and_missing_record(world: World) -> None:
    world.dns.add(record(name="web", type="A", value="10.100.1.40"))
    world.dns.delete(record(name="web", type="A", value="10.100.1.40"))
    assert "web.kornode.lan" not in world.fqdns()
    assert "web.kornode.lan" not in world.conf()
    with pytest.raises(ManagementError) as raised:
        world.dns.delete(record(name="web", type="A", value="10.100.1.40"))
    assert raised.value.status == 404


def test_duplicate_and_hub_node_target(world: World) -> None:
    world.dns.add(record(name="web", type="A", value="10.100.1.40"))
    with pytest.raises(ManagementError) as raised:
        world.dns.add(record(name="web", type="A", value="10.100.1.40"))
    assert raised.value.status == 409
    with pytest.raises(ManagementError) as raised:
        world.dns.add(record(name="x", type="A", value="10.0.0.1", node="hub"))
    assert raised.value.status == 404


def test_failed_restart_is_reported_as_committed(world: World) -> None:
    def broken() -> None:
        raise RuntimeError("supervisor down")

    world.dns.restart_dnsmasq = broken
    with pytest.raises(ManagementError) as raised:
        world.dns.add(record(name="web", type="A", value="10.100.1.40"))
    assert raised.value.error == "dns_sync_failed"
    assert raised.value.details == {"committed": True, "recovery": "korctl registry maintain"}
    assert len(world.env.registry.dns_records()) == 1
    # The file already matches, but the failed restart is still retried.
    world.dns.restart_dnsmasq = world._restart
    assert world.dns.sync() is True
    assert world.restarts == 1
    assert world.dns.sync() is False


def test_dangling_cname_elsewhere_does_not_block_unrelated_deletes(world: World) -> None:
    world.env.add(3)
    world.dns.add(record(name="box", type="A", value="10.100.3.9", node="node3"))
    world.dns.add(record(name="cam", type="CNAME", value="box.node3"))
    world.dns.add(record(name="web", type="A", value="10.100.1.40"))
    world.env.registry.delete_node(3)  # orphans the hub-wide CNAME
    world.dns.delete(record(name="web", type="A", value="10.100.1.40"))
    assert "cname=cam" not in world.conf()


def test_node_records_go_with_the_node(world: World) -> None:
    world.env.add(3)
    world.dns.add(record(name="cam", type="A", value="192.168.3.7", node="node3"))
    world.env.registry.delete_node(3)
    assert world.env.registry.dns_records() == []


def test_interlink_enables_hub_dnsmasq(world: World) -> None:
    assert "interlink_dns" in world.env.config.dnsmasq_active_reasons()


def test_orphaned_cname_is_not_rendered() -> None:
    from kornode.services.interlink_dns import ZoneRecord

    lines = dnsmasq_lines(
        [
            ZoneRecord("a.z", "CNAME", "gone.z", None),
            ZoneRecord("b.z", "CNAME", "h.z", None),
            ZoneRecord("h.z", "A", "10.0.0.1", None),
        ]
    )
    assert lines == ["host-record=h.z,10.0.0.1", "cname=b.z,h.z"]


@pytest.mark.parametrize(
    "data",
    [
        {"name": "x.kornode.lan\nlog-queries", "type": "A", "value": "10.0.0.1"},
        {"name": "x.kornode.lan", "type": "A", "value": "fd00::1"},
        {"name": "x.kornode.lan", "type": "CNAME", "value": "y,z"},
    ],
)
def test_bundle_dns_records_are_strict(data: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        LocalRecord.model_validate(data)


def test_bundle_dns_servers_must_be_addresses() -> None:
    with pytest.raises(ValidationError):
        Dns.model_validate({"forward_zones": [{"zone": "z", "servers": ["1.1.1.1#53"]}]})
    with pytest.raises(ValidationError):
        Dns.model_validate({"upstream_servers": ["resolver.example"]})


def test_api_requires_auth_and_shares_the_service(world: World) -> None:
    from fastapi.testclient import TestClient

    from kornode.api.app import create_app
    from kornode.config.models import AppConfig

    data = world.env.config.model_dump(mode="json")
    data["web"]["admin_password"] = "admin-secret"
    application = create_app(AppConfig.model_validate(data))
    application.state.interlink_dns = world.dns
    client = TestClient(application, base_url="https://testserver")
    for method in ("GET", "POST", "DELETE"):
        assert client.request(method, "/api/dns/records").status_code == 401
    auth = ("admin", "admin-secret")
    body = {"name": "monitoring", "type": "A", "value": "10.100.1.20"}
    added = client.post("/api/dns/records", auth=auth, json=body)
    assert added.status_code == 200
    assert "monitoring.kornode.lan" in {r["fqdn"] for r in added.json()["records"]}
    refused = client.post("/api/dns/records", auth=auth, json={**body, "extra": 1})
    assert refused.status_code == 422
    deleted = client.request("DELETE", "/api/dns/records", auth=auth, json=body)
    assert deleted.status_code == 200
    missing = client.request("DELETE", "/api/dns/records", auth=auth, json=body)
    assert missing.status_code == 404


def test_cli_adds_lists_and_deletes(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    from typer.testing import CliRunner

    from kornode.cli import app

    world.env.add(3)
    monkeypatch.setattr("kornode.cli_agents.InterlinkDnsService", lambda config: world.dns)
    runner = CliRunner()
    added = runner.invoke(
        app, ["dns", "record", "add", "cam", "a", "192.168.3.7", "--node", "node3", "--json"]
    )
    assert added.exit_code == 0, added.output
    listed = json.loads(runner.invoke(app, ["dns", "record", "list", "--json"]).output)
    assert "cam.node3.kornode.lan" in {r["fqdn"] for r in listed["records"]}
    reserved = runner.invoke(app, ["dns", "record", "add", "hub", "A", "10.0.0.1", "--json"])
    assert reserved.exit_code == 2 and json.loads(reserved.output)["error"] == "reserved"
    deleted = runner.invoke(
        app, ["dns", "record", "del", "cam", "A", "192.168.3.7", "--node", "node3", "--json"]
    )
    assert deleted.exit_code == 0, deleted.output


def test_unsupervised_hub_has_no_resolver_to_restart(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kornode.services.command import CommandResult

    actions: list[str] = []

    def process_action(self: Any, action: str, process: str) -> CommandResult:
        actions.append(action)
        return CommandResult(("supervisor-rpc", action, process), 1, "", "no supervisor")

    monkeypatch.setattr("kornode.services.server.ServerService.process_action", process_action)
    service = InterlinkDnsService(world.env.config, agents=world.agents)
    service.add(record(name="web", type="A", value="10.100.1.40"))
    assert actions == ["status"]
    assert "web.kornode.lan" in world.conf()


def test_supervised_restart_failure_is_reported(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kornode.services.command import CommandResult

    def process_action(self: Any, action: str, process: str) -> CommandResult:
        return CommandResult(("supervisor-rpc", action, process), 0 if action == "status" else 1)

    monkeypatch.setattr("kornode.services.server.ServerService.process_action", process_action)
    monkeypatch.setattr(
        "kornode.services.internal_dns.InternalDnsService.ensure_listen_address",
        lambda self: None,
    )
    service = InterlinkDnsService(world.env.config, agents=world.agents)
    with pytest.raises(ManagementError) as raised:
        service.add(record(name="web", type="A", value="10.100.1.40"))
    assert raised.value.error == "dns_sync_failed"


def test_bundle_node_addresses_must_be_ipv4() -> None:
    from kornode.bundle.models import NodeInfo

    base = {"name": "n", "roles": [], "client_pool": "10.100.3.0/24"}
    with pytest.raises(ValidationError):
        NodeInfo.model_validate(
            {
                **base, "interlink_address": "10.99.0.3\nserver=1.1.1.1",
                "service_address": "10.100.3.1",
            }
        )
    with pytest.raises(ValidationError):
        NodeInfo.model_validate(
            {**base, "interlink_address": "10.99.0.3", "service_address": "fd00::1"}
        )
