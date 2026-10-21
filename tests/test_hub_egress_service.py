from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from kornode.api.app import create_app
from kornode.cli import app
from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.registry.db import migrate, open_registry
from kornode.registry.repository import Registry
from kornode.services.agent_models import ManagementError
from kornode.services.hub_egress import HubEgressService

SOURCE = {"name": "wg", "interface": "wg0", "cidr": "10.8.1.0/24"}
RULE = {"from": ["clients", "wg"], "to": "any", "via": "local"}


class World:
    def __init__(self, tmp_path: Path) -> None:
        self.path = tmp_path / "config.yaml"
        self.path.write_text(
            yaml.safe_dump(
                {
                    "system": {
                        "data_dir": str(tmp_path / "data"),
                        "generated_dir": str(tmp_path / "generated"),
                        "secrets_dir": str(tmp_path / "secrets"),
                        "log_dir": str(tmp_path / "logs"),
                    },
                    "web": {"admin_password": "admin-secret"},
                }
            ),
            encoding="utf-8",
        )
        self.config = load_config(self.path)
        self.synced: list[AppConfig] = []

    def service(self) -> HubEgressService:
        return HubEgressService(self.config, self.path, sync=self.synced.append)

    def add_exit_node(self) -> None:
        self.config.system.data_dir.mkdir(parents=True, exist_ok=True)
        registry = Registry(open_registry(self.config.system.data_dir / "registry.db"))
        migrate(registry.conn)
        registry.create_node(id=1, name="hub", state="active")
        registry.create_node(id=2, name="out", state="active", roles=["exit"])


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def test_set_policy_writes_config_and_syncs(world: World) -> None:
    result = world.service().set_policy({"sources": [SOURCE], "egress": [RULE]})

    assert result["policy"]["egress"] == [RULE]
    stored = yaml.safe_load(world.path.read_text(encoding="utf-8"))
    assert stored["egress"] == [RULE] and stored["sources"] == [SOURCE]
    assert stored["web"]["admin_password"] == "admin-secret"  # the rest of the file is kept
    assert world.path.stat().st_mode & 0o777 == 0o600
    assert len(world.synced) == 1 and world.synced[0].egress_policy().sources[0].name == "wg"


def test_empty_egress_stays_explicit_and_drops_clients(world: World) -> None:
    world.service().set_policy({"egress": []})

    assert yaml.safe_load(world.path.read_text(encoding="utf-8"))["egress"] == []
    assert load_config(world.path).egress == ()


def test_invalid_policy_is_refused_and_nothing_is_written(world: World) -> None:
    before = world.path.read_text(encoding="utf-8")
    for bad in (
        {"egress": [{"from": ["ghost"], "to": "any", "via": "local"}]},
        {"sources": [{**SOURCE, "cidr": "192.168.9.0/24"}]},  # outside the source pool
        {"egress": [{"from": ["clients"], "to": "any", "via": "drop", "bogus": 1}]},
    ):
        with pytest.raises(ManagementError) as err:
            world.service().set_policy(bad)
        assert err.value.status == 422
    assert world.path.read_text(encoding="utf-8") == before
    assert world.synced == []


def test_exit_target_is_checked_against_the_registry(world: World) -> None:
    exit_rule = {"egress": [{"from": ["clients"], "to": "any", "via": "exit:2"}]}
    with pytest.raises(ManagementError) as err:
        world.service().set_policy(exit_rule)
    assert (err.value.status, err.value.error) == (409, "exit_node")

    world.add_exit_node()
    world.service().set_policy(exit_rule)
    assert load_config(world.path).egress[0].via == "exit:2"


def test_check_changes_nothing(world: World) -> None:
    before = world.path.read_text(encoding="utf-8")

    assert world.service().check({"sources": [SOURCE], "egress": [RULE]})["valid"] is True
    assert world.path.read_text(encoding="utf-8") == before
    assert world.synced == []
    assert not list(world.path.parent.glob(".egress-check-*"))


def test_check_reports_shadowed_rules(world: World) -> None:
    shadowed = {"egress": [{"from": ["clients"], "to": "any", "via": "local"}, RULE]}
    warnings = world.service().check({"sources": [SOURCE], **shadowed})["warnings"]
    assert warnings == []  # the second rule adds the source, so it is not covered
    twice = {"egress": [RULE, RULE]}
    result = world.service().check({"sources": [SOURCE], **twice})
    assert result["warnings"] == ["rule 1 is shadowed by rule 0"]
    assert result["dead_rules"] == [{"rule": 1, "shadowed_by": 0}]
    assert world.service().policy()["dead_rules"] == []


def test_source_add_replace_and_delete(world: World) -> None:
    service = world.service()
    service.set_source("wg", {"interface": "wg0", "cidr": "10.8.1.0/24"})
    service.set_source("wg", {"interface": "wg1", "cidr": "10.8.1.0/24", "export": False})
    assert service.sources()["sources"] == [
        {"name": "wg", "interface": "wg1", "cidr": "10.8.1.0/24", "export": False}
    ]
    service.set_source("wg", None)
    assert service.sources()["sources"] == []
    with pytest.raises(ManagementError) as err:
        service.set_source("wg", None)
    assert err.value.status == 404


def test_removing_a_referenced_source_is_refused(world: World) -> None:
    world.service().set_policy({"sources": [SOURCE], "egress": [RULE]})
    with pytest.raises(ManagementError):
        world.service().set_source("wg", None)
    assert load_config(world.path).sources[0].name == "wg"


def test_api_requires_admin_and_round_trips(world: World) -> None:
    application = create_app(world.config, config_path=world.path)
    client = TestClient(application, base_url="https://testserver")
    for method, path in (("get", "/api/egress"), ("put", "/api/egress"), ("get", "/api/sources")):
        assert client.request(method, path).status_code == 401
    auth = ("admin", "admin-secret")

    assert client.put("/api/egress", auth=auth, json={"egress": [RULE], "sources": [SOURCE]})
    assert client.get("/api/egress", auth=auth).json()["policy"]["egress"] == [RULE]
    assert client.get("/api/sources", auth=auth).json()["sources"] == [SOURCE]
    refused = client.put("/api/sources/bad", auth=auth, json={"interface": "x", "cidr": "nope"})
    assert refused.status_code == 422


def test_cli_show_check_set(world: World, tmp_path: Path) -> None:
    runner = CliRunner()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"sources": [SOURCE], "egress": [RULE]}), encoding="utf-8")
    base = ["--config", str(world.path)]

    checked = runner.invoke(app, [*base, "egress", "check", "--file", str(policy), "--json"])
    assert checked.exit_code == 0, checked.output
    saved = runner.invoke(app, [*base, "egress", "set", "--file", str(policy), "--json"])
    assert saved.exit_code == 0, saved.output
    shown: Any = json.loads(runner.invoke(app, [*base, "egress", "show", "--json"]).output)
    assert shown["policy"]["egress"] == [RULE]
    listed = json.loads(runner.invoke(app, [*base, "source", "list", "--json"]).output)
    assert listed["sources"] == [SOURCE]
