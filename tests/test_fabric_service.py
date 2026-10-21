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
from kornode.services.fabric import FabricService


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
        self.config.system.data_dir.mkdir(parents=True, exist_ok=True)
        registry = Registry(open_registry(self.config.system.data_dir / "registry.db"))
        migrate(registry.conn)
        registry.create_node(id=1, name="hub", state="active")
        registry.create_node(id=2, name="alpha", state="active", roles=["exit"])
        registry.set_prefixes(2, [{"prefix": "192.168.50.0/24", "kind": "lan", "export": True}])

    def service(self) -> FabricService:
        return FabricService(self.config, self.path, sync=self.synced.append)


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def test_show_aggregates_nodes_prefixes_dns_and_sources(world: World) -> None:
    shown = world.service().show()

    assert shown["fabric"]["domain"] == world.config.fabric.domain
    assert shown["hub"]["fabric_address"] == "10.99.0.1"
    (node,) = shown["nodes"]
    assert (node["name"], node["roles"], node["online"]) == ("alpha", ["exit"], False)
    assert node["fabric_address"] == "10.99.0.2"
    assert node["prefixes"] == [{"prefix": "192.168.50.0/24", "kind": "lan", "export": True}]
    assert shown["dns"]["domain"] == world.config.fabric.domain
    assert shown["sources"] == []
    assert "seal_pubkey" not in json.dumps(shown)


def test_set_updates_only_fabric_and_syncs(world: World) -> None:
    result = world.service().set({"domain": "mesh.example"})

    assert result["fabric"]["domain"] == "mesh.example"
    stored = yaml.safe_load(world.path.read_text(encoding="utf-8"))
    assert stored["fabric"]["domain"] == "mesh.example"
    assert stored["web"]["admin_password"] == "admin-secret"
    assert world.path.stat().st_mode & 0o777 == 0o600
    assert len(world.synced) == 1 and world.synced[0].fabric.domain == "mesh.example"


def test_set_refuses_bad_input_and_writes_nothing(world: World) -> None:
    before = world.path.read_text(encoding="utf-8")
    for bad in ({"bogus": 1}, {}, {"cidr": "not-a-cidr"}):
        with pytest.raises(ManagementError) as err:
            world.service().set(bad)
        assert err.value.status == 422
    assert world.path.read_text(encoding="utf-8") == before
    assert world.synced == []
    assert not list(world.path.parent.glob(".fabric-check-*"))


def test_api_requires_admin_and_round_trips(world: World) -> None:
    client = TestClient(
        create_app(world.config, config_path=world.path), base_url="https://testserver"
    )
    assert client.get("/api/fabric").status_code == 401
    assert client.patch("/api/fabric", json={"domain": "x.example"}).status_code == 401
    auth = ("admin", "admin-secret")

    assert client.get("/api/fabric", auth=auth).json()["nodes"][0]["name"] == "alpha"
    saved = client.patch("/api/fabric", auth=auth, json={"domain": "mesh.example"})
    assert saved.json()["fabric"]["domain"] == "mesh.example"
    assert client.patch("/api/fabric", auth=auth, json={"cidr": "bad"}).status_code == 422


def test_cli_show_and_set(world: World) -> None:
    runner = CliRunner()
    base = ["--config", str(world.path)]

    shown: Any = json.loads(runner.invoke(app, [*base, "fabric", "show", "--json"]).output)
    assert shown["hub"]["fabric_address"] == "10.99.0.1"
    saved = runner.invoke(app, [*base, "fabric", "set", "--domain", "mesh.example", "--json"])
    assert saved.exit_code == 0, saved.output
    assert load_config(world.path).fabric.domain == "mesh.example"
