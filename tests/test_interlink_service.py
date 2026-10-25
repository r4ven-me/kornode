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
from kornode.services.interlink import InterlinkService


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
        registry.create_node(id=2, name="alpha", state="active", roles=["gateway"])
        registry.set_prefixes(2, [{"prefix": "192.168.50.0/24", "kind": "lan", "export": True}])

    def service(self) -> InterlinkService:
        return InterlinkService(self.config, self.path, sync=self.synced.append)


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def test_show_aggregates_nodes_prefixes_dns_and_sources(world: World) -> None:
    shown = world.service().show()

    assert shown["interlink"]["domain"] == world.config.interlink.domain
    assert shown["hub"]["interlink_address"] == "10.99.0.1"
    (node,) = shown["nodes"]
    assert (node["name"], node["roles"], node["online"]) == ("alpha", ["gateway"], False)
    assert node["interlink_address"] == "10.99.0.2"
    assert node["prefixes"] == [{"prefix": "192.168.50.0/24", "kind": "lan", "export": True}]
    assert shown["dns"]["domain"] == world.config.interlink.domain
    assert shown["sources"] == []
    assert "seal_pubkey" not in json.dumps(shown)


def test_set_updates_only_interlink_and_syncs(world: World) -> None:
    result = world.service().set({"domain": "mesh.example"})

    assert result["interlink"]["domain"] == "mesh.example"
    stored = yaml.safe_load(world.path.read_text(encoding="utf-8"))
    assert stored["interlink"]["domain"] == "mesh.example"
    assert stored["web"]["admin_password"] == "admin-secret"
    assert world.path.stat().st_mode & 0o777 == 0o600
    assert len(world.synced) == 1 and world.synced[0].interlink.domain == "mesh.example"


def test_set_node_id_writes_the_node_section_and_derives_addresses(world: World) -> None:
    result = world.service().set({"node_id": 3, "reserved": ["10.200.0.0/16"]})

    assert result["interlink"]["node_id"] == 3
    stored = yaml.safe_load(world.path.read_text(encoding="utf-8"))
    assert stored["node"]["id"] == 3
    assert stored["interlink"]["reserved"] == ["10.200.0.0/16"]
    synced = world.synced[0]
    assert str(synced.server.ipv4_network) == "10.100.3.0/24"
    assert synced.internal_dns.listen == "10.100.3.1"


def test_set_refuses_bad_input_and_writes_nothing(world: World) -> None:
    before = world.path.read_text(encoding="utf-8")
    for bad in (
        {"bogus": 1},
        {},
        {"cidr": "not-a-cidr"},
        {"node_id": 0},
        {"client_pool": "10.100.{node}.0/24"},
    ):
        with pytest.raises(ManagementError) as err:
            world.service().set(bad)
        assert err.value.status == 422
    assert world.path.read_text(encoding="utf-8") == before
    assert world.synced == []
    assert not list(world.path.parent.glob(".interlink-check-*"))


def test_api_requires_admin_and_round_trips(world: World) -> None:
    client = TestClient(
        create_app(world.config, config_path=world.path), base_url="https://testserver"
    )
    assert client.get("/api/interlink").status_code == 401
    assert client.patch("/api/interlink", json={"domain": "x.example"}).status_code == 401
    auth = ("admin", "admin-secret")

    assert client.get("/api/interlink", auth=auth).json()["nodes"][0]["name"] == "alpha"
    saved = client.patch("/api/interlink", auth=auth, json={"domain": "mesh.example"})
    assert saved.json()["interlink"]["domain"] == "mesh.example"
    assert client.patch("/api/interlink", auth=auth, json={"cidr": "bad"}).status_code == 422


def test_cli_show_and_set(world: World) -> None:
    runner = CliRunner()
    base = ["--config", str(world.path)]

    shown: Any = json.loads(runner.invoke(app, [*base, "interlink", "show", "--json"]).output)
    assert shown["hub"]["interlink_address"] == "10.99.0.1"
    saved = runner.invoke(app, [*base, "interlink", "set", "--domain", "mesh.example", "--json"])
    assert saved.exit_code == 0, saved.output
    assert load_config(world.path).interlink.domain == "mesh.example"


@pytest.mark.parametrize("use_alias", [False, True])
def test_cli_set_keeps_explicit_env_file_and_raw_secret_refs(
    world: World, tmp_path: Path, use_alias: bool
) -> None:
    raw = yaml.safe_load(world.path.read_text())
    raw["web"]["admin_password"] = "${SECRET:ADMIN}"
    world.path.write_text(yaml.safe_dump(raw))
    env_file = tmp_path / "selected.env"
    env_file.write_text("ADMIN=selected-secret\nKORNODE_FABRIC__DOMAIN=selected.example\n")
    world.path.with_name(".env").write_text("ADMIN=wrong-secret\n")
    path = world.path
    if use_alias:
        alias_dir = tmp_path / "alias"
        alias_dir.mkdir()
        path = alias_dir / "config.yaml"
        path.symlink_to(world.path)
        path.with_name(".env").write_text("ADMIN=wrong-alias-secret\n")
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(path),
            "--env-file",
            str(env_file),
            "interlink",
            "set",
            "--reserved",
            "192.0.2.0/24",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["interlink"]["domain"] == "selected.example"
    saved = yaml.safe_load(world.path.read_text())
    assert saved["web"]["admin_password"] == "${SECRET:ADMIN}"
    assert saved["interlink"] == {"reserved": ["192.0.2.0/24"]}
    assert "fabric" not in saved
    config = load_config(path, env_file=env_file)
    assert config.web.admin_password == "selected-secret"
    assert "selected-secret" not in result.output
    assert "selected-secret" not in world.path.read_text()
    if use_alias:
        assert path.is_symlink()
