"""Fabric overview and settings (spec 07, 08 `fabric.show` / `fabric.settings`).

One read model for the whole fabric (addressing, nodes with prefixes, DNS zone, hub
sources) so the CLI, the API and the panel's Fabric section show the same thing. Writes
are limited to the `fabric:` section of the config file.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from kornode.config.loader import load_config, load_yaml_file
from kornode.config.models import AppConfig
from kornode.net.addressing import derive_addresses
from kornode.services.agent_models import ManagementError
from kornode.services.agents import AgentService
from kornode.services.config import ConfigService
from kornode.services.fabric_dns import FabricDnsService
from kornode.services.files import FileManager
from kornode.services.hub_egress import HubEgressService
from kornode.services.net import NetService

HUB_NODE_ID = 1
SETTINGS_KEYS = ("cidr", "client_pool", "source_pool", "enroll_pool", "domain", "reserved")


class FabricService:
    def __init__(
        self,
        config: AppConfig,
        path: Path,
        *,
        saved: Callable[[AppConfig], None] | None = None,
        sync: Callable[[AppConfig], None] | None = None,
    ) -> None:
        self.config = config
        self.path = path
        self.saved = saved
        self.sync = sync or self._sync

    def show(self) -> dict[str, Any]:
        agents = AgentService(self.config)
        with agents.registry() as r:
            prefixes: dict[int, list[dict[str, Any]]] = {}
            for prefix in r.list_prefixes(None):
                prefixes.setdefault(prefix.node_id, []).append(
                    {"prefix": prefix.prefix, "kind": prefix.kind, "export": prefix.export}
                )
        nodes = [
            {
                "id": item["id"],
                "name": item["name"],
                "roles": item["roles"],
                "state": item["state"],
                "online": item["online"],
                "fabric_address": str(self._service_address(item["id"])),
                "prefixes": prefixes.get(item["id"], []),
            }
            for item in agents.list()["agents"]
        ]
        zone = FabricDnsService(self.config).list()
        return {
            "fabric": self.settings(),
            "hub": {
                "fabric_address": str(self._service_address(HUB_NODE_ID)),
                "server_name": self.config.fabric.server_name,
                "prefixes": prefixes.get(HUB_NODE_ID, []),
            },
            "nodes": nodes,
            "dns": zone,
            "sources": HubEgressService(self.config, self.path).sources()["sources"],
        }

    def settings(self) -> dict[str, Any]:
        fabric = self.config.fabric.model_dump(mode="json")
        return {key: fabric[key] for key in SETTINGS_KEYS}

    def set(self, data: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(data) - set(SETTINGS_KEYS))
        if unknown:
            raise ManagementError(422, "invalid", f"unknown fabric settings: {', '.join(unknown)}")
        if not data:
            raise ManagementError(422, "invalid", "no fabric settings given")
        raw = load_yaml_file(self.path)
        raw["fabric"] = {**(raw.get("fabric") or {}), **data}
        self._validate(raw)
        FileManager().atomic_write_text(self.path, yaml.safe_dump(raw, sort_keys=False), mode=0o600)
        self.config = load_config(self.path)
        if self.saved is not None:
            self.saved(self.config)
        self.sync(self.config)
        return {"fabric": self.settings()}

    def _validate(self, raw: dict[str, Any]) -> None:
        # The loader validates the whole file (derived addresses, DNS) exactly as a
        # restart would, so it reads a sibling copy and never the live file.
        with tempfile.NamedTemporaryFile(
            "w", dir=self.path.parent, prefix=".fabric-check-", suffix=".yaml", delete=False
        ) as handle:
            temp = Path(handle.name)
            handle.write(yaml.safe_dump(raw, sort_keys=False))
        try:
            load_config(temp)
        except ValidationError as exc:
            messages = [str(error["msg"]) for error in exc.errors()]
            fields = [".".join(str(part) for part in error["loc"]) for error in exc.errors()]
            raise ManagementError(422, "invalid", "; ".join(messages), fields) from None
        except ValueError as exc:
            raise ManagementError(422, "invalid", str(exc)) from None
        finally:
            temp.unlink(missing_ok=True)

    def _service_address(self, node_id: int) -> object:
        fabric = self.config.fabric
        return derive_addresses(
            node_id,
            fabric_cidr=fabric.cidr,
            client_pool=fabric.client_pool,
            source_pool=fabric.source_pool,
            domain=fabric.domain,
        ).fabric_address

    @staticmethod
    def _sync(config: AppConfig) -> None:
        ConfigService().write_rendered_files(config)
        NetService(config).wake()
