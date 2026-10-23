"""Interlink overview and settings (spec 07, 08 `interlink.show` / `interlink.settings`).

One read model for the whole interlink (addressing, nodes with prefixes, DNS zone, hub
sources) so the CLI, the API and the panel's Interlink section show the same thing. Writes
are limited to the `interlink:` section of the config file.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from kornode.config.loader import deep_merge
from kornode.config.models import AppConfig
from kornode.net.addressing import derive_addresses
from kornode.services.agent_models import ManagementError
from kornode.services.agents import AgentService
from kornode.services.config_store import ConfigApplyError, ConfigPreflightError, mutate_config
from kornode.services.hub_egress import HubEgressService
from kornode.services.interlink_dns import InterlinkDnsService
from kornode.services.net import NetService
from kornode.services.secrets import sanitized_validation_errors

HUB_NODE_ID = 1
SETTINGS_KEYS = ("cidr", "client_pool", "source_pool", "enroll_pool", "domain", "reserved")
# `node_id` lives in the `node:` section (the hub's own id), not under `interlink:`.
ACCEPTED_KEYS = (*SETTINGS_KEYS, "node_id")


class InterlinkService:
    def __init__(
        self,
        config: AppConfig,
        path: Path,
        *,
        env_file: Path | None = None,
        saved: Callable[[AppConfig], None] | None = None,
        sync: Callable[[AppConfig], None] | None = None,
    ) -> None:
        self.config = config
        self.path = path
        self.env_file = env_file
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
                "interlink_address": str(self._service_address(item["id"])),
                "prefixes": prefixes.get(item["id"], []),
            }
            for item in agents.list()["agents"]
        ]
        zone = InterlinkDnsService(self.config).list()
        return {
            "interlink": self.settings(),
            "hub": {
                "interlink_address": str(self._service_address(HUB_NODE_ID)),
                "server_name": self.config.interlink.server_name,
                "prefixes": prefixes.get(HUB_NODE_ID, []),
            },
            "nodes": nodes,
            "dns": zone,
            "sources": HubEgressService(self.config, self.path).sources()["sources"],
        }

    def settings(self) -> dict[str, Any]:
        interlink = self.config.interlink.model_dump(mode="json")
        return {"node_id": self.config.node.id, **{key: interlink[key] for key in SETTINGS_KEYS}}

    def set(self, data: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(data) - set(ACCEPTED_KEYS))
        if unknown:
            raise ManagementError(
                422, "invalid", f"unknown interlink settings: {', '.join(unknown)}"
            )
        if not data:
            raise ManagementError(422, "invalid", "no interlink settings given")
        patch: dict[str, Any] = {
            "interlink": {key: value for key, value in data.items() if key != "node_id"},
        }
        if "node_id" in data:
            patch["node"] = {"id": data["node_id"]}

        def installed(config: AppConfig) -> None:
            self.config = config
            if self.saved is not None:
                self.saved(config)

        try:
            mutate_config(
                self.path,
                lambda raw: deep_merge(raw, patch),
                env_file=self.env_file,
                on_commit=installed,
                after_apply=self.sync,
            )
        except ValidationError as exc:
            raise ManagementError(
                422,
                "invalid",
                "Invalid interlink configuration",
                sanitized_validation_errors(exc.errors()),
            ) from None
        except ValueError:
            raise ManagementError(422, "invalid", "Invalid interlink configuration") from None
        except ConfigPreflightError:
            raise ManagementError(
                500,
                "not_saved",
                "Render preflight failed; configuration was not saved",
                {"saved": False, "applied": False},
            ) from None
        except ConfigApplyError:
            raise ManagementError(
                500,
                "saved_but_not_applied",
                "Configuration saved; runtime application failed. Retry rendering before reload.",
                {"saved": True, "applied": False},
            ) from None
        return {"interlink": self.settings()}

    def _service_address(self, node_id: int) -> object:
        interlink = self.config.interlink
        return derive_addresses(
            node_id,
            interlink_cidr=interlink.cidr,
            client_pool=interlink.client_pool,
            source_pool=interlink.source_pool,
            domain=interlink.domain,
        ).interlink_address

    @staticmethod
    def _sync(config: AppConfig) -> None:
        NetService(config).wake()
