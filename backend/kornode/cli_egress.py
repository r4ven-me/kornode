"""Thin Typer adapters for the hub egress model: `korctl egress` and `korctl source`."""

from __future__ import annotations

import json as jsonlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from click import edit

from kornode.cli_agents import Json, invoke, read_json
from kornode.config.loader import DEFAULT_CONFIG_PATH
from kornode.config.models import AppConfig
from kornode.services.agent_models import ManagementError
from kornode.services.hub_egress import HubEgressService


def register(
    app: typer.Typer, config: Callable[[], AppConfig], path: Callable[[], Path | None]
) -> None:
    egress = typer.Typer(help="Hub egress policy (egress, sources and sets of config.yaml)")
    source = typer.Typer(help="Hub sources: attached access servers (wg-easy, Amnezia)")

    def service() -> HubEgressService:
        return HubEgressService(config(), path() or DEFAULT_CONFIG_PATH)

    @egress.command("show")
    def egress_show(json: Json = False) -> None:
        invoke(lambda: service().policy(), json)

    @egress.command("check")
    def egress_check(file: Path = typer.Option(..., "--file"), json: Json = False) -> None:
        invoke(lambda: service().check(read_json(file)), json)

    @egress.command("set")
    def egress_set(file: Path = typer.Option(..., "--file"), json: Json = False) -> None:
        invoke(lambda: service().set_policy(read_json(file)), json)

    @egress.command("edit")
    def egress_edit(json: Json = False) -> None:
        def action() -> dict[str, Any]:
            if json:
                raise ManagementError(
                    422, "usage", "use egress set --file for non-interactive editing"
                )
            text = edit(jsonlib.dumps(service().policy()["policy"], indent=2), extension=".json")
            if text is None:
                raise ManagementError(409, "cancelled", "edit cancelled")
            try:
                data = jsonlib.loads(text)
            except ValueError:
                raise ManagementError(422, "invalid", "editor returned invalid JSON") from None
            return service().set_policy(data)

        invoke(action, json)

    @source.command("list")
    def source_list(json: Json = False) -> None:
        invoke(lambda: service().sources(), json)

    @source.command("add")
    @source.command("set")
    def source_set(name: str, file: Path = typer.Option(..., "--file"), json: Json = False) -> None:
        invoke(lambda: service().set_source(name, read_json(file)), json)

    @source.command("del")
    def source_del(name: str, json: Json = False) -> None:
        invoke(lambda: service().set_source(name, None), json)

    app.add_typer(egress, name="egress")
    app.add_typer(source, name="source")
