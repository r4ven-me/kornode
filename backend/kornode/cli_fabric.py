"""Thin Typer adapter for the fabric overview: `korctl fabric`."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from kornode.cli_agents import Json, invoke
from kornode.config.loader import DEFAULT_CONFIG_PATH
from kornode.config.models import AppConfig
from kornode.services.fabric import FabricService


def register(
    app: typer.Typer, config: Callable[[], AppConfig], path: Callable[[], Path | None]
) -> None:
    fabric = typer.Typer(help="Fabric overview: addressing, nodes, prefixes, DNS and sources")

    def service() -> FabricService:
        return FabricService(config(), path() or DEFAULT_CONFIG_PATH)

    @fabric.command("show")
    def fabric_show(json: Json = False) -> None:
        invoke(lambda: service().show(), json)

    @fabric.command("set")
    def fabric_set(
        cidr: str | None = typer.Option(None, "--cidr"),
        client_pool: str | None = typer.Option(None, "--client-pool"),
        source_pool: str | None = typer.Option(None, "--source-pool"),
        enroll_pool: str | None = typer.Option(None, "--enroll-pool"),
        domain: str | None = typer.Option(None, "--domain"),
        reserved: list[str] | None = typer.Option(None, "--reserved"),
        json: Json = False,
    ) -> None:
        values: dict[str, Any] = {
            "cidr": cidr,
            "client_pool": client_pool,
            "source_pool": source_pool,
            "enroll_pool": enroll_pool,
            "domain": domain,
            "reserved": reserved,
        }
        data = {key: value for key, value in values.items() if value is not None}
        invoke(lambda: service().set(data), json)

    app.add_typer(fabric, name="fabric")
