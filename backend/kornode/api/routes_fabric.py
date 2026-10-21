"""Fabric overview and settings (spec 07, 08); all logic lives in FabricService."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from kornode.api.auth import require_admin
from kornode.api.routes_agents import payload
from kornode.config.models import AppConfig
from kornode.services.fabric import FabricService

router = APIRouter(dependencies=[Depends(require_admin)])


def service(request: Request) -> FabricService:
    def saved(config: AppConfig) -> None:
        request.app.state.config = config

    return FabricService(request.app.state.config, request.app.state.config_path, saved=saved)


@router.get("")
def fabric_show(request: Request) -> dict[str, Any]:
    return service(request).show()


@router.patch("")
async def fabric_set(request: Request) -> dict[str, Any]:
    return await run_in_threadpool(service(request).set, await payload(request))
