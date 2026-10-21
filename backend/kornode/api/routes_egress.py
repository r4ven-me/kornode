"""Hub egress policy and sources; all logic lives in HubEgressService."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from kornode.api.auth import require_admin
from kornode.api.routes_agents import payload
from kornode.config.models import AppConfig
from kornode.services.hub_egress import HubEgressService

router = APIRouter(dependencies=[Depends(require_admin)])
sources_router = APIRouter(dependencies=[Depends(require_admin)])


def service(request: Request) -> HubEgressService:
    def saved(config: AppConfig) -> None:
        request.app.state.config = config

    return HubEgressService(request.app.state.config, request.app.state.config_path, saved=saved)


@router.get("")
def egress_show(request: Request) -> dict[str, Any]:
    return service(request).policy()


@router.put("")
async def egress_set(request: Request) -> dict[str, Any]:
    return await run_in_threadpool(service(request).set_policy, await payload(request))


@router.post("/check")
async def egress_check(request: Request) -> dict[str, Any]:
    return await run_in_threadpool(service(request).check, await payload(request))


@sources_router.get("")
def source_list(request: Request) -> dict[str, Any]:
    return service(request).sources()


@sources_router.put("/{name}")
async def source_set(name: str, request: Request) -> dict[str, Any]:
    return await run_in_threadpool(service(request).set_source, name, await payload(request))


@sources_router.delete("/{name}")
def source_delete(name: str, request: Request) -> dict[str, Any]:
    return service(request).set_source(name, None)
