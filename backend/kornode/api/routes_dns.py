"""Fabric DNS zone records (spec 07 "DNS", D-66); logic lives in FabricDnsService."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from kornode.api.auth import require_admin
from kornode.api.routes_agents import payload
from kornode.services.agents import parse
from kornode.services.fabric_dns import DnsRecordInput, FabricDnsService

router = APIRouter(dependencies=[Depends(require_admin)])


def service(request: Request) -> FabricDnsService:
    override: FabricDnsService | None = getattr(request.app.state, "fabric_dns", None)
    return override or FabricDnsService(request.app.state.config)


@router.get("/records")
def dns_records(request: Request) -> dict[str, Any]:
    return service(request).list()


@router.post("/records")
async def dns_record_add(request: Request) -> dict[str, Any]:
    data = parse(DnsRecordInput, await payload(request))
    return await run_in_threadpool(service(request).add, data)


@router.delete("/records")
async def dns_record_delete(request: Request) -> dict[str, Any]:
    data = parse(DnsRecordInput, await payload(request))
    return await run_in_threadpool(service(request).delete, data)
