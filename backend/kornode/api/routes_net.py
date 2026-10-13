from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from kornode.api.auth import require_admin
from kornode.config.models import AppConfig
from kornode.net.errors import NetError
from kornode.services.net import NetApplyError, NetService

router = APIRouter(dependencies=[Depends(require_admin)])


class ApplyRequest(BaseModel):
    dry_run: bool = False


class ExplainRequest(BaseModel):
    src: str
    dst: str


def _service(request: Request) -> NetService:
    config: AppConfig = request.app.state.config
    return NetService(config)


@router.get("/plan")
def net_plan(request: Request) -> dict[str, Any]:
    try:
        return _service(request).plan()
    except NetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/apply")
def net_apply(payload: ApplyRequest, request: Request) -> dict[str, Any]:
    try:
        return _service(request).apply(dry_run=payload.dry_run)
    except NetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except NetApplyError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/explain")
def net_explain(payload: ExplainRequest, request: Request) -> dict[str, Any]:
    try:
        return _service(request).explain(payload.src, payload.dst)
    except (NetError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/status")
def net_status(request: Request) -> dict[str, Any]:
    return _service(request).status()
