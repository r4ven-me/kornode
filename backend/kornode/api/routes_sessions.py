from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from kornode.api.auth import require_admin
from kornode.config.models import AppConfig
from kornode.services.sessions import SessionService

router = APIRouter(dependencies=[Depends(require_admin)])


class DryRunRequest(BaseModel):
    dry_run: bool = False


@router.get("")
def list_sessions(request: Request) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    return [record.__dict__ for record in SessionService(config).list_sessions()]


@router.post("/{username}/kick")
def kick_session(
    request: Request,
    username: str,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    result = SessionService(config).kick(username, dry_run=payload.dry_run if payload else False)
    return {
        "argv": ["korctl", "sessions", "kick", username],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }
