from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch

router = APIRouter(dependencies=[Depends(require_admin)])


class WebSettingsRequest(BaseModel):
    enabled: bool = False
    listen: str = "127.0.0.1"
    port: int = Field(default=8443, ge=1, le=65535)
    tls: bool = True
    allow_insecure_http: bool = False
    trusted_proxies: list[str] = Field(default_factory=list)
    admin_user: str = "admin"
    terminal_enabled: bool = False
    terminal_idle_timeout: int = Field(default=900, ge=60, le=86400)
    terminal_max_sessions: int = Field(default=2, ge=1, le=10)
    client_sync_enabled: bool = False
    session_lifetime: int = Field(default=43200, ge=300, le=86400)
    session_cookie_secure: bool = True


@router.post("/settings")
def save_web_settings(
    request: Request,
    payload: WebSettingsRequest,
) -> dict[str, object]:
    loaded_config, written = apply_config_patch(request, {"web": payload.model_dump()})
    return {
        "status": "saved",
        "written": written,
        "web": loaded_config.model_dump_safe()["web"],
    }
