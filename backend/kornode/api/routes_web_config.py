from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch
from kornode.config.models import ControlConfig

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


class ControlSettingsRequest(ControlConfig):
    """Structured settings use the authoritative types, including a nullable key path."""

    @field_validator("signing_key")
    @classmethod
    def path_only(cls, value: Path | None) -> Path | None:
        if value is not None:
            text = str(value)
            # Reject accidental PEM pastes without opening the target path.
            if any(part in text for part in ("\n", "\r", "\0", "-----BEGIN ", "-----END ")):
                raise ValueError("signing_key must be a filesystem path, not key material")
        return value


@router.post("/control-settings")
def save_control_settings(request: Request, payload: ControlSettingsRequest) -> dict[str, object]:
    # Store only settings. Never initialize, read, rotate or render key material here.
    loaded_config, written = apply_config_patch(
        request,
        {"control": payload.model_dump(mode="json", exclude_unset=True)},
        write_rendered=False,
    )
    settings = loaded_config.control.model_dump(mode="json")
    if "signing_key" in payload.model_fields_set:
        # AppConfig resolves null to the default runtime path; keep the editor's
        # explicit default-selection state rather than replacing it with that path.
        settings["signing_key"] = payload.model_dump(mode="json")["signing_key"]
    return {
        "status": "saved",
        "written": written,
        "control": settings,
        "restart_required": True,
    }
