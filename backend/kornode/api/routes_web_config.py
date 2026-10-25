from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from kornode.api.auth import require_admin
from kornode.api.routes_auth import ReauthenticateRequest, _apply_auth_patch, _reauthenticate
from kornode.api.routes_config import apply_config_patch
from kornode.config.models import ControlConfig, WebConfig

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
    # Reauthentication for the sensitive changes below; never stored.
    current_password: str | None = Field(default=None, max_length=1024, repr=False)
    totp_code: str | None = Field(default=None, repr=False)


def sensitive_web_changes(current: WebConfig, payload: WebSettingsRequest) -> list[str]:
    """Settings that widen the attack surface of a stolen session and so need reauthentication."""
    changed: list[str] = []
    if payload.terminal_enabled and not current.terminal_enabled:
        changed.append("terminal_enabled")
    if payload.admin_user != current.admin_user:
        changed.append("admin_user")
    if list(payload.trusted_proxies) != list(current.trusted_proxies):
        changed.append("trusted_proxies")
    if current.session_cookie_secure and not payload.session_cookie_secure:
        changed.append("session_cookie_secure")
    return changed


@router.post("/settings")
def save_web_settings(
    request: Request,
    payload: WebSettingsRequest,
) -> dict[str, object]:
    patch = {"web": payload.model_dump(exclude={"current_password", "totp_code"})}
    sensitive = sensitive_web_changes(request.app.state.config.web, payload)
    if sensitive:
        if not payload.current_password:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "reauthentication_required",
                    "fields": sensitive,
                },
            )
        proof = _reauthenticate(
            request,
            ReauthenticateRequest(
                current_password=payload.current_password, totp_code=payload.totp_code
            ),
        )
        loaded_config, written = _apply_auth_patch(request, proof, patch, write_rendered=True)
    else:
        loaded_config, written = apply_config_patch(request, patch)
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
