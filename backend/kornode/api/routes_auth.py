from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from kornode.api.auth import (
    SESSION_COOKIE,
    AdminSession,
    AuthSessionRegistry,
    _auth_fingerprint,
    _reject_cross_origin_basic_request,
    admin_identity,
    auth_registry,
    authenticate_password,
    authenticate_totp,
    require_admin,
)
from kornode.api.routes_config import apply_config_mutation
from kornode.config.loader import deep_merge, validate_config_data
from kornode.config.models import AppConfig
from kornode.services.admin_totp import AdminTotpService
from kornode.services.password_hash import hash_password
from kornode.services.password_policy import validate_new_admin_password

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str = Field(repr=False)
    totp_code: str | None = Field(default=None, repr=False)


@router.post("/login")
def login(request: Request, response: Response, payload: LoginRequest) -> dict[str, object]:
    _reject_cross_origin_basic_request(request)
    registry = auth_registry(request)
    generation = registry.generation
    authenticate_password(request, payload.username, payload.password)
    authenticate_totp(request, payload.totp_code, consume=True)
    config = request.app.state.config
    registry = auth_registry(request)
    previous_token = request.cookies.get(SESSION_COOKIE)
    if previous_token:
        registry.revoke(previous_token)
    token, session = registry.create(payload.username, expected_generation=generation)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=config.web.session_lifetime,
        httponly=True,
        secure=config.web.session_cookie_secure,
        samesite="strict",
        path="/",
    )
    request.state.admin_username = payload.username
    request.state.admin_session = session
    return admin_identity(request)


@router.post("/logout")
def logout(request: Request, response: Response) -> dict[str, bool]:
    _reject_cross_origin_basic_request(request)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        auth_registry(request).revoke(token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"authenticated": False}


@router.get("/me")
def me(
    request: Request,
    _: Annotated[None, Depends(require_admin)],
) -> dict[str, object]:
    return admin_identity(request)


class ReauthenticateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=1024, repr=False)
    totp_code: str | None = Field(default=None, repr=False)


class PasswordChangeRequest(ReauthenticateRequest):
    new_password: str = Field(min_length=1, max_length=1024, repr=False)

    @field_validator("new_password")
    @classmethod
    def _strong_enough(cls, value: str) -> str:
        return validate_new_admin_password(value)


class TotpConfirmRequest(ReauthenticateRequest):
    secret: str = Field(min_length=1, max_length=128, repr=False)
    code: str = Field(repr=False)


@dataclass(frozen=True)
class _ReauthenticationProof:
    registry: AuthSessionRegistry = field(repr=False)
    generation: int
    fingerprint: bytes = field(repr=False)
    session_token: str | None = field(repr=False)


def _reauthenticate(request: Request, payload: ReauthenticateRequest) -> _ReauthenticationProof:
    registry = auth_registry(request)
    config = request.app.state.config
    proof = _ReauthenticationProof(
        registry=registry,
        generation=request.state.admin_auth_generation,
        fingerprint=_auth_fingerprint(config),
        session_token=(
            request.cookies.get(SESSION_COOKIE)
            if isinstance(getattr(request.state, "admin_session", None), AdminSession)
            else None
        ),
    )
    authenticate_password(request, config.web.admin_user, payload.current_password)
    authenticate_totp(request, payload.totp_code)
    return proof


def _apply_auth_patch(
    request: Request,
    proof: _ReauthenticationProof,
    patch: dict[str, Any],
    *,
    write_rendered: bool = False,
) -> tuple[AppConfig, list[str]]:
    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        # apply_config_mutation already holds the config lock. Bind the earlier
        # password/TOTP checks to this latest candidate before any persistence.
        latest = validate_config_data(raw, Path(request.app.state.config_path))
        registry = auth_registry(request)
        if registry is not proof.registry or _auth_fingerprint(latest) != proof.fingerprint:
            raise HTTPException(status_code=401, detail="authentication_changed")
        registry.require_current_authority(proof.generation, proof.session_token)
        return deep_merge(raw, patch)

    return apply_config_mutation(request, mutate, write_rendered=write_rendered)


@router.post("/password")
def change_password(
    request: Request,
    response: Response,
    payload: PasswordChangeRequest,
    _: Annotated[None, Depends(require_admin)],
) -> dict[str, object]:
    proof = _reauthenticate(request, payload)
    _apply_auth_patch(
        request,
        proof,
        {
            "web": {
                "admin_password": None,
                "admin_password_hash": hash_password(payload.new_password),
            }
        },
    )
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "password_changed", "reauthentication_required": True}


@router.get("/totp/status")
def totp_status(
    request: Request,
    _: Annotated[None, Depends(require_admin)],
) -> dict[str, object]:
    config = request.app.state.config
    return {"enabled": config.web.admin_totp_enabled}


@router.post("/totp/setup")
def totp_setup(
    request: Request,
    payload: ReauthenticateRequest,
    _: Annotated[None, Depends(require_admin)],
) -> dict[str, object]:
    _reauthenticate(request, payload)
    config = request.app.state.config
    service = AdminTotpService(config)
    secret = service.generate_secret()
    qr = service.qr_svg(secret)
    return {
        "secret": secret,
        "otpauth_uri": service.otpauth_uri(secret),
        "qr_svg": qr.stdout if qr.ok else None,
    }


@router.post("/totp/confirm")
def totp_confirm(
    request: Request,
    response: Response,
    payload: TotpConfirmRequest,
    _: Annotated[None, Depends(require_admin)],
) -> dict[str, object]:
    proof = _reauthenticate(request, payload)
    config = request.app.state.config
    service = AdminTotpService(config)
    try:
        valid = service.verify_code(payload.secret, payload.code)
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_totp_code")
    _apply_auth_patch(
        request,
        proof,
        {"web": {"admin_totp_enabled": True, "admin_totp_secret": payload.secret}},
    )
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "enabled", "reauthentication_required": True}


@router.post("/totp/disable")
def totp_disable(
    request: Request,
    response: Response,
    payload: ReauthenticateRequest,
    _: Annotated[None, Depends(require_admin)],
) -> dict[str, object]:
    proof = _reauthenticate(request, payload)
    _apply_auth_patch(
        request,
        proof,
        {"web": {"admin_totp_enabled": False, "admin_totp_secret": None}},
    )
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "disabled", "reauthentication_required": True}
