from __future__ import annotations

import smtplib
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch
from kornode.config.models import AppConfig, OtpAuthConfig
from kornode.renderers import OcservConfigRenderer
from kornode.services.command import CommandResult
from kornode.services.otp_delivery import OtpDeliveryService
from kornode.services.server import ServerService

router = APIRouter(dependencies=[Depends(require_admin)])


class DryRunRequest(BaseModel):
    dry_run: bool = False


class ProcessActionRequest(BaseModel):
    action: str
    process: str
    dry_run: bool = False


class CamouflageSettings(BaseModel):
    enabled: bool = False
    secret: str | None = None
    realm: str = "Hidden service"


class ServerSettingsRequest(BaseModel):
    enabled: bool = True
    listen: str = "0.0.0.0"
    port: int = Field(default=443, ge=1, le=65535)
    udp_enabled: bool = True
    device: str = "vpns"
    cn: str = "vpn.example.com"
    realm: str = "Korvus VPN Server"
    ipv4_network: str = "10.10.10.0/24"
    dns: list[str] = Field(default_factory=list)
    search_domains: list[str] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)
    no_routes: list[str] = Field(default_factory=list)
    max_clients: int = Field(default=128, ge=1)
    max_same_clients: int = Field(default=2, ge=1)
    keepalive: int = Field(default=32400, ge=0)
    dpd: int = Field(default=90, ge=0)
    mobile_dpd: int = Field(default=1800, ge=0)
    compression: bool = False
    cisco_client_compat: bool = True
    isolate_workers: bool = True
    try_mtu_discovery: bool = True
    predictable_ips: bool = True
    deny_roaming: bool = False
    ping_leases: bool = False
    dtls_legacy: bool = True
    client_bypass_protocol: bool = False
    rate_limit_ms: int = Field(default=200, ge=0)
    server_stats_reset_time: int = Field(default=604800, ge=0)
    switch_to_tcp_timeout: int = Field(default=25, ge=0)
    auth_timeout: int = Field(default=240, ge=0)
    cookie_timeout: int = Field(default=600, ge=0)
    ban_time: int = Field(default=300, ge=0)
    max_ban_score: int = Field(default=80, ge=0)
    ban_reset_time: int = Field(default=1200, ge=0)
    rekey_time: int = Field(default=172800, ge=0)
    rekey_method: Literal["ssl", "new-tunnel"] = "ssl"
    cert_user_oid: str = "2.5.4.3"
    tls_priorities: str | None = None
    camouflage: CamouflageSettings = Field(default_factory=CamouflageSettings)
    connect_script: str | None = None
    disconnect_script: str | None = None
    debug_level: int = Field(default=1, ge=0, le=9)
    reload: bool = True


class AuthMethodsSettingsRequest(BaseModel):
    password_enabled: bool = True
    certificate_enabled: bool = False
    otp_enabled: bool = False
    otp_ocserv_oath_auth: bool = False
    otp_issuer: str = "Korvus Node"
    otp_send_by_email: bool = False
    otp_send_by_telegram: bool = False
    otp_smtp_host: str | None = None
    otp_smtp_port: int | None = Field(default=None, ge=1, le=65535)
    otp_smtp_username: str | None = None
    otp_smtp_password: str | None = None
    otp_smtp_from: str | None = None
    otp_smtp_starttls: bool | None = None
    otp_smtp_test_recipient: str | None = None
    otp_telegram_bot_token: str | None = None
    otp_telegram_chat_id: str | None = None


def otp_settings_from_payload(
    payload: AuthMethodsSettingsRequest,
    current: AppConfig,
) -> dict[str, object]:
    return {
        "enabled": payload.otp_enabled,
        "ocserv_oath_auth": payload.otp_ocserv_oath_auth,
        "issuer": payload.otp_issuer,
        "send_by_email": payload.otp_send_by_email,
        "send_by_telegram": payload.otp_send_by_telegram,
        "smtp_host": (
            payload.otp_smtp_host
            if "otp_smtp_host" in payload.model_fields_set
            else current.auth.otp.smtp_host
        ),
        "smtp_port": payload.otp_smtp_port or current.auth.otp.smtp_port,
        "smtp_username": (
            payload.otp_smtp_username
            if "otp_smtp_username" in payload.model_fields_set
            else current.auth.otp.smtp_username
        ),
        "smtp_password": payload.otp_smtp_password or current.auth.otp.smtp_password,
        "smtp_from": (
            payload.otp_smtp_from
            if "otp_smtp_from" in payload.model_fields_set
            else current.auth.otp.smtp_from
        ),
        "smtp_starttls": (
            payload.otp_smtp_starttls
            if payload.otp_smtp_starttls is not None
            else current.auth.otp.smtp_starttls
        ),
        "smtp_test_recipient": (
            payload.otp_smtp_test_recipient
            if "otp_smtp_test_recipient" in payload.model_fields_set
            else current.auth.otp.smtp_test_recipient
        ),
        "telegram_bot_token": payload.otp_telegram_bot_token
        or current.auth.otp.telegram_bot_token,
        "telegram_chat_id": (
            payload.otp_telegram_chat_id
            if "otp_telegram_chat_id" in payload.model_fields_set
            else current.auth.otp.telegram_chat_id
        ),
    }


def command_result(result: CommandResult, argv: tuple[str, ...] | None = None) -> dict[str, object]:
    return {
        "argv": list(argv or result.argv),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


def running_ocserv_conf(request: Request) -> str:
    """ocserv.conf for the config in effect before a settings save."""
    return OcservConfigRenderer().render(request.app.state.config)


def ocserv_apply_result(result: CommandResult | None) -> dict[str, object] | None:
    if result is None:
        return None
    action = "restart" if "restartProcess" in result.argv else "reload"
    return command_result(result, ("korctl", "server", action))


@router.post("/settings")
def save_server_settings(
    request: Request,
    payload: ServerSettingsRequest,
) -> dict[str, object]:
    patch = payload.model_dump(exclude={"reload"})
    previous = running_ocserv_conf(request)
    loaded_config, written = apply_config_patch(request, {"server": patch})
    # Rewriting ocserv.conf alone does not make the *running* ocserv process
    # pick up the change (e.g. max-same-clients, debug_level) -- without a
    # reload, the server keeps enforcing whatever was last loaded, silently
    # diverging from what the panel shows as saved. A port/listen/device
    # change needs a full restart, which apply_config_change picks.
    reload_result = (
        ServerService(loaded_config).apply_config_change(previous) if payload.reload else None
    )
    return {
        "status": "saved",
        "written": written,
        "server": loaded_config.model_dump_safe()["server"],
        "reload": ocserv_apply_result(reload_result),
    }


@router.post("/auth-settings")
def save_auth_methods_settings(
    request: Request,
    payload: AuthMethodsSettingsRequest,
) -> dict[str, object]:
    patch = {
        "password": {"enabled": payload.password_enabled},
        "certificate": {"enabled": payload.certificate_enabled},
        "otp": otp_settings_from_payload(payload, request.app.state.config),
    }
    previous = running_ocserv_conf(request)
    loaded_config, written = apply_config_patch(request, {"auth": patch})
    # ocserv reads its `auth =` lines only at startup: switching a method on
    # or off takes a restart, or the running server keeps the old methods.
    reload_result = ServerService(loaded_config).apply_config_change(previous)
    return {
        "status": "saved",
        "written": written,
        "auth": loaded_config.model_dump_safe()["auth"],
        "reload": ocserv_apply_result(reload_result),
    }


@router.post("/auth-settings/test-email")
def test_otp_email(request: Request, payload: AuthMethodsSettingsRequest) -> dict[str, str]:
    settings = OtpAuthConfig.model_validate(
        otp_settings_from_payload(payload, request.app.state.config)
    )
    try:
        OtpDeliveryService(settings).send_test_email()
    except (OSError, ValueError, smtplib.SMTPException) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "sent"}


@router.post("/auth-settings/test-telegram")
def test_otp_telegram(request: Request, payload: AuthMethodsSettingsRequest) -> dict[str, str]:
    settings = OtpAuthConfig.model_validate(
        otp_settings_from_payload(payload, request.app.state.config)
    )
    try:
        OtpDeliveryService(settings).send_test_telegram()
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "sent"}


@router.get("/status")
def status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return command_result(ServerService(config).status(), ("korctl", "server", "status"))


@router.get("/processes")
def processes(request: Request) -> list[dict[str, str]]:
    config: AppConfig = request.app.state.config
    return [process.__dict__ for process in ServerService(config).processes()]


@router.post("/reload")
def reload_server(request: Request, payload: DryRunRequest | None = None) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return command_result(
        ServerService(config).reload(dry_run=payload.dry_run if payload else False),
        ("korctl", "server", "reload"),
    )


@router.post("/restart")
def restart_server(request: Request, payload: DryRunRequest | None = None) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return command_result(
        ServerService(config).restart(dry_run=payload.dry_run if payload else False),
        ("korctl", "server", "restart"),
    )


@router.post("/start")
def start_server(request: Request, payload: DryRunRequest | None = None) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return command_result(
        ServerService(config).start(dry_run=payload.dry_run if payload else False),
        ("korctl", "server", "start"),
    )


@router.post("/stop")
def stop_server(request: Request, payload: DryRunRequest | None = None) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return command_result(
        ServerService(config).stop(dry_run=payload.dry_run if payload else False),
        ("korctl", "server", "stop"),
    )


@router.post("/process")
def process_action(request: Request, payload: ProcessActionRequest) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = ServerService(config).process_action(
            payload.action,
            payload.process,
            dry_run=payload.dry_run,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return command_result(
        result,
        ("korctl", "server", "process", payload.action, payload.process),
    )
