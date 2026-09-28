from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Literal, NoReturn, cast

import yaml
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field, field_validator

from kornode.api.auth import require_admin
from kornode.config.loader import load_config
from kornode.config.models import AppConfig, IntervalUnit, LetsEncryptConfig
from kornode.services.certificates import CertificateService
from kornode.services.command import CommandError, CommandResult
from kornode.services.config import ConfigService
from kornode.services.files import FileManager
from kornode.services.server import ServerService
from kornode.services.server_certificates import ServerCertificatePaths, ServerCertificateService

router = APIRouter(dependencies=[Depends(require_admin)])


class AutoRenewIntervalMixin(BaseModel):
    auto_renew_interval: int = Field(default=7, ge=1)
    auto_renew_interval_unit: IntervalUnit = "days"


class LetsEncryptIssueRequest(AutoRenewIntervalMixin):
    email: str
    domains: list[str] = Field(min_length=1)
    staging: bool = False
    reload: bool = True
    auto_renew_enabled: bool = True
    dry_run: bool = False

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("valid email is required for Let's Encrypt")
        return value


class LetsEncryptRenewRequest(BaseModel):
    reload: bool = True
    dry_run: bool = False


class LetsEncryptSettingsRequest(AutoRenewIntervalMixin):
    enabled: bool = False
    email: str | None = None
    domains: list[str] = Field(default_factory=list)
    renew_reload: bool = True
    auto_renew_enabled: bool = True
    http01_address: str | None = None
    http01_port: int = Field(default=80, ge=1, le=65535)


class CertificateSettingsRequest(BaseModel):
    mode: Literal["auto", "external"]
    ca_name: str


class CaRegenerateRequest(BaseModel):
    dry_run: bool = False


class RevokeCertificateRequest(BaseModel):
    certificate_b64: str
    dry_run: bool = False


def command_result(result: CommandResult, argv: tuple[str, ...] | None = None) -> dict[str, object]:
    return {
        "argv": list(argv or result.argv),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


def command_error_detail(result: CommandResult) -> str:
    return result.stderr.strip() or result.stdout.strip() or f"command failed ({result.returncode})"


def raise_command_http_error(exc: CommandError) -> NoReturn:
    raise HTTPException(status_code=400, detail=command_error_detail(exc.result)) from exc


@router.get("/server-pin")
def server_certificate_pin(request: Request) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    return ServerCertificateService(config).server_pin()


@router.get("")
def status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return ServerCertificateService(config).status()


@router.post("/ca/regenerate")
def regenerate_ca(request: Request, payload: CaRegenerateRequest) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    results = CertificateService(config).regenerate_ca(dry_run=payload.dry_run)
    return {
        "results": [
            command_result(result, ("korctl", "certificates", "ca", "regenerate"))
            for result in results
        ]
    }


@router.post("/ca/upload")
async def upload_ca(
    request: Request,
    ca_cert: UploadFile = File(...),
    ca_key: UploadFile = File(...),
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = CertificateService(config).save_ca_material(
            ca_cert=await ca_cert.read(),
            ca_key=await ca_key.read(),
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return command_result(result, ("korctl", "certificates", "ca", "upload"))


@router.post("/ca/revoke")
def revoke_certificate_b64(
    request: Request,
    payload: RevokeCertificateRequest,
) -> dict[str, object]:
    try:
        certificate = base64.b64decode(payload.certificate_b64, validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="certificate_b64 must be valid base64") from exc
    config: AppConfig = request.app.state.config
    result = CertificateService(config).revoke_certificate_pem(
        certificate,
        dry_run=payload.dry_run,
    )
    return command_result(result, ("korctl", "certificates", "ca", "revoke-pem"))


@router.post("/ca/revoke-file")
async def revoke_certificate_file(
    request: Request,
    certificate: UploadFile = File(...),
    dry_run: bool = Form(False),
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = CertificateService(config).revoke_certificate_pem(
            await certificate.read(),
            dry_run=dry_run,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return command_result(result, ("korctl", "certificates", "ca", "revoke-file"))


@router.get("/ca/revoked")
def list_revoked_certificates(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return {"certificates": CertificateService(config).list_revoked_certificates()}


@router.get("/ca/info")
def authority_certificate_info(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    path = config.cert_path("ca.crt")
    return {
        "path": str(path),
        "certificate": CertificateService(config).certificate_info_from_path(path),
    }


@router.get("/server/info")
def server_certificate_info(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    path = ServerCertificateService(config).active_paths().server_cert
    return {
        "path": str(path),
        "certificate": CertificateService(config).certificate_info_from_path(path),
    }


@router.get("/letsencrypt/info")
def letsencrypt_certificate_info(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    le = config.certificates.letsencrypt
    service = ServerCertificateService(config)
    path = (
        service.letsencrypt_paths(le.domains[0]).server_cert
        if le.domains
        else service.active_paths().server_cert
    )
    return {
        "path": str(path),
        "certificate": CertificateService(config).certificate_info_from_path(path),
    }


@router.post("/external")
async def upload_external(
    request: Request,
    server_cert: UploadFile = File(...),
    server_key: UploadFile = File(...),
    ca_cert: UploadFile = File(...),
    reload: bool = Form(True),
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    service = ServerCertificateService(config)
    try:
        paths = service.save_external_material(
            server_cert=await server_cert.read(),
            server_key=await server_key.read(),
            ca_cert=await ca_cert.read(),
        )
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="certificate files must be UTF-8 PEM files",
        ) from exc
    loaded_config = _activate_external_config(request, paths, letsencrypt=False)
    reload_result = _write_and_reload(loaded_config, reload=reload)
    return {
        "status": "external certificates installed",
        "config": loaded_config.model_dump_safe(),
        "reload": command_result(reload_result, ("korctl", "server", "reload"))
        if reload_result
        else None,
    }


@router.post("/letsencrypt/issue")
def issue_letsencrypt(
    request: Request,
    payload: LetsEncryptIssueRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    domains = [domain.strip().rstrip(".") for domain in payload.domains if domain.strip()]
    validation_config = AppConfig.model_validate(
        {
            "certificates": {
                "mode": "auto",
                "letsencrypt": {"email": str(payload.email), "domains": domains},
            }
        }
    )
    domains = validation_config.certificates.letsencrypt.domains
    service = ServerCertificateService(config)
    try:
        result = service.issue_letsencrypt(
            email=str(payload.email),
            domains=domains,
            staging=payload.staging,
            dry_run=payload.dry_run,
        )
    except CommandError as exc:
        raise_command_http_error(exc)
    loaded_config: AppConfig | None = None
    reload_result: CommandResult | None = None
    if not payload.dry_run:
        paths = service.letsencrypt_paths(domains[0])
        if not config.cert_path("ca.key").exists() or not config.cert_path("ca.crt").exists():
            CertificateService(config).init_ca()
        loaded_config = _activate_letsencrypt_config(
            request,
            paths,
            config=config,
            email=str(payload.email),
            domains=domains,
            renew_reload=payload.reload,
            auto_renew_enabled=payload.auto_renew_enabled,
            auto_renew_interval=payload.auto_renew_interval,
            auto_renew_interval_unit=payload.auto_renew_interval_unit,
            http01_address=config.certificates.letsencrypt.http01_address,
            http01_port=config.certificates.letsencrypt.http01_port,
        )
        reload_result = _write_and_reload(loaded_config, reload=payload.reload)
    return {
        "result": command_result(
            result,
            ("korctl", "certificates", "letsencrypt-issue", "--email", "***"),
        ),
        "config": loaded_config.model_dump_safe() if loaded_config else None,
        "reload": command_result(reload_result, ("korctl", "server", "reload"))
        if reload_result
        else None,
    }


@router.post("/letsencrypt/settings")
def save_letsencrypt_settings(
    request: Request,
    payload: LetsEncryptSettingsRequest,
) -> dict[str, object]:
    domains = [domain.strip().rstrip(".") for domain in payload.domains if domain.strip()]
    # Validated directly against LetsEncryptConfig (not AppConfig) so that a blank
    # http01_address stays None here rather than being resolved against a throwaway
    # AppConfig's default server.listen ("0.0.0.0"); the real per-request resolution
    # against the actual persisted server.listen happens in AppConfig's own root
    # validator when the saved YAML is next loaded.
    le = LetsEncryptConfig.model_validate(
        {
            "email": payload.email,
            "domains": domains,
            "enabled": payload.enabled,
            "renew_reload": payload.renew_reload,
            "auto_renew_enabled": payload.auto_renew_enabled,
            "auto_renew_interval": payload.auto_renew_interval,
            "auto_renew_interval_unit": payload.auto_renew_interval_unit,
            "http01_address": payload.http01_address,
            "http01_port": payload.http01_port,
        }
    )
    loaded_config = _update_certificate_config(
        request,
        {
            "letsencrypt": {
                "enabled": le.enabled,
                "email": le.email,
                "domains": le.domains,
                "renew_reload": le.renew_reload,
                "auto_renew_enabled": le.auto_renew_enabled,
                "auto_renew_interval": le.auto_renew_interval,
                "auto_renew_interval_unit": le.auto_renew_interval_unit,
                "http01_address": le.http01_address,
                "http01_port": le.http01_port,
            },
        },
    )
    ConfigService().write_rendered_files(loaded_config)
    request.app.state.config = loaded_config
    return {"status": "letsencrypt settings saved", "config": loaded_config.model_dump_safe()}


@router.post("/settings")
def save_certificate_settings(
    request: Request,
    payload: CertificateSettingsRequest,
) -> dict[str, object]:
    loaded_config = _update_certificate_config(
        request,
        {"mode": payload.mode, "ca_name": payload.ca_name},
    )
    ConfigService().write_rendered_files(loaded_config)
    request.app.state.config = loaded_config
    return {"status": "certificate settings saved", "config": loaded_config.model_dump_safe()}


@router.post("/letsencrypt/renew")
def renew_letsencrypt(
    request: Request,
    payload: LetsEncryptRenewRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = ServerCertificateService(config).renew_letsencrypt(dry_run=payload.dry_run)
    except CommandError as exc:
        raise_command_http_error(exc)
    reload_result: CommandResult | None = None
    if not payload.dry_run and config.certificates.letsencrypt.renew_reload:
        reload_result = _write_and_reload(config, reload=payload.reload)
    return {
        "result": command_result(result, ("korctl", "certificates", "letsencrypt-renew")),
        "reload": command_result(reload_result, ("korctl", "server", "reload"))
        if reload_result
        else None,
    }


def _activate_external_config(
    request: Request,
    paths: ServerCertificatePaths,
    *,
    letsencrypt: bool,
) -> AppConfig:
    patch: dict[str, Any] = {
        "mode": "external",
        "server_cert": str(paths.server_cert),
        "server_key": str(paths.server_key),
        "ca_cert": str(paths.ca_cert),
    }
    if not letsencrypt:
        patch["letsencrypt"] = {"enabled": False}
    return _update_certificate_config(request, patch)


def _activate_letsencrypt_config(
    request: Request,
    paths: ServerCertificatePaths,
    *,
    config: AppConfig,
    email: str,
    domains: list[str],
    renew_reload: bool,
    auto_renew_enabled: bool,
    auto_renew_interval: int,
    auto_renew_interval_unit: IntervalUnit,
    http01_address: str | None,
    http01_port: int,
) -> AppConfig:
    return _update_certificate_config(
        request,
        {
            "mode": "external",
            "server_cert": str(paths.server_cert),
            "server_key": str(paths.server_key),
            # ocserv's ca-cert verifies client certificates, which are always signed by
            # the local CA (see CertificateService.create_user_certificate), not by
            # Let's Encrypt.
            "ca_cert": str(config.cert_path("ca.crt")),
            "letsencrypt": {
                "enabled": True,
                "email": email,
                "domains": domains,
                "renew_reload": renew_reload,
                "auto_renew_enabled": auto_renew_enabled,
                "auto_renew_interval": auto_renew_interval,
                "auto_renew_interval_unit": auto_renew_interval_unit,
                "http01_address": http01_address,
                "http01_port": http01_port,
            },
        },
    )


def _update_certificate_config(request: Request, patch: dict[str, Any]) -> AppConfig:
    path = Path(request.app.state.config_path)
    data = _load_yaml_mapping(path)
    certificates = data.setdefault("certificates", {})
    if not isinstance(certificates, dict):
        raise ValueError("certificates config must be a mapping")
    certificates.update(patch)
    FileManager().atomic_write_text(path, _dump_yaml(data), mode=0o600)
    loaded_config = load_config(path)
    request.app.state.config = loaded_config
    return loaded_config


def _write_and_reload(config: AppConfig, *, reload: bool) -> CommandResult | None:
    ConfigService().write_rendered_files(config)
    if not reload:
        return None
    return ServerService(config).reload(dry_run=False)


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"configuration root must be a mapping: {path}")
    return cast(dict[str, Any], loaded)


def _dump_yaml(data: Any) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False)
