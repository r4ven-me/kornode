from __future__ import annotations

from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, ValidationError

from kornode.api.auth import require_admin
from kornode.config.models import AppConfig
from kornode.services.certificates import CertificateService
from kornode.services.command import CommandError, CommandResult
from kornode.services.otp import OtpService
from kornode.services.users import UserConfig, UserService

router = APIRouter(dependencies=[Depends(require_admin)])


class UserCreateRequest(BaseModel):
    username: str
    password: str = Field(min_length=1)
    dry_run: bool = False


class PasswordChangeRequest(BaseModel):
    password: str = Field(min_length=1)
    dry_run: bool = False


class P12CreateRequest(BaseModel):
    passphrase: str | None = None
    apple_compatible: bool = False
    dry_run: bool = False


class DryRunRequest(BaseModel):
    dry_run: bool = False


class UserConfigRequest(UserConfig):
    pass


class UserGroupsRequest(BaseModel):
    groups: list[str] = Field(default_factory=list)


def command_result(result: CommandResult, argv: tuple[str, ...] | None = None) -> dict[str, object]:
    return {
        "argv": list(argv or result.argv),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


def command_error_detail(result: CommandResult) -> str:
    output = result.stderr.strip() or result.stdout.strip()
    if output:
        return output
    return f"command failed with exit code {result.returncode}"


def user_command_result(result: CommandResult, argv: tuple[str, ...]) -> dict[str, object]:
    return command_result(result, argv)


def raise_command_http_error(exc: CommandError) -> NoReturn:
    raise HTTPException(status_code=400, detail=command_error_detail(exc.result)) from exc


@router.get("")
def list_users(request: Request) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    return [record.__dict__ for record in UserService(config).list_users()]


@router.post("")
def create_user(
    request: Request,
    payload: UserCreateRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = UserService(config).create_user(
            payload.username,
            payload.password,
            dry_run=payload.dry_run,
        )
    except CommandError as exc:
        raise_command_http_error(exc)
    return user_command_result(
        result,
        ("korctl", "user", "create", payload.username, "--password", "***"),
    )


@router.delete("/{username}")
def delete_user(
    request: Request,
    username: str,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    deleted = UserService(config).delete_user(username)
    return command_result(
        CommandResult(
            ("korctl", "user", "delete", username),
            0,
            f"deleted: {str(deleted).lower()}\n",
            "",
            False,
        )
    )


@router.post("/{username}/password")
def change_password(
    request: Request,
    username: str,
    payload: PasswordChangeRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = UserService(config).change_password(
            username,
            payload.password,
            dry_run=payload.dry_run,
        )
    except CommandError as exc:
        raise_command_http_error(exc)
    return user_command_result(result, ("korctl", "user", "passwd", username, "--password", "***"))


@router.post("/{username}/enable")
def enable_user(
    request: Request,
    username: str,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = UserService(config).enable_user(
            username,
            dry_run=payload.dry_run if payload else False,
        )
    except CommandError as exc:
        raise_command_http_error(exc)
    return user_command_result(result, ("korctl", "user", "enable", username))


@router.post("/{username}/disable")
def disable_user(
    request: Request,
    username: str,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = UserService(config).disable_user(
            username,
            dry_run=payload.dry_run if payload else False,
        )
    except CommandError as exc:
        raise_command_http_error(exc)
    return user_command_result(result, ("korctl", "user", "disable", username))


@router.get("/{username}/config")
def get_user_config(request: Request, username: str) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        user_config = UserService(config).read_user_config(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return user_config.model_dump(mode="json")


@router.put("/{username}/config")
def save_user_config(
    request: Request,
    username: str,
    payload: UserConfigRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = UserService(config).save_user_config(username, payload)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return command_result(result, ("korctl", "user", "config", "save", username))


@router.get("/{username}/groups")
def get_user_groups(request: Request, username: str) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        groups = UserService(config).read_user_groups(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"username": username, "groups": groups}


@router.put("/{username}/groups")
def save_user_groups(
    request: Request,
    username: str,
    payload: UserGroupsRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        result = UserService(config).set_user_groups(username, payload.groups)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return command_result(result, ("korctl", "user", "groups", "set", username))


@router.delete("/{username}/config")
def delete_user_config(request: Request, username: str) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    try:
        deleted = UserService(config).delete_user_config(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return command_result(
        CommandResult(
            ("korctl", "user", "config", "delete", username),
            0,
            f"deleted: {str(deleted).lower()}\n",
            "",
            False,
        )
    )


@router.post("/{username}/otp")
def enable_otp(
    request: Request,
    username: str,
) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    OtpService(config).enable(username)
    return {"status": "enabled"}


@router.delete("/{username}/otp")
def disable_otp(
    request: Request,
    username: str,
) -> dict[str, bool]:
    config: AppConfig = request.app.state.config
    return {"disabled": OtpService(config).disable(username)}


@router.get("/otp")
def list_otp_records(request: Request) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    return [record.__dict__ for record in OtpService(config).list_records()]


@router.get("/{username}/otp/qr")
def show_otp_qr(request: Request, username: str) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return command_result(
        OtpService(config).qr_svg(username),
        ("korctl", "user", "otp", "show-qr", username),
    )


@router.post("/{username}/cert")
def create_certificate(
    request: Request,
    username: str,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    results = CertificateService(config).create_user_certificate(
        username,
        dry_run=payload.dry_run if payload else False,
    )
    return {
        "results": [
            {
                "argv": list(("korctl", "user", "cert", "create", username)),
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "dry_run": result.dry_run,
            }
            for result in results
        ]
    }


@router.delete("/{username}/cert")
def revoke_certificate(
    request: Request,
    username: str,
    payload: DryRunRequest | None = None,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    result = CertificateService(config).revoke_user_certificate(
        username,
        dry_run=payload.dry_run if payload else False,
    )
    return command_result(result, ("korctl", "user", "cert", "revoke", username))


@router.get("/{username}/cert")
def download_certificate(request: Request, username: str) -> FileResponse:
    config: AppConfig = request.app.state.config
    path = CertificateService(config).user_cert_path(username)
    if not path.exists():
        raise HTTPException(status_code=404, detail="certificate does not exist; create it first")
    return FileResponse(
        path,
        media_type="application/x-x509-user-cert",
        filename=path.name,
    )


@router.get("/{username}/key")
def download_key(request: Request, username: str) -> FileResponse:
    config: AppConfig = request.app.state.config
    path = CertificateService(config).user_key_path(username)
    if not path.exists():
        raise HTTPException(status_code=404, detail="private key does not exist; create it first")
    return FileResponse(
        path,
        media_type="application/x-pem-file",
        filename=path.name,
    )


@router.post("/{username}/p12")
def create_p12(
    request: Request,
    username: str,
    payload: P12CreateRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    result = CertificateService(config).create_p12(
        username,
        payload.passphrase,
        apple_compatible=payload.apple_compatible,
        dry_run=payload.dry_run,
    )
    argv = ["korctl", "user", "p12", "create", username]
    if payload.apple_compatible:
        argv.append("--apple-compatible")
    if payload.passphrase:
        argv.extend(["--passphrase", "***"])
    return command_result(result, tuple(argv))


@router.get("/{username}/p12")
def download_p12(request: Request, username: str) -> FileResponse:
    config: AppConfig = request.app.state.config
    path = CertificateService(config).user_p12_path(username)
    if not path.exists():
        raise HTTPException(status_code=404, detail="p12 bundle does not exist; create it first")
    return FileResponse(
        path,
        media_type="application/x-pkcs12",
        filename=path.name,
    )
