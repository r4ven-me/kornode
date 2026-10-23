from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch
from kornode.config.models import AppConfig, IntervalUnit, LogRotationConfig
from kornode.services.logs import LogRecord, LogRotationService, LogService

router = APIRouter(dependencies=[Depends(require_admin)])


class LogRotationSettingsRequest(BaseModel):
    enabled: bool = False
    max_size_mb: int = Field(default=50, ge=0)
    max_age: int = Field(default=0, ge=0)
    max_age_unit: IntervalUnit = "days"
    keep_files: int = Field(default=5, ge=1, le=100)


@router.get("/files")
def list_logs(request: Request) -> list[LogRecord]:
    config: AppConfig = request.app.state.config
    return LogService(config).list_logs()


@router.get("")
def tail_log(
    request: Request,
    name: str = Query("api.log", min_length=1, max_length=128),
    lines: int = Query(100, ge=1, le=1000),
) -> dict[str, str | int]:
    config: AppConfig = request.app.state.config
    return {
        "name": name,
        "lines": lines,
        "content": LogService(config).tail(name=name, lines=lines),
    }


@router.get("/rotation")
def rotation_settings(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return config.system.log_rotation.model_dump(mode="json")


@router.post("/rotation")
def save_rotation_settings(
    request: Request,
    payload: LogRotationSettingsRequest,
) -> dict[str, object]:
    settings = LogRotationConfig.model_validate(payload.model_dump())
    # No rendered file depends on rotation settings. The shared transaction
    # still validates and installs the candidate under the config lock.
    loaded_config, _ = apply_config_patch(
        request,
        {"system": {"log_rotation": settings.model_dump(mode="json")}},
        write_rendered=False,
    )
    return {
        "status": "log rotation settings saved",
        "settings": loaded_config.system.log_rotation.model_dump(mode="json"),
    }


@router.post("/rotation/run")
def run_rotation(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    rotated = LogRotationService(config).rotate(force=True)
    return {"status": "rotation completed", "rotated": rotated}
