from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.config.loader import load_config
from kornode.config.models import AppConfig, IntervalUnit, LogRotationConfig
from kornode.services.files import FileManager
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
    path = Path(request.app.state.config_path)
    data = _load_yaml_mapping(path)
    system = data.setdefault("system", {})
    if not isinstance(system, dict):
        raise ValueError("system config must be a mapping")
    system["log_rotation"] = settings.model_dump(mode="json")
    FileManager().atomic_write_text(
        path,
        yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
        mode=0o600,
    )
    # No rendered file depends on rotation settings (the supervisor program is
    # unconditional and korctl re-reads the config each cycle), so persisting
    # the YAML and refreshing the in-memory config is enough.
    loaded_config = load_config(path)
    request.app.state.config = loaded_config
    return {
        "status": "log rotation settings saved",
        "settings": loaded_config.system.log_rotation.model_dump(mode="json"),
    }


@router.post("/rotation/run")
def run_rotation(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    rotated = LogRotationService(config).rotate(force=True)
    return {"status": "rotation completed", "rotated": rotated}


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"configuration root must be a mapping: {path}")
    return cast(dict[str, Any], loaded)
