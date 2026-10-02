from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from kornode.api.auth import require_admin
from kornode.config.defaults import DEFAULT_CONFIG
from kornode.config.env import combined_environment, env_overrides_from_mapping
from kornode.config.loader import deep_merge, load_config, resolve_secret_refs
from kornode.config.models import AppConfig
from kornode.services.config import ConfigService
from kornode.services.files import FileManager
from kornode.services.secrets import (
    collect_config_secrets,
    is_secret_key,
    mask_text,
    redact_value,
)

router = APIRouter(dependencies=[Depends(require_admin)])


class ConfigSourceSaveRequest(BaseModel):
    content: str = ""
    write_rendered: bool = True


class ConfigSourceValidateRequest(BaseModel):
    content: str = ""


class ConfigPatchRequest(BaseModel):
    patch: dict[str, Any]
    write_rendered: bool = True


class GeneralSettingsRequest(BaseModel):
    timezone: str = "UTC"
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    project_name: str = "kornode"
    cli_enabled: bool = True


@router.get("")
def get_config(request: Request) -> dict[str, Any]:
    config: AppConfig = request.app.state.config
    return config.model_dump_safe()


@router.get("/validate")
def validate_current_config(request: Request) -> dict[str, Any]:
    config: AppConfig = request.app.state.config
    return {"valid": True, "config": config.model_dump_safe()}


@router.post("/validate")
def validate_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = AppConfig.model_validate(payload)
    return config.model_dump_safe()


@router.get("/render")
def render_config(request: Request) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    service = ConfigService()
    secrets = collect_config_secrets(config)
    return {
        str(rendered.path): mask_text(rendered.content, secrets)
        for rendered in service.render_files(config)
    }


@router.post("/render")
def write_rendered_config(
    request: Request,
) -> dict[str, list[str]]:
    config: AppConfig = request.app.state.config
    paths = ConfigService().write_rendered_files(config)
    return {"written": [str(path) for path in paths]}


@router.get("/diff")
def diff_config(request: Request) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    return {"diff": ConfigService().diff_rendered_files(config)}


@router.get("/source")
def get_config_source(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    path = _config_path(request)
    exists = path.exists()
    content = path.read_text(encoding="utf-8") if exists else ""
    return {
        "path": str(path),
        "exists": exists,
        "content": _masked_yaml(content, config),
    }


@router.post("/source/validate")
def validate_config_source(
    request: Request,
    payload: ConfigSourceValidateRequest,
) -> dict[str, object]:
    path = _config_path(request)
    data = _parse_yaml_mapping(payload.content, path)
    old_data = _load_existing_mapping(path)
    restored = _restore_masked_values(data, old_data)
    config = _validate_yaml_config(restored, path)
    return {"valid": True, "config": config.model_dump_safe()}


@router.post("/source")
def save_config_source(
    request: Request,
    payload: ConfigSourceSaveRequest,
) -> dict[str, object]:
    path = _config_path(request)
    data = _parse_yaml_mapping(payload.content, path)
    old_data = _load_existing_mapping(path)
    restored = _restore_masked_values(data, old_data)
    _validate_yaml_config(restored, path)
    FileManager().atomic_write_text(path, _dump_yaml(restored), mode=0o600)
    loaded_config = load_config(path)
    request.app.state.config = loaded_config
    written: list[str] = []
    if payload.write_rendered:
        written = [str(item) for item in ConfigService().write_rendered_files(loaded_config)]
    return {
        "path": str(path),
        "written": written,
        "config": loaded_config.model_dump_safe(),
        "content": _masked_yaml(path.read_text(encoding="utf-8"), loaded_config),
        "valid": True,
    }


@router.patch("")
def patch_config(
    request: Request,
    payload: ConfigPatchRequest,
) -> dict[str, object]:
    loaded_config, written = apply_config_patch(
        request,
        payload.patch,
        write_rendered=payload.write_rendered,
    )
    return {
        "status": "saved",
        "written": written,
        "config": loaded_config.model_dump_safe(),
    }


@router.post("/general-settings")
def save_general_settings(
    request: Request,
    payload: GeneralSettingsRequest,
) -> dict[str, object]:
    patch = {
        "system": {
            "timezone": payload.timezone,
            "log_level": payload.log_level,
            "project_name": payload.project_name,
        },
        "cli": {"enabled": payload.cli_enabled},
    }
    loaded_config, written = apply_config_patch(request, patch)
    return {
        "status": "saved",
        "written": written,
        "system": loaded_config.system.model_dump(mode="json"),
        "cli": loaded_config.cli.model_dump(mode="json"),
    }


def apply_config_patch(
    request: Request,
    patch: dict[str, Any],
    *,
    write_rendered: bool = True,
) -> tuple[AppConfig, list[str]]:
    path = _config_path(request)
    old_data = _load_existing_mapping(path)
    merged = deep_merge(old_data, patch)
    _validate_yaml_config(merged, path)
    FileManager().atomic_write_text(path, _dump_yaml(merged), mode=0o600)
    loaded_config = load_config(path)
    request.app.state.config = loaded_config
    written: list[str] = []
    if write_rendered:
        written = [str(item) for item in ConfigService().write_rendered_files(loaded_config)]
    return loaded_config, written


def _config_path(request: Request) -> Path:
    return Path(request.app.state.config_path)


def _parse_yaml_mapping(content: str, path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(content)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"configuration root must be a mapping: {path}")
    return loaded


def _load_existing_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return _parse_yaml_mapping(path.read_text(encoding="utf-8"), path)


def _validate_yaml_config(data: dict[str, Any], path: Path) -> AppConfig:
    environment = combined_environment(path, environ=None)
    env_overrides = env_overrides_from_mapping(environment)
    merged = deep_merge(DEFAULT_CONFIG, env_overrides)
    merged = deep_merge(merged, data)
    merged = resolve_secret_refs(merged, environment)
    return AppConfig.model_validate(merged)


def _restore_masked_values(value: Any, old_value: Any, key: str | None = None) -> Any:
    if (
        key is not None
        and is_secret_key(key)
        and isinstance(value, str)
        and value in {"***", "${SECRET:***}"}
    ):
        return old_value
    if isinstance(value, dict):
        old_mapping = old_value if isinstance(old_value, dict) else {}
        return {
            item_key: _restore_masked_values(
                item_value,
                old_mapping.get(item_key),
                str(item_key),
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        old_list = old_value if isinstance(old_value, list) else []
        return [
            _restore_masked_values(
                item,
                old_list[index] if index < len(old_list) else None,
                key,
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, str) and value == "${SECRET:***}" and isinstance(old_value, str):
        return old_value
    return value


def _masked_yaml(content: str, config: AppConfig) -> str:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return mask_text(content, collect_config_secrets(config))
    if isinstance(data, dict):
        return _dump_yaml(redact_value(data))
    return mask_text(content, collect_config_secrets(config))


def _dump_yaml(data: Any) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False)
