from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from kornode.api.auth import invalidate_auth_sessions, require_admin
from kornode.config.env import config_environment
from kornode.config.loader import deep_merge, rename_legacy_sections, validate_config_data
from kornode.config.models import AppConfig
from kornode.services.config import ConfigService
from kornode.services.config_store import (
    ConfigApplyError,
    ConfigPreflightError,
    ConfigVersionConflict,
    config_lock,
    mutate_config,
    source_etag,
    source_version,
)
from kornode.services.render_transaction import render_config as render_config_transaction
from kornode.services.secrets import (
    collect_config_secrets,
    mask_text,
    redact_value,
)

router = APIRouter(dependencies=[Depends(require_admin)])


class ConfigSourceSaveRequest(BaseModel):
    content: str = ""
    write_rendered: bool = True
    etag: str | None = None


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
def validate_config(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    path = _config_path(request)
    with config_lock(path) as target:
        old_data = _load_existing_mapping(target)
        restored = _restore_masked_values(payload, old_data)
        config = _validate_public_candidate(restored, old_data, path)
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
    path = runtime_config_path(request)
    if path is None:
        # Embedded/initialization-only apps have no authoritative disk source.
        return {
            "written": [
                str(item) for item in ConfigService().write_rendered_files(request.app.state.config)
            ]
        }
    return {"written": render_config_transaction(path)}


@router.get("/diff")
def diff_config(request: Request) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    return {"diff": ConfigService().diff_rendered_files(config)}


@router.get("/source")
def get_config_source(request: Request, response: Response) -> dict[str, object]:
    path = _config_path(request)
    with config_lock(path) as target:
        exists = target.exists()
        content = target.read_text(encoding="utf-8") if exists else ""
        etag = source_etag(target)
        response.headers["ETag"] = etag
        return {
            "path": str(path),
            "exists": exists,
            "etag": etag,
            "content": _masked_yaml(content, request.app.state.config),
        }


@router.post("/source/validate")
def validate_config_source(
    request: Request,
    payload: ConfigSourceValidateRequest,
) -> dict[str, object]:
    path = _config_path(request)
    data = _parse_yaml_mapping(payload.content, path)
    with config_lock(path) as target:
        old_data = _load_existing_mapping(target)
        restored = _restore_masked_values(data, old_data)
        config = _validate_public_candidate(restored, old_data, path)
        return {"valid": True, "config": config.model_dump_safe()}


@router.post("/source")
def save_config_source(
    request: Request,
    payload: ConfigSourceSaveRequest,
    response: Response,
) -> dict[str, object]:
    path = _config_path(request)
    data = _parse_yaml_mapping(payload.content, path)
    expected = request.headers.get("if-match") or payload.etag
    if expected is None:
        raise HTTPException(status_code=428, detail="source version required; reload source first")
    saved: dict[str, Any] = {}

    def replace(raw: dict[str, Any]) -> dict[str, Any]:
        restored = _restore_masked_values(data, raw)
        _validate_public_candidate(restored, raw, path)
        saved.update(restored)
        return cast(dict[str, Any], restored)

    loaded_config, written = _apply_config_mutation(
        request,
        replace,
        write_rendered=payload.write_rendered,
        expected_etag=expected,
    )
    content = _dump_yaml(saved)
    etag = source_version(b"present\0" + content.encode("utf-8"))
    response.headers["ETag"] = etag
    return {
        "path": str(path),
        "written": written,
        "config": loaded_config.model_dump_safe(),
        "content": _masked_yaml(content, loaded_config),
        "valid": True,
        "etag": etag,
    }


@router.patch("")
def patch_config(
    request: Request,
    payload: ConfigPatchRequest,
) -> dict[str, object]:
    def patch(raw: dict[str, Any]) -> dict[str, Any]:
        candidate = _restore_masked_values(deep_merge(raw, payload.patch), raw)
        _validate_public_candidate(candidate, raw, _config_path(request))
        return cast(dict[str, Any], candidate)

    loaded_config, written = _apply_config_mutation(
        request,
        patch,
        write_rendered=payload.write_rendered,
        expected_etag=request.headers.get("if-match"),
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
    return apply_config_mutation(
        request,
        lambda raw: deep_merge(raw, patch),
        write_rendered=write_rendered,
    )


def apply_config_mutation(
    request: Request,
    mutation: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    write_rendered: bool = True,
) -> tuple[AppConfig, list[str]]:
    """Internal trusted mutation; callback receives latest raw YAML under the lock.

    Dedicated auth routes may change credentials here after reauthentication.
    Public raw-source and PATCH endpoints enforce their own auth-field guard.
    """
    return _apply_config_mutation(request, mutation, write_rendered=write_rendered)


def _apply_config_mutation(
    request: Request,
    mutation: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    write_rendered: bool = True,
    expected_etag: str | None = None,
) -> tuple[AppConfig, list[str]]:
    def install(config: AppConfig) -> None:
        previous = request.app.state.config
        request.app.state.config = config
        request.app.state.config_source = _config_path(request)
        invalidate_auth_sessions(request, previous, config)

    try:
        return mutate_config(
            _config_path(request),
            mutation,
            write_rendered=write_rendered,
            on_commit=install,
            expected_etag=expected_etag,
        )
    except ConfigPreflightError:
        raise HTTPException(
            status_code=500,
            detail={
                "status": "not_saved",
                "saved": False,
                "applied": False,
                "message": "Render preflight failed; configuration was not saved.",
            },
        ) from None
    except ConfigVersionConflict:
        raise HTTPException(
            status_code=412,
            detail="configuration source changed; reload first",
        ) from None
    except ConfigApplyError:
        raise HTTPException(
            status_code=500,
            detail={
                "status": "saved_but_not_applied",
                "saved": True,
                "applied": False,
                "message": "Runtime files may be partially updated; retry rendering before reload.",
            },
        ) from None


def _validate_public_candidate(
    candidate: dict[str, Any],
    previous: dict[str, Any],
    path: Path,
) -> AppConfig:
    with config_environment(path):
        config = _validate_yaml_config(candidate, path)
        old_config = _validate_yaml_config(previous, path)
    for field in (
        "admin_password",
        "admin_password_hash",
        "admin_totp_enabled",
        "admin_totp_secret",
    ):
        if getattr(config.web, field) != getattr(old_config.web, field):
            raise HTTPException(
                status_code=403,
                detail="admin authentication changes require dedicated auth actions",
            )
    return config


def runtime_config_path(request: Request) -> Path | None:
    """Explicit source for runtime writers; embedded config-only apps keep overrides."""
    source = getattr(request.app.state, "config_source", request.app.state.config_path)
    return Path(source) if source is not None else None


def _config_path(request: Request) -> Path:
    return Path(request.app.state.config_path)


def _parse_yaml_mapping(content: str, path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(content)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"configuration root must be a mapping: {path}")
    return rename_legacy_sections(loaded, str(path))


def _load_existing_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return _parse_yaml_mapping(path.read_text(encoding="utf-8"), path)


def _validate_yaml_config(data: dict[str, Any], path: Path) -> AppConfig:
    return validate_config_data(data, path)


def _restore_masked_values(value: Any, old_value: Any, key: str | None = None) -> Any:
    if isinstance(value, str) and (value == "***" or "${SECRET:***}" in value):
        if (
            isinstance(old_value, str)
            and old_value not in {"", "***", "${SECRET:***}"}
            and redact_value(old_value, key) == value
        ):
            return old_value
        raise ValueError("masked placeholder has no unambiguous original secret")
    if isinstance(value, dict):
        old_mapping = old_value if isinstance(old_value, dict) else {}
        return {
            item_key: _restore_masked_values(item_value, old_mapping.get(item_key), str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        old_list = old_value if isinstance(old_value, list) else []

        # Never transfer a credential by position. Reorder/removal must follow
        # stable named identity; unnamed lists cannot round-trip masked values.
        def named(items: list[Any]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    continue
                name = item["name"]
                if name in result:
                    raise ValueError("duplicate list identity makes secret restoration ambiguous")
                result[name] = item
            return result

        originals = named(old_list)
        named(value)
        return [
            _restore_masked_values(
                item,
                originals.get(item["name"])
                if isinstance(item, dict) and isinstance(item.get("name"), str)
                else None,
                key,
            )
            for item in value
        ]
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
