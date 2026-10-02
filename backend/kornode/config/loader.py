from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from kornode.config.defaults import DEFAULT_CONFIG
from kornode.config.env import combined_environment, env_overrides_from_mapping
from kornode.config.models import AppConfig

DEFAULT_CONFIG_PATH = Path("/etc/kornode/config.yaml")
SECRET_REF_RE = re.compile(r"^\$\{SECRET:([A-Za-z_][A-Za-z0-9_]*)}$")


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_yaml_file(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"configuration root must be a mapping: {path}")
    return loaded


def resolve_secret_refs(value: Any, secrets: Mapping[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: resolve_secret_refs(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_secret_refs(item, secrets) for item in value]
    if isinstance(value, str):
        match = SECRET_REF_RE.match(value)
        if match:
            secret_name = match.group(1)
            if secret_name not in secrets:
                raise ValueError(f"missing required secret environment variable: {secret_name}")
            return secrets[secret_name]
    return value


def load_config(
    config_path: Path | str | None = None,
    *,
    env_file: Path | str | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> AppConfig:
    resolved_config_path = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH
    resolved_env_file = Path(env_file) if env_file is not None else None

    yaml_config = load_yaml_file(resolved_config_path)
    environment = combined_environment(resolved_config_path, resolved_env_file, environ)
    env_overrides = env_overrides_from_mapping(environment)

    merged = deep_merge(DEFAULT_CONFIG, env_overrides)
    merged = deep_merge(merged, yaml_config)
    if cli_overrides:
        merged = deep_merge(merged, cli_overrides)
    merged = resolve_secret_refs(merged, environment)
    return AppConfig.model_validate(merged)


def load_default_config() -> AppConfig:
    return AppConfig.model_validate(copy.deepcopy(DEFAULT_CONFIG))
