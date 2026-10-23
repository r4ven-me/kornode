"""Select raw collections without materializing resolved configuration or secrets."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from kornode.config.env import combined_environment, env_overrides_from_mapping


def raw_collection(
    raw: dict[str, Any], config_path: Path, section: str, field: str
) -> list[dict[str, Any]]:
    """YAML wins over env, including an explicitly empty list.

    Call inside apply_config_mutation so selection and replacement share its lock.
    Only the requested collection is copied back to YAML; env secret references
    stay references and unrelated effective defaults never become persisted state.
    """
    value = raw_config_value(raw, config_path, section, field, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{section}.{field} must be a list of mappings")
    return deepcopy(value)


def raw_config_value(
    raw: dict[str, Any], config_path: Path, section: str, field: str, default: Any = None
) -> Any:
    """Select one unresolved value using the same YAML-over-env precedence."""
    block = raw.get(section, {})
    if field in block:
        return deepcopy(block[field])
    overrides = env_overrides_from_mapping(combined_environment(config_path))
    return deepcopy(overrides.get(section, {}).get(field, default))


def replace_named(
    items: list[dict[str, Any]], name: str, replacement: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """Replace in place to preserve positional tunnel interfaces; None deletes."""
    result = []
    found = False
    for item in items:
        if item.get("name") == name:
            found = True
            if replacement is not None:
                result.append(replacement)
        else:
            result.append(item)
    if not found and replacement is not None:
        result.append(replacement)
    return result
