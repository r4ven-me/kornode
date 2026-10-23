from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

DOTENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Collections absent from DEFAULT_CONFIG; keep independent of models to avoid imports cycles.
TOP_LEVEL_COLLECTIONS = {"egress", "sources", "sets"}
SECRET_ENV_SEGMENT_RE = re.compile(r"(password|passphrase|secret|token)$", re.IGNORECASE)
_CONFIG_ENVIRONMENT: ContextVar[tuple[Path, Path | None, dict[str, str]] | None] = ContextVar(
    "config_environment",
    default=None,
)


def parse_dotenv_file(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, value = line.split("=", 1)
        key = key.strip()
        if not DOTENV_KEY_RE.match(key):
            continue
        value = _parse_dotenv_value(value)
        values[key] = value
    return values


def _parse_dotenv_value(value: str) -> str:
    stripped = _strip_inline_comment(value.strip())
    if not stripped:
        return ""
    if stripped[0] == stripped[-1] == "'":
        return stripped[1:-1]
    if stripped[0] == stripped[-1] == '"':
        return _unescape_double_quoted_dotenv(stripped[1:-1])
    return stripped


def _strip_inline_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            continue
        if char == "#" and quote is None and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value


def _unescape_double_quoted_dotenv(value: str) -> str:
    replacements = {
        "\\n": "\n",
        "\\r": "\r",
        "\\t": "\t",
        '\\"': '"',
        "\\\\": "\\",
    }
    for escaped, replacement in replacements.items():
        value = value.replace(escaped, replacement)
    return value


def discover_env_file(config_path: Path | None, explicit_env_file: Path | None) -> Path | None:
    if explicit_env_file is not None:
        return explicit_env_file
    candidates: list[Path] = []
    if config_path is not None:
        candidates.append(config_path.parent / ".env")
    candidates.append(Path.cwd() / ".env")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


@contextmanager
def config_environment(config_path: Path, env_file: Path | None = None) -> Iterator[None]:
    """Freeze one supplied path's environment across guards, callbacks and commit.

    Do not resolve config_path: a symlink's parent .env is part of the loader's
    public configuration context, even when publication uses the target inode.
    """
    current = _CONFIG_ENVIRONMENT.get()
    if current is not None and current[0] == config_path.absolute():
        if env_file is not None and env_file.absolute() != current[1]:
            raise ValueError("conflicting configuration environment context")
        yield
        return
    selected = discover_env_file(config_path, env_file)
    environment = combined_environment(config_path, selected)
    token = _CONFIG_ENVIRONMENT.set(
        (
            config_path.absolute(),
            selected.absolute() if selected is not None else None,
            environment,
        )
    )
    try:
        yield
    finally:
        _CONFIG_ENVIRONMENT.reset(token)


def combined_environment(
    config_path: Path | None = None,
    env_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    current = _CONFIG_ENVIRONMENT.get()
    if current is not None and config_path is not None:
        bound_path, bound_env_file, environment = current
        if config_path.absolute() == bound_path:
            if environ is not None or (
                env_file is not None and env_file.absolute() != bound_env_file
            ):
                raise ValueError("conflicting configuration environment context")
            return dict(environment)
        if config_path.resolve() == bound_path.resolve():
            raise ValueError("alternate configuration alias inside an environment context")
    selected_env_file = discover_env_file(config_path, env_file)
    file_values = parse_dotenv_file(selected_env_file)
    process_values = dict(os.environ if environ is None else environ)
    return {**file_values, **process_values}


def parse_env_value(value: str) -> Any:
    stripped = value.strip()
    if stripped == "":
        return ""

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    lowered = stripped.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none"}:
        return None

    try:
        if stripped.startswith("0") and stripped not in {"0"} and not stripped.startswith("0."):
            return stripped
        return int(stripped)
    except ValueError:
        return stripped


def env_overrides_from_mapping(
    values: Mapping[str, str],
    prefix: str = "KORNODE_",
) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for key, raw_value in values.items():
        if not key.startswith(prefix) or key in {"KORNODE_CONFIG", "KORNODE_ENV_FILE"}:
            continue
        if (
            "__" not in key[len(prefix) :]
            and key[len(prefix) :].lower() not in TOP_LEVEL_COLLECTIONS
        ):
            continue
        path = [segment.lower() for segment in key[len(prefix) :].split("__") if segment]
        if not path:
            continue
        current: dict[str, Any] = overrides
        for segment in path[:-1]:
            child = current.setdefault(segment, {})
            if not isinstance(child, dict):
                raise ValueError(f"conflicting environment override at {key}")
            current = child
        if SECRET_ENV_SEGMENT_RE.search(path[-1]):
            # Credentials stay verbatim strings: an all-digit password must
            # not turn into an int, and "true"/"null" passwords stay text.
            current[path[-1]] = raw_value
        else:
            current[path[-1]] = parse_env_value(raw_value)
    return overrides
