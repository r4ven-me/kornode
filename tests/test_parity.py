from __future__ import annotations

import importlib
import re
from pathlib import Path
from typing import Any

import yaml
from fastapi.routing import APIRoute, APIWebSocketRoute
from typer.main import get_command

from kornode.api.app import create_app
from kornode.cli import app as typer_app
from kornode.config.defaults import DEFAULT_CONFIG
from kornode.config.models import AppConfig

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "parity.yaml"
UI_ROOT = ROOT / "frontend" / "src"


def discover_cli_commands() -> set[str]:
    root = get_command(typer_app)

    def walk(command: Any, prefix: tuple[str, ...]) -> set[str]:
        children = getattr(command, "commands", None)
        if isinstance(children, dict) and children:
            found: set[str] = set()
            for name, child in children.items():
                found.update(walk(child, (*prefix, name)))
            return found
        return {" ".join(prefix)}

    return walk(root, ())


def discover_api_routes() -> set[str]:
    config = AppConfig.model_validate(DEFAULT_CONFIG)
    app = create_app(config=config, config_path=ROOT / "config.example.yaml")

    def walk(routes: list[Any], prefix: str = "") -> set[str]:
        found: set[str] = set()
        for route in routes:
            if isinstance(route, APIRoute):
                path = f"{prefix}{route.path}"
                for method in route.methods - {"HEAD", "OPTIONS"}:
                    found.add(f"{method} {path}")
            elif isinstance(route, APIWebSocketRoute):
                found.add(f"WS {prefix}{route.path}")
            elif type(route).__name__ == "_IncludedRouter":
                context = route.include_context
                found.update(walk(route.original_router.routes, f"{prefix}{context.prefix}"))
        return found

    return {
        item
        for item in walk(app.routes)
        if item.split(" ", 1)[1].startswith("/api/") or item == "GET /healthz"
    }


def discover_ui_capabilities() -> set[str]:
    pattern = re.compile(r"data-capability\s*=\s*[\"']([^\"']+)[\"']")
    found: set[str] = set()
    for path in UI_ROOT.rglob("*.tsx"):
        if path.name.endswith(".test.tsx"):
            continue  # a capability that survives only in a test is not in the panel
        found.update(pattern.findall(path.read_text(encoding="utf-8")))
    return found


def resolve_service(path: str) -> bool:
    parts = path.split(".")
    for index in range(len(parts), 0, -1):
        module_name = ".".join(parts[:index])
        try:
            target: Any = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue
        for attr in parts[index:]:
            target = getattr(target, attr)
        return callable(target)
    return False


def check_parity(
    manifest: dict[str, Any],
    *,
    cli_commands: set[str],
    api_routes: set[str],
    ui_capabilities: set[str],
) -> list[str]:
    errors: list[str] = []
    capabilities = manifest.get("capabilities")
    ignores = manifest.get("parity_ignore", [])
    if not isinstance(capabilities, list):
        return ["parity.yaml must contain a capabilities list"]
    if not isinstance(ignores, list):
        return ["parity.yaml parity_ignore must be a list"]

    listed_cli: set[str] = set()
    listed_api: set[str] = set()
    ignore_cli: set[str] = set()
    ignore_api: set[str] = set()

    for item in ignores:
        if not isinstance(item, dict):
            errors.append("parity_ignore entries must be mappings")
            continue
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"parity_ignore entry {item!r} requires a non-empty reason")
        cli = item.get("cli")
        api = item.get("api")
        if isinstance(cli, str):
            ignore_cli.add(cli)
        if isinstance(api, str):
            ignore_api.add(api)

    for capability in capabilities:
        if not isinstance(capability, dict):
            errors.append("capabilities entries must be mappings")
            continue
        cap_id = capability.get("id")
        if not isinstance(cap_id, str) or not cap_id.strip():
            errors.append(f"capability {capability!r} requires a non-empty id")
            continue

        exempt = capability.get("exempt")
        has_exempt = isinstance(exempt, str) and bool(exempt.strip())
        if "exempt" in capability and not has_exempt:
            errors.append(f"capability {cap_id} has exempt but no non-empty reason")

        missing_sides = [side for side in ("cli", "api", "ui") if capability.get(side) is None]
        if missing_sides and not has_exempt:
            errors.append(f"capability {cap_id} has {', '.join(missing_sides)} null without exempt")

        cli = capability.get("cli")
        if cli is not None:
            if not isinstance(cli, str) or not cli.strip():
                errors.append(f"capability {cap_id} cli must be a non-empty string or null")
            elif cli not in cli_commands:
                errors.append(f"capability {cap_id} cli does not resolve: {cli}")
            else:
                listed_cli.add(cli)

        api = capability.get("api")
        if api is not None:
            if not isinstance(api, str) or not api.strip():
                errors.append(f"capability {cap_id} api must be a non-empty string or null")
            elif api not in api_routes:
                errors.append(f"capability {cap_id} api does not resolve: {api}")
            else:
                listed_api.add(api)

        ui = capability.get("ui")
        if ui is not None:
            if not isinstance(ui, str) or not ui.strip():
                errors.append(f"capability {cap_id} ui must be a non-empty string or null")
            elif ui not in ui_capabilities:
                errors.append(f"capability {cap_id} ui does not resolve: {ui}")

        service = capability.get("service")
        if service is not None:
            if not isinstance(service, str) or not service.strip():
                errors.append(f"capability {cap_id} service must be a non-empty string or null")
            elif not resolve_service(service):
                errors.append(f"capability {cap_id} service does not resolve: {service}")

    missing_cli = sorted(cli_commands - listed_cli - ignore_cli)
    if missing_cli:
        errors.append("unlisted CLI commands: " + ", ".join(missing_cli))
    missing_api = sorted(api_routes - listed_api - ignore_api)
    if missing_api:
        errors.append("unlisted API routes: " + ", ".join(missing_api))
    return errors


def load_manifest() -> dict[str, Any]:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_manifest_matches_discovered_surfaces() -> None:
    errors = check_parity(
        load_manifest(),
        cli_commands=discover_cli_commands(),
        api_routes=discover_api_routes(),
        ui_capabilities=discover_ui_capabilities(),
    )
    assert errors == []


def test_rule_a_reports_cli_without_api_or_ui() -> None:
    errors = check_parity(
        {
            "capabilities": [
                {
                    "id": "demo.command",
                    "service": None,
                    "cli": "demo",
                    "api": None,
                    "ui": None,
                }
            ],
            "parity_ignore": [],
        },
        cli_commands={"demo"},
        api_routes=set(),
        ui_capabilities=set(),
    )
    assert errors == ["capability demo.command has api, ui null without exempt"]


def test_unlisted_cli_command_is_reported() -> None:
    errors = check_parity(
        {"capabilities": [], "parity_ignore": []},
        cli_commands={"orphan"},
        api_routes=set(),
        ui_capabilities=set(),
    )
    assert errors == ["unlisted CLI commands: orphan"]


def test_unknown_ui_id_is_reported() -> None:
    errors = check_parity(
        {
            "capabilities": [
                {
                    "id": "demo.ui",
                    "service": None,
                    "cli": None,
                    "api": None,
                    "ui": "missing.ui",
                    "exempt": "negative fixture",
                }
            ],
            "parity_ignore": [],
        },
        cli_commands=set(),
        api_routes=set(),
        ui_capabilities={"known.ui"},
    )
    assert errors == ["capability demo.ui ui does not resolve: missing.ui"]
