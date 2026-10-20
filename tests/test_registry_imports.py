from __future__ import annotations

import ast
import sys
from pathlib import Path

REGISTRY_PACKAGE = Path(__file__).resolve().parents[1] / "backend" / "kornode" / "registry"


def forbidden_imports(source: str) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                continue
            names = [node.module or ""]
        else:
            continue
        for name in names:
            root = name.split(".")[0]
            if name == "kornode.registry" or name.startswith("kornode.registry."):
                continue
            if name == "kornode.net" or name.startswith("kornode.net."):
                continue
            if root in sys.stdlib_module_names:
                continue
            found.append(name)
    return found


def test_kornode_registry_imports_only_allowed_modules() -> None:
    modules = sorted(REGISTRY_PACKAGE.rglob("*.py"))
    assert modules, "kornode.registry package not found"
    violations = {
        str(path.relative_to(REGISTRY_PACKAGE)): bad
        for path in modules
        if (bad := forbidden_imports(path.read_text(encoding="utf-8")))
    }
    assert violations == {}


def test_import_checker_rejects_hub_dependencies() -> None:
    source = (
        "import os\n"
        "from kornode.registry.db import migrate\n"
        "from kornode.net.errors import NetError\n"
        "from . import state\n"
        "from kornode.config.models import AppConfig\n"
        "import fastapi\n"
        "from kornode.api import app\n"
    )

    assert forbidden_imports(source) == ["kornode.config.models", "fastapi", "kornode.api"]
