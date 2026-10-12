from __future__ import annotations

import ast
import sys
from pathlib import Path

NET_PACKAGE = Path(__file__).resolve().parents[1] / "backend" / "kornode" / "net"
ALLOWED_THIRD_PARTY = {"pydantic", "pyroute2"}


def forbidden_imports(source: str) -> list[str]:
    """Top-level import roots not allowed in kornode.net.

    Allowed: the stdlib, pydantic, pyroute2 and kornode.net itself (absolute
    or relative). Everything else -- kornode.api, kornode.config, FastAPI,
    other kornode packages -- is rejected, so the core stays usable by the
    agent image without the hub's dependencies.
    """
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
            if name == "kornode.net" or name.startswith("kornode.net."):
                continue
            if root in sys.stdlib_module_names or root in ALLOWED_THIRD_PARTY:
                continue
            found.append(name)
    return found


def test_kornode_net_imports_only_allowed_modules() -> None:
    modules = sorted(NET_PACKAGE.rglob("*.py"))
    assert modules, "kornode.net package not found"
    violations = {
        str(path.relative_to(NET_PACKAGE)): bad
        for path in modules
        if (bad := forbidden_imports(path.read_text(encoding="utf-8")))
    }
    assert violations == {}


def test_import_checker_rejects_hub_dependencies() -> None:
    source = (
        "import os\n"
        "from pydantic import BaseModel\n"
        "from pyroute2 import IPRoute\n"
        "from kornode.net.errors import NetError\n"
        "from . import state\n"
        "from kornode.config.models import AppConfig\n"
        "import fastapi\n"
        "from kornode.api import app\n"
    )

    assert forbidden_imports(source) == ["kornode.config.models", "fastapi", "kornode.api"]
