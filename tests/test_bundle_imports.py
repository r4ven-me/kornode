from __future__ import annotations

import ast
import sys
from pathlib import Path

BUNDLE_PACKAGE = Path(__file__).resolve().parents[1] / "backend" / "kornode" / "bundle"
ALLOWED_THIRD_PARTY = {"pydantic", "cryptography"}


def forbidden_imports(source: str) -> list[str]:
    """Import roots not allowed in kornode.bundle (D-34): the stdlib, pydantic,
    cryptography, kornode.net and this package itself."""
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
            if name.split(".")[:2] in (["kornode", "net"], ["kornode", "bundle"]):
                continue
            if root in sys.stdlib_module_names or root in ALLOWED_THIRD_PARTY:
                continue
            found.append(name)
    return found


def test_kornode_bundle_imports_only_allowed_modules() -> None:
    modules = sorted(BUNDLE_PACKAGE.rglob("*.py"))
    assert modules, "kornode.bundle package not found"
    violations = {
        str(path.relative_to(BUNDLE_PACKAGE)): bad
        for path in modules
        if (bad := forbidden_imports(path.read_text(encoding="utf-8")))
    }
    assert violations == {}


def test_import_checker_rejects_hub_dependencies() -> None:
    source = (
        "import os\n"
        "from pydantic import BaseModel\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "from kornode.net.model import EgressPolicy\n"
        "from kornode.config.models import AppConfig\n"
        "import fastapi\n"
        "from kornode.registry import db\n"
    )

    assert forbidden_imports(source) == ["kornode.config.models", "fastapi", "kornode.registry"]
