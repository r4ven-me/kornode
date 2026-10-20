from __future__ import annotations

import ast
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "backend" / "kornode" / "tunnels"


def forbidden_imports(source: str) -> list[str]:
    """kornode.tunnels is shared with the agent: the stdlib and itself only."""
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
            if name.split(".")[:2] == ["kornode", "tunnels"]:
                continue
            if name.split(".")[0] in sys.stdlib_module_names:
                continue
            found.append(name)
    return found


def test_kornode_tunnels_imports_only_stdlib() -> None:
    modules = sorted(PACKAGE.rglob("*.py"))
    assert modules
    violations = {
        path.name: bad
        for path in modules
        if (bad := forbidden_imports(path.read_text(encoding="utf-8")))
    }
    assert violations == {}


def test_import_checker_rejects_hub_modules() -> None:
    source = "import os\nfrom kornode.services.command import CommandRunner\nimport yaml\n"
    assert forbidden_imports(source) == ["kornode.services.command", "yaml"]
