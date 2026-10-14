from __future__ import annotations

import ast
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "backend" / "kornode_agent"
ALLOWED_THIRD_PARTY = {"httpx", "cryptography", "pydantic", "yaml"}
ALLOWED_KORNODE = {"kornode.net", "kornode.bundle", "kornode.tunnels"}


def forbidden_imports(source: str) -> list[str]:
    """kornode_agent depends only on kornode.net/bundle/tunnels (ROADMAP P3-06)."""
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
            if ".".join(name.split(".")[:2]) in ALLOWED_KORNODE or root == "kornode_agent":
                continue
            if root in sys.stdlib_module_names or root in ALLOWED_THIRD_PARTY:
                continue
            found.append(name)
    return found


def test_kornode_agent_imports_only_allowed_modules() -> None:
    modules = sorted(PACKAGE.rglob("*.py"))
    assert modules
    violations = {
        path.name: bad
        for path in modules
        if (bad := forbidden_imports(path.read_text(encoding="utf-8")))
    }
    assert violations == {}


def test_import_checker_rejects_hub_modules() -> None:
    source = "import httpx\nfrom kornode.services.users import UserService\nimport fastapi\n"
    assert forbidden_imports(source) == ["kornode.services.users", "fastapi"]
