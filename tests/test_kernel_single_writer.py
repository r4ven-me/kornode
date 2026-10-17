"""P2 done-when: nft and rule/route/sysctl mutations exist in exactly one
module, kornode.net.kernel. Everything else changes reconciler inputs.

The check walks the AST, so comments and docstrings cannot trip it and
aliased imports cannot hide from it. Read-only probes (`ip -j rule show`,
`nft list ...`, `nft --version`) are fine anywhere; only mutating argv shapes
are flagged.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "backend"
BACKEND = ROOT / "kornode"
AGENT = ROOT / "kornode_agent"
KERNEL = BACKEND / "net" / "kernel.py"

NFT_READ_ONLY = {"--version", "-V", "list", "-j"}
IP_MUTATIONS = {"add", "del", "delete", "replace", "flush", "change"}
EXEC_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
}
# Generic runners take an argv built elsewhere; every literal argv that reaches
# them is checked where it is written, so a non-literal call here is not a gap.
GENERIC_RUNNERS = {
    "kornode/services/command.py",
    "kornode_agent/agent.py",
    "kornode_agent/doctor.py",
    "kornode_agent/inputs.py",
    "kornode_agent/tunnels.py",
}
WRITE_MODES = re.compile(r"[wax+]")
SHELL_MUTATION = re.compile(
    r"\b(?:ip\s+(?:-[46]\s+)?(?:rule|route)\s+(?:add|del|delete|replace|flush|change)"
    r"|nft\s+(?:-f|add|delete|flush|insert|replace)|sysctl\s+-w)\b"
)


def _literal_argv(node: ast.AST) -> list[str | None] | None:
    """Elements of a list/tuple literal; None for non-string or starred ones."""
    if not isinstance(node, ast.List | ast.Tuple):
        return None
    return [
        element.value
        if isinstance(element, ast.Constant) and isinstance(element.value, str)
        else None
        for element in node.elts
    ]


def _argv_problem(argv: list[str | None]) -> str | None:
    head = argv[0]
    rest = argv[1:]
    if head == "nft":
        if not rest or rest[0] is None:
            return "nft argv with a dynamic subcommand"
        if rest[0] not in NFT_READ_ONLY:
            return f"nft {rest[0]}"
    elif head == "sysctl" and "-w" in rest:
        return "sysctl -w"
    elif head == "ip":
        for first, second in zip(rest, rest[1:], strict=False):
            if first in {"rule", "route"} and second in IP_MUTATIONS:
                return f"ip {first} {second}"
    return None


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _writes_files(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"write_text", "write_bytes"}:
            return True
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            mode = node.args[1] if len(node.args) > 1 else None
            if isinstance(mode, ast.Constant) and WRITE_MODES.search(str(mode.value)):
                return True
    return False


def kernel_writes(source: str, *, generic_runner: bool = False) -> list[str]:
    """What in `source` touches the kernel's mutable state or the netlink API.
    Reading /proc/sys is fine; naming it in a module that writes files is not."""
    tree = ast.parse(source)
    writes_files = _writes_files(tree)
    docstrings = {
        id(body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and (body := node.body)
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
    }
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [f"import {a.name}" for a in node.names if a.name.split(".")[0] == "pyroute2"]
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and (node.module or "").split(".")[0] == "pyroute2":
                found.append(f"import from {node.module}")
        elif isinstance(node, ast.List | ast.Tuple):
            if any(isinstance(e, ast.List | ast.Tuple) for e in node.elts):
                continue  # pairs like ("nft", ["nft", "--version"]), not an argv
            argv = _literal_argv(node)
            if argv and argv[0] is not None and (problem := _argv_problem(argv)):
                found.append(problem)
            if argv and any(a == "-f" and b == "-" for a, b in zip(argv, argv[1:], strict=False)):
                found.append("nft -f -")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings:
                continue
            if node.value.startswith("/proc/sys") and writes_files:
                found.append(f"path {node.value}")
            elif SHELL_MUTATION.search(node.value):
                found.append(f"command string {node.value!r}")
        elif (
            isinstance(node, ast.Call)
            and _dotted(node.func) in EXEC_CALLS
            and not generic_runner
            and (not node.args or _literal_argv(node.args[0]) is None)
        ):
            found.append(f"{_dotted(node.func)} with a non-literal argv")
    return found


def _sources() -> list[Path]:
    # The agent is covered too: only kornode.net may touch the kernel (D-34).
    return sorted(
        path
        for package in (BACKEND, AGENT)
        for path in package.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def test_only_the_net_package_writes_kernel_state() -> None:
    net_package = BACKEND / "net"
    offenders = {
        str(path.relative_to(ROOT)): writes
        for path in _sources()
        if path != KERNEL
        and net_package not in path.parents
        and (
            writes := kernel_writes(
                path.read_text(encoding="utf-8"),
                generic_runner=str(path.relative_to(ROOT)) in GENERIC_RUNNERS,
            )
        )
    }
    assert offenders == {}


def test_inside_the_net_package_only_kernel_py_mutates() -> None:
    offenders = {
        str(path.relative_to(ROOT)): writes
        for path in sorted((BACKEND / "net").rglob("*.py"))
        if path != KERNEL
        and (
            writes := [
                w
                for w in kernel_writes(path.read_text(encoding="utf-8"))
                if not w.startswith("import")
            ]
        )
    }
    assert offenders == {}


def test_the_scanner_flags_what_it_must() -> None:
    cases = {
        "import pyroute2.iproute as r": "import pyroute2.iproute",
        "from pyroute2 import IPRoute as X": "import from pyroute2",
        'run(["nft", "add", "table", "x"])': "nft add",
        'run(["nft", *args])': "nft argv with a dynamic subcommand",
        'run(["sysctl", "-w", "a=1"])': "sysctl -w",
        'run(["ip", "-4", "rule", "add", "x"])': "ip rule add",
        'run(["ip", "route", "replace", "x"])': "ip route replace",
        'run(["x", "-f", "-"])': "nft -f -",
        'open("/proc/sys/net/ipv4/ip_forward", "w")': "path /proc/sys/net/ipv4/ip_forward",
        "subprocess.run(cmd)": "subprocess.run with a non-literal argv",
        'os.system("ip route add x")': "os.system with a non-literal argv",
    }
    for source, expected in cases.items():
        assert expected in kernel_writes(source), source


def test_the_scanner_ignores_what_it_must() -> None:
    harmless = [
        'run(["nft", "--version"])',
        'run(["nft", "-j", "list", "ruleset"])',
        'run(["nft", "list", "table", "inet", "kornode"])',
        'run(["ip", "-j", "rule", "show"])',
        'subprocess.run(["ls", "-l"])',
        'x = ("nft", ["nft", "--version"])',
        'p = Path("/proc/sys/net/ipv4/conf/all/rp_filter").read_text()',
        '"""ip rule add is documented here"""\nx = 1',
        "# nft add table x\nx = 1",
    ]
    for source in harmless:
        assert kernel_writes(source) == [], source


def test_the_scan_sees_the_kernel_module() -> None:
    # Guards against the scan silently matching nothing.
    writes = kernel_writes(KERNEL.read_text(encoding="utf-8"))
    assert "nft -f -" in writes
    assert any(w.startswith("import") for w in writes)
