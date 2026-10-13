"""P2 done-when: nft and rule/route/sysctl mutations exist in exactly one
module, kornode.net.kernel. Everything else changes reconciler inputs.

Read-only probes (`ip -j rule show`, `nft list ...`, `nft --version`) are
fine anywhere; only mutating argv shapes are matched.
"""

from __future__ import annotations

import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend" / "kornode"
KERNEL = BACKEND / "net" / "kernel.py"

MUTATIONS = {
    "nft mutation": re.compile(r'"nft"\s*,\s*"(?!--version|list|-j)'),
    "nft -f -": re.compile(r'"-f"\s*,\s*"-"'),
    "ip rule/route mutation": re.compile(
        r'"(?:rule|route)"\s*,\s*"(?:add|del|delete|replace|flush|change)"'
    ),
    "ip rule/route mutation (string)": re.compile(
        r"\bip\s+(?:-[46]\s+)?(?:rule|route)\s+(?:add|del|delete|replace|flush|change)\b"
    ),
    "sysctl -w": re.compile(r'"sysctl"\s*,\s*"-w"'),
}
NETLINK = re.compile(r"\b(?:pyroute2|IPRoute|NDB)\b")


def _sources() -> list[Path]:
    return sorted(path for path in BACKEND.rglob("*.py") if "__pycache__" not in path.parts)


def test_only_kernel_py_mutates_kernel_state() -> None:
    offenders = [
        f"{path.relative_to(BACKEND)}: {name}"
        for path in _sources()
        if path != KERNEL
        for name, pattern in MUTATIONS.items()
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_netlink_is_only_used_inside_the_net_package() -> None:
    net_package = BACKEND / "net"
    offenders = [
        str(path.relative_to(BACKEND))
        for path in _sources()
        if net_package not in path.parents and NETLINK.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_the_patterns_actually_match_the_kernel_module() -> None:
    # Guards against the scan silently matching nothing.
    source = KERNEL.read_text(encoding="utf-8")
    assert MUTATIONS["nft -f -"].search(source)
    assert NETLINK.search(source)
