"""Health checks for apply-with-confirm and reports (spec 06 "Health window")."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Protocol

from kornode.bundle.validator import Validated


class TunnelView(Protocol):
    def is_up(self, exit_name: str) -> bool: ...


def ping_through(interface: str, host: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-I", interface, "-c", "2", "-i", "0.3", "-W", "2", host],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


class AgentHealth:
    """`interlink` = tunnel up and an mTLS ping to the hub succeeds; `upstream:<name>` =
    tunnel up and, when set, `check_host` reachable through it."""

    def __init__(
        self,
        tunnels: TunnelView,
        hub_ping: Callable[[], bool],
        probe: Callable[[str, str], bool] = ping_through,
    ) -> None:
        self.tunnels = tunnels
        self.hub_ping = hub_ping
        self.probe = probe

    def checks(self, active: Validated | None) -> dict[str, bool]:
        results = {"interlink": self.tunnels.is_up("interlink") and self.hub_ping()}
        if active is None:
            return results
        for upstream in active.bundle.tunnels.upstreams:
            if not upstream.enabled:
                continue
            name = f"upstream:{upstream.name}"
            up = self.tunnels.is_up(name)
            if up and upstream.check_host:
                up = self.probe(upstream.interface, upstream.check_host)
            results[name] = up
        return results
