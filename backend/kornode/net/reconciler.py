"""The reconciler loop (docs/spec/04-netcore-reconciler.md).

One pass: desired = provider(); actual = kernel.read(); apply diff. Passes
are triggered by wake() (inputs changed / control socket), netlink events
(links, addresses, rules, routes) and a periodic timer; triggers are
debounced and passes never overlap. Errors back off exponentially and keep
the last good kernel state (nothing is rolled back -- the next pass diffs
from whatever is really there).
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import socket
import socketserver
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from kornode.net.diff import Plan, diff
from kornode.net.errors import NetError
from kornode.net.state import ActualState, DesiredState

DEBOUNCE_SECONDS = 0.2
TIMER_SECONDS = 10.0
BACKOFF_START = 1.0
BACKOFF_MAX = 30.0


class KernelLike(Protocol):
    def read(self, sysctl_keys: list[str]) -> ActualState: ...

    def apply(self, plan: Plan) -> None: ...


@dataclass(slots=True)
class ReconcilerStatus:
    passes: int = 0
    last_pass_at: float | None = None
    last_apply_at: float | None = None
    last_plan_size: int = 0
    last_error: str | None = None
    consecutive_errors: int = 0
    drift: Counter[str] = field(default_factory=Counter)
    schema_hash: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "passes": self.passes,
            "last_pass_at": self.last_pass_at,
            "last_apply_at": self.last_apply_at,
            "last_plan_size": self.last_plan_size,
            "last_error": self.last_error,
            "consecutive_errors": self.consecutive_errors,
            "drift": dict(self.drift),
            "schema_hash": self.schema_hash,
        }


class Reconciler:
    def __init__(
        self,
        provider: Callable[[], DesiredState],
        kernel: KernelLike,
        *,
        debounce: float = DEBOUNCE_SECONDS,
        timer: float = TIMER_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.provider = provider
        self.kernel = kernel
        self.debounce = debounce
        self.timer = timer
        self.clock = clock
        self.wall_clock = wall_clock
        self._status = ReconcilerStatus()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()  # single flight
        self._last_desired: DesiredState | None = None
        self._backoff = 0.0

    # -- triggers -----------------------------------------------------------

    def wake(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return self._status.as_dict()

    # -- one pass -----------------------------------------------------------

    def run_once(self) -> Plan:
        """One full read + diff + apply. Raises nothing: failures are
        recorded in status and drive the backoff."""
        with self._lock:
            status = self._status
            status.passes += 1
            status.last_pass_at = self.wall_clock()
            try:
                desired = self.provider()
                keys = sorted(sysctl.key for sysctl in desired.sysctls)
                plan = diff(self.kernel.read(keys), desired)
                if not plan.is_empty:
                    if desired == self._last_desired:
                        # Inputs unchanged, kernel differs: someone else
                        # changed kernel state (or a link bounced).
                        status.drift.update(type(op).__name__ for op in plan.ops)
                    self.kernel.apply(plan)
                    status.last_apply_at = self.wall_clock()
                status.last_plan_size = len(plan.ops)
                status.schema_hash = desired.nft.schema_hash if desired.nft else None
                self._last_desired = desired
                status.last_error = None
                status.consecutive_errors = 0
                self._backoff = 0.0
                return plan
            except (NetError, OSError, ValueError) as exc:
                status.last_error = f"{type(exc).__name__}: {exc}"
                status.consecutive_errors += 1
                self._backoff = min(
                    BACKOFF_MAX, BACKOFF_START if not self._backoff else self._backoff * 2
                )
                return Plan()

    # -- loop ---------------------------------------------------------------

    def run_forever(self) -> None:
        """Pass immediately, then on every trigger (debounced), on the timer,
        or after the backoff delay following a failure."""
        next_timer = self.clock()
        while not self._stop.is_set():
            now = self.clock()
            timeout = self._backoff or max(0.0, next_timer - now)
            woken = self._wake.wait(timeout)
            if self._stop.is_set():
                return
            if woken:
                # Debounce: let a burst of events settle into one pass.
                time.sleep(self.debounce)
                self._wake.clear()
            self.run_once()
            next_timer = self.clock() + self.timer


def watch_netlink(reconciler: Reconciler, stop: threading.Event) -> None:
    """Wake the reconciler on link/address/rule/route changes. Runs until
    `stop` is set; meant for a daemon thread."""
    from pyroute2 import IPRoute  # type: ignore[import-untyped]
    from pyroute2.netlink.rtnl import (  # type: ignore[import-untyped]
        RTMGRP_IPV4_IFADDR,
        RTMGRP_IPV4_ROUTE,
        RTMGRP_IPV4_RULE,
        RTMGRP_IPV6_IFADDR,
        RTMGRP_IPV6_ROUTE,
        RTMGRP_LINK,
    )

    groups = (
        RTMGRP_LINK
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV6_IFADDR
        | RTMGRP_IPV4_ROUTE
        | RTMGRP_IPV6_ROUTE
        | RTMGRP_IPV4_RULE
    )
    with IPRoute() as ipr:
        ipr.bind(groups=groups)
        while not stop.is_set():
            # select() with a timeout so the thread notices `stop`; get()
            # only once there is something to read (it blocks otherwise).
            ready, _, _ = select.select([ipr], [], [], 0.5)
            if not ready:
                continue
            if ipr.get():
                reconciler.wake()


class _ControlHandler(socketserver.StreamRequestHandler):
    server: _ControlServer

    def handle(self) -> None:
        try:
            request = json.loads(self.rfile.readline(4096) or b"{}")
            op = request.get("op")
            if op == "wake":
                self.server.reconciler.wake()
                reply: dict[str, Any] = {"ok": True}
            elif op == "status":
                reply = {"ok": True, "status": self.server.reconciler.status()}
            else:
                reply = {"ok": False, "error": f"unknown op {op!r}"}
        except (ValueError, AttributeError) as exc:
            reply = {"ok": False, "error": str(exc)}
        self.wfile.write(json.dumps(reply).encode("utf-8") + b"\n")


class _ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, reconciler: Reconciler) -> None:
        self.reconciler = reconciler
        super().__init__(path, _ControlHandler)


def serve_control(reconciler: Reconciler, path: Path) -> _ControlServer:
    """Unix socket `{"op": "wake"}` / `{"op": "status"}` (one JSON line in,
    one out). Owner-only permissions: only root/the service may poke it."""
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    server = _ControlServer(str(path), reconciler)
    os.chmod(path, 0o600)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def control_request(path: Path, op: str, *, timeout: float = 5.0) -> dict[str, Any]:
    """Client side of the control socket (used by `korctl net apply`/API)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(path))
        sock.sendall(json.dumps({"op": op}).encode("utf-8") + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    reply: dict[str, Any] = json.loads(data or b"{}")
    return reply
