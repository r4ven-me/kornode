"""Supervised helper programs of the agent (dnsmasq, ocserv; D-66, D-67).

Each program has `autostart=false` in the supervisor configuration; the agent
writes its files from the active bundle and starts, restarts or stops it. A
`Converger` applies the desired state off the bundle activation path and
retries failures, so a slow or broken supervisor never delays a switch and a
failure is never final. Failures are surfaced as doctor findings, never as a
rollback: these programs serve clients, they are not the fabric.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Callable

log = logging.getLogger("kornode_agent.programs")

SUPERVISORCTL = ("supervisorctl", "-c", "/etc/supervisor/conf.d/kornode-agent.conf")

UNSET = object()


def supervisorctl(program: str, action: str) -> bool:
    try:
        result = subprocess.run(
            [*SUPERVISORCTL, action, program],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("supervisorctl %s %s: %s", action, program, type(exc).__name__)
        return False
    output = result.stdout + result.stderr
    # `stop` of a stopped program reports "not running" with a non-zero code.
    if result.returncode == 0 or (action == "stop" and "not running" in output):
        return True
    log.warning("supervisorctl %s %s: %s", action, program, output.strip()[:200])
    return False


class Converger[T]:
    """`submit` records the desired state; a worker thread applies it with
    `apply_content` (one attempt, True on success) and retries until it
    succeeds or a newer state arrives."""

    def __init__(self, retry_seconds: float) -> None:
        self.retry_seconds = retry_seconds
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._desired: T | None = None
        self._worker: threading.Thread | None = None
        self.error: str | None = None

    def submit_content(self, desired: T | None) -> None:
        with self._lock:
            self._desired = desired
            if self._worker is None:
                self._worker = threading.Thread(
                    target=self._run, name=type(self).__name__, daemon=True
                )
                self._worker.start()
        self._wake.set()

    def _run(self) -> None:
        while True:
            self._wake.clear()
            with self._lock:
                desired = self._desired
            if not self.apply_content(desired):
                self._wake.wait(self.retry_seconds)
                continue
            with self._lock:
                if self._desired == desired:
                    self._worker = None
                    return

    def apply_content(self, desired: T | None) -> bool:
        raise NotImplementedError

    def failed(self, message: str) -> bool:
        self.error = message
        log.warning("%s: %s", type(self).__name__, message)
        return False


ControlFn = Callable[[str], bool]
