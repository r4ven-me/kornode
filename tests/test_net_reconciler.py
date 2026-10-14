from __future__ import annotations

import os
import stat
import threading
import time
from pathlib import Path

import pytest

from kornode.net.diff import Plan, apply_to_state
from kornode.net.errors import ApplyError, PolicyError
from kornode.net.reconciler import (
    BACKOFF_MAX,
    Reconciler,
    control_request,
    serve_control,
)
from kornode.net.state import ActualState, DesiredState, IpRule, Route, Sysctl

RULE = IpRule(priority=101, table=12001, fwmark=0x0C000100, fwmask=0xFFFFFF00)
ROUTE = Route(table=12001, dst="default", type="unreachable", metric=4096)
DESIRED = DesiredState(
    sysctls=frozenset({Sysctl("net.ipv4.ip_forward", "1")}),
    rules=frozenset({RULE}),
    routes=frozenset({ROUTE}),
)


class FakeKernel:
    def __init__(self) -> None:
        self.state = ActualState()
        self.applied: list[Plan] = []
        self.fail = False

    def read(
        self, sysctl_keys: list[str], foreign_chains: object = (), address_devs: object = ()
    ) -> ActualState:
        return self.state

    def apply(self, plan: Plan) -> None:
        if self.fail:
            raise ApplyError("boom")
        self.applied.append(plan)
        self.state = apply_to_state(self.state, plan)


def test_run_once_converges_and_then_does_nothing() -> None:
    kernel = FakeKernel()
    reconciler = Reconciler(lambda: DESIRED, kernel)

    first = reconciler.run_once()
    second = reconciler.run_once()

    assert len(first.ops) == 3
    assert second.is_empty
    assert len(kernel.applied) == 1
    status = reconciler.status()
    assert status["passes"] == 2 and status["last_plan_size"] == 0
    assert status["drift"] == {}


def test_kernel_drift_is_counted_but_input_changes_are_not() -> None:
    kernel = FakeKernel()
    desired = [DESIRED]
    reconciler = Reconciler(lambda: desired[0], kernel)
    reconciler.run_once()

    # Someone deletes our route: drift.
    kernel.state = ActualState(
        sysctls=kernel.state.sysctls, rules=kernel.state.rules, routes=frozenset()
    )
    reconciler.run_once()
    assert reconciler.status()["drift"] == {"ReplaceRoute": 1}

    # Our own inputs change: not drift.
    desired[0] = DesiredState(sysctls=DESIRED.sysctls, rules=DESIRED.rules)
    reconciler.run_once()
    assert reconciler.status()["drift"] == {"ReplaceRoute": 1}


def test_errors_back_off_exponentially_and_recover() -> None:
    kernel = FakeKernel()
    kernel.fail = True
    reconciler = Reconciler(lambda: DESIRED, kernel)

    delays = []
    for _ in range(7):
        reconciler.run_once()
        delays.append(reconciler._backoff)

    assert delays == [1.0, 2.0, 4.0, 8.0, 16.0, BACKOFF_MAX, BACKOFF_MAX]
    status = reconciler.status()
    assert status["consecutive_errors"] == 7
    assert status["last_error"] == "ApplyError: boom"

    kernel.fail = False
    reconciler.run_once()
    assert reconciler._backoff == 0.0
    assert reconciler.status()["last_error"] is None


def test_invalid_inputs_are_an_error_not_a_crash() -> None:
    def provider() -> DesiredState:
        raise PolicyError("unknown upstream 'office'")

    reconciler = Reconciler(provider, FakeKernel())

    assert reconciler.run_once().is_empty
    assert reconciler.status()["last_error"] == "PolicyError: unknown upstream 'office'"


def test_any_failure_in_a_pass_is_an_error_not_a_dead_loop() -> None:
    # e.g. pyroute2's NetlinkError on read, or a YAML error in the provider:
    # neither is a NetError/OSError/ValueError.
    class NetlinkLike(Exception):
        pass

    def provider() -> DesiredState:
        raise NetlinkLike("(16, 'Device or resource busy')")

    reconciler = Reconciler(provider, FakeKernel())

    assert reconciler.run_once().is_empty
    assert reconciler.status()["last_error"] == "NetlinkLike: (16, 'Device or resource busy')"
    assert reconciler.status()["consecutive_errors"] == 1


def _start(reconciler: Reconciler) -> threading.Thread:
    thread = threading.Thread(target=reconciler.run_forever, daemon=True)
    thread.start()
    return thread


def _wait_for(predicate: object, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():  # type: ignore[operator]
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")


def test_loop_passes_at_start_and_debounces_a_burst_of_wakes() -> None:
    kernel = FakeKernel()
    reconciler = Reconciler(lambda: DESIRED, kernel, debounce=0.2, timer=60)
    thread = _start(reconciler)
    try:
        _wait_for(lambda: reconciler.status()["passes"] == 1)
        for _ in range(10):
            reconciler.wake()
            time.sleep(0.01)
        _wait_for(lambda: reconciler.status()["passes"] >= 2)
        time.sleep(0.4)
        assert reconciler.status()["passes"] == 2
    finally:
        reconciler.stop()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_timer_triggers_full_passes() -> None:
    reconciler = Reconciler(lambda: DESIRED, FakeKernel(), debounce=0.0, timer=0.05)
    thread = _start(reconciler)
    try:
        _wait_for(lambda: reconciler.status()["passes"] >= 4)
    finally:
        reconciler.stop()
        thread.join(timeout=2)


def test_control_socket_wake_and_status(tmp_path: Path) -> None:
    kernel = FakeKernel()
    reconciler = Reconciler(lambda: DESIRED, kernel, debounce=0.0, timer=60)
    path = tmp_path / "reconciler.sock"
    server = serve_control(reconciler, path)
    thread = _start(reconciler)
    try:
        _wait_for(lambda: reconciler.status()["passes"] == 1)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

        assert control_request(path, "wake") == {"ok": True}
        _wait_for(lambda: reconciler.status()["passes"] == 2)
        reply = control_request(path, "status")
        assert reply["ok"] and reply["status"]["passes"] == 2
        assert control_request(path, "explode") == {"ok": False, "error": "unknown op 'explode'"}
    finally:
        reconciler.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("stale", [True, False])
def test_serve_control_replaces_a_stale_socket(tmp_path: Path, stale: bool) -> None:
    path = tmp_path / "reconciler.sock"
    if stale:
        path.write_text("left over", encoding="utf-8")
    server = serve_control(Reconciler(lambda: DESIRED, FakeKernel()), path)
    try:
        assert control_request(path, "status")["ok"]
    finally:
        server.shutdown()
        server.server_close()


def test_control_socket_apply_is_synchronous(tmp_path: Path) -> None:
    kernel = FakeKernel()
    reconciler = Reconciler(lambda: DESIRED, kernel)
    path = tmp_path / "reconciler.sock"
    server = serve_control(reconciler, path)
    try:
        reply = control_request(path, "apply")

        # No run_forever loop: the pass happened inside the request.
        assert reply["ok"] and reply["ops"] == 3
        assert reply["status"]["passes"] == 1 and reply["status"]["last_error"] is None
        assert kernel.state.rules == {RULE}
    finally:
        server.shutdown()
        server.server_close()
