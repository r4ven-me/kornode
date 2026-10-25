from __future__ import annotations

import select
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from kornode.tunnels.argv import DialSpec
from kornode_agent.health import ping_through
from kornode_agent.tunnels import (
    BACKOFF_START,
    DISCONNECT_GRACE,
    UPSTREAM_HEALTH_FAILURES,
    UPSTREAM_HEALTH_INTERVAL,
    TunnelManager,
    TunnelSpec,
    specs_for,
)


class Fake:
    """Runner + converge + links in one place so call order is observable."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[str] = []
        self.codes: list[int] = []
        self.links: set[str] = set()
        self.argvs: list[list[str]] = []
        self.stdin: list[str | None] = []
        self.now = 0.0
        self.procs: list[subprocess.Popen[bytes]] = []

    def converge(self) -> None:
        self.calls.append("converge")

    def link_up(self, iface: str) -> bool:
        return iface in self.links

    def run(self, argv: list[str], *, input_text: str | None, timeout: int, log: Path) -> int:
        self.calls.append("dial")
        self.argvs.append(argv)
        self.stdin.append(input_text)
        code = self.codes.pop(0) if self.codes else 0
        if code == 0:
            pid_file = Path(next(a for a in argv if a.startswith("--pid-file=")).split("=", 1)[1])
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            proc = subprocess.Popen(["sleep", "60"])  # a real, harmless daemon stand-in
            self.procs.append(proc)
            pid_file.write_text(f"{proc.pid}\n")
            self.links.add(argv[argv.index("--interface") + 1])
        return code

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake(tmp_path: Path) -> Iterator[Fake]:
    instance = Fake(tmp_path)
    yield instance
    for proc in instance.procs:
        proc.kill()
        proc.wait()


def _spec(root: Path, *servers: str, password: str | None = None) -> TunnelSpec:
    dials = tuple(
        DialSpec(
            server=server,
            port=443,
            interface="oc-hub0",
            pid_file=root / "run" / "oc-interlink.pid",
            script=root / "run" / "vpnc-script-kornode",
            auth_type="password" if password else "cert",
            password=password,
        )
        for server in servers
    )
    return TunnelSpec("interlink", dials, password=password)


def _manager(fake: Fake, root: Path) -> TunnelManager:
    return TunnelManager(
        root,
        converge=fake.converge,
        link_up=fake.link_up,
        runner=fake,
        resolve=lambda server: ["203.0.113.9"],
        clock=fake.clock,
        sleep=fake.sleep,
        jitter=lambda: 1.0,
    )


def test_killswitch_pass_and_carrier_come_before_the_dial(tmp_path: Path, fake: Fake) -> None:
    manager = _manager(fake, tmp_path)
    manager.set_desired({"interlink": _spec(tmp_path, "hub.example", password="s3cret")})

    manager.tick()

    assert fake.calls[:2] == ["converge", "dial"]
    assert manager.carrier("interlink") == ("203.0.113.9",)
    assert fake.stdin == ["s3cret\n"] and "s3cret" not in " ".join(fake.argvs[0])
    assert manager.is_up("interlink")
    assert (tmp_path / "run" / "vpnc-script-kornode").stat().st_mode & 0o777 == 0o755


def test_failed_dial_backs_off_and_fails_over_to_the_next_hub(tmp_path: Path, fake: Fake) -> None:
    fake.codes = [1, 1, 0]
    manager = _manager(fake, tmp_path)
    manager.set_desired({"interlink": _spec(tmp_path, "hub-a", "hub-b")})

    manager.tick()
    assert "hub-a:443" in fake.argvs[0] and "interlink" in manager.errors
    manager.tick()  # still inside the backoff window: no new dial
    assert len(fake.argvs) == 1

    fake.now += 1.0
    manager.tick()
    assert "hub-b:443" in fake.argvs[1]
    fake.now += 3.0
    manager.tick()
    assert "hub-a:443" in fake.argvs[2] and "interlink" not in manager.errors


def test_changed_spec_restarts_and_suspend_stops_redialing(tmp_path: Path, fake: Fake) -> None:
    manager = _manager(fake, tmp_path)
    manager.set_desired({"interlink": _spec(tmp_path, "hub-a")})
    manager.tick()
    assert manager.is_up("interlink")

    manager.suspend("interlink")
    manager.tick()
    assert len(fake.argvs) == 1  # a revoked node does not hammer the hub

    manager.set_desired({})
    assert manager.carrier("interlink") == () and not manager.is_up("interlink")


class HealthFake(Fake):
    """Deterministic PIDs and nonpersistent TUNs; never signal a real process."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.live: dict[int, str] = {}
        self.signals: list[tuple[int, int]] = []
        self.probes: list[tuple[str, str]] = []
        self.results: list[bool] = []
        self.reachable = False
        self.last_pid = 10000

    def run(self, argv: list[str], *, input_text: str | None, timeout: int, log: Path) -> int:
        self.calls.append("dial")
        self.argvs.append(argv)
        self.stdin.append(input_text)
        code = self.codes.pop(0) if self.codes else 0
        if code == 0:
            pid_file = Path(next(a for a in argv if a.startswith("--pid-file=")).split("=", 1)[1])
            interface = argv[argv.index("--interface") + 1]
            self.last_pid += 1
            self.live[self.last_pid] = interface
            self.links.add(interface)
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            pid_file.write_text(f"{self.last_pid}\n")
        return code

    def alive(self, pid: int) -> bool:
        return pid in self.live

    def kill(self, pid: int, sig: int) -> None:
        assert pid in self.live, "attempted to signal an unowned simulated process"
        self.signals.append((pid, sig))
        interface = self.live.pop(pid)
        self.links.discard(interface)
        self.calls.append(f"stop:{interface}")

    def probe(self, interface: str, host: str) -> bool:
        self.probes.append((interface, host))
        self.calls.append(f"probe:{interface}")
        return self.results.pop(0) if self.results else self.reachable


def _upstream(root: Path, name: str = "office", check_host: str | None = "10.60.0.1") -> TunnelSpec:
    base = _spec(root, f"{name}.example", password="upstream-password")
    dial = replace(base.dials[0], interface=f"oc-{name}", pid_file=root / "run" / f"oc-{name}.pid")
    return replace(base, exit_name=f"upstream:{name}", dials=(dial,), check_host=check_host)


def _health_manager(fake: HealthFake, monkeypatch: pytest.MonkeyPatch) -> TunnelManager:
    manager = TunnelManager(
        fake.root,
        converge=fake.converge,
        link_up=fake.link_up,
        runner=fake,
        resolve=lambda server: ["203.0.113.9"],
        clock=fake.clock,
        sleep=fake.sleep,
        jitter=lambda: 1.0,
        probe=fake.probe,
    )
    monkeypatch.setattr(manager, "_alive", fake.alive)
    monkeypatch.setattr("kornode_agent.tunnels.os.kill", fake.kill)
    return manager


def _health_tick(manager: TunnelManager, fake: HealthFake) -> None:
    fake.now += UPSTREAM_HEALTH_INTERVAL
    manager.tick()


def test_three_spaced_failures_stop_reconcile_then_redial_only_the_bad_upstream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    office = _upstream(tmp_path)
    backup = _upstream(tmp_path, "backup", check_host=None)
    manager.set_desired(
        {"interlink": _spec(tmp_path, "hub"), "upstream:office": office, "upstream:backup": backup}
    )
    manager.tick()
    original_pids = dict(fake.live)
    hub_pid = next(pid for pid, interface in fake.live.items() if interface == "oc-hub0")
    hub_attached = manager.attached["interlink"]
    fake.now = UPSTREAM_HEALTH_INTERVAL - 0.01
    manager.tick()
    assert not fake.probes  # first successful dial gets a full health interval
    for attempt in range(1, UPSTREAM_HEALTH_FAILURES):
        fake.now = attempt * UPSTREAM_HEALTH_INTERVAL
        manager.tick()
        assert not fake.signals and len(fake.argvs) == 3
        manager.tick()  # a fast run loop must not count the same interval twice
        assert len(fake.probes) == attempt
    fake.calls.clear()
    fake.now = UPSTREAM_HEALTH_FAILURES * UPSTREAM_HEALTH_INTERVAL
    manager.tick()
    assert fake.calls == ["probe:oc-office", "stop:oc-office", "converge"]
    assert manager.errors["upstream:office"] == "upstream health check failed"
    assert not manager.is_up("upstream:office")
    assert manager.is_up("interlink") and manager.is_up("upstream:backup")
    assert manager.attached["interlink"] == hub_attached
    assert manager.carrier("upstream:office") == ("203.0.113.9",)
    assert fake.live[hub_pid] == "oc-hub0"
    assert len(fake.signals) == 1 and fake.signals[0][1] == signal.SIGTERM
    assert len(fake.argvs) == 3
    assert "upstream:office" not in manager._health_failures
    assert "upstream:office" not in manager._health_next
    fake.calls.clear()
    manager.tick()
    assert not fake.calls  # a reset never redials within the same tick/backoff window
    fake.now += BACKOFF_START
    manager.tick()
    assert fake.calls == ["converge", "dial", "converge"]
    assert manager.is_up("upstream:office")
    assert "upstream:office" not in manager.errors
    assert set(original_pids) - set(fake.live) == {fake.signals[0][0]}
    assert all(interface == "oc-office" for interface, _ in fake.probes)
    assert "upstream-password" not in repr(manager.errors) + caplog.text
    assert all("upstream-password" not in " ".join(argv) for argv in fake.argvs)
    assert fake.stdin[-1] == "upstream-password\n"


def test_health_success_breaks_the_failure_streak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = HealthFake(tmp_path)
    fake.results = [False, False, True, False, False, False]
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired({"upstream:office": _upstream(tmp_path)})
    manager.tick()
    for _ in range(5):
        _health_tick(manager, fake)
        assert not fake.signals
    _health_tick(manager, fake)
    assert len(fake.signals) == 1
    assert len(fake.probes) == 6


def test_health_interval_starts_after_a_slow_probe_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired({"upstream:office": _upstream(tmp_path)})
    manager.tick()

    def slow_probe(interface: str, host: str) -> bool:
        fake.now += 10  # exercise the actual probe's maximum subprocess timeout
        return fake.probe(interface, host)

    manager.probe = slow_probe
    for failure in range(1, UPSTREAM_HEALTH_FAILURES):
        _health_tick(manager, fake)
        assert manager._health_failures["upstream:office"] == failure
        assert manager._health_next["upstream:office"] == fake.now + UPSTREAM_HEALTH_INTERVAL
        manager.tick()
        assert len(fake.probes) == failure  # no catch-up/burst probes after a timeout
    _health_tick(manager, fake)
    assert len(fake.signals) == 1


def test_failed_redials_after_a_health_reset_use_existing_exponential_backoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired({"upstream:office": _upstream(tmp_path)})
    manager.tick()
    for _ in range(UPSTREAM_HEALTH_FAILURES):
        _health_tick(manager, fake)
    assert not fake.live
    fake.codes = [1, 1, 0]
    fake.now += BACKOFF_START
    manager.tick()
    assert len(fake.argvs) == 2 and manager._backoff["upstream:office"] == 1
    manager.tick()
    assert len(fake.argvs) == 2
    fake.now += 1
    manager.tick()
    assert len(fake.argvs) == 3 and manager._backoff["upstream:office"] == 2
    fake.now += 1
    manager.tick()
    assert len(fake.argvs) == 3
    fake.now += 1
    manager.tick()
    assert len(fake.argvs) == 4 and manager.is_up("upstream:office")
    assert "upstream:office" not in manager.errors
    assert "upstream:office" not in manager._backoff
    assert "upstream:office" not in manager._health_failures


def test_missing_interface_counts_failures_without_attempting_a_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired({"upstream:office": _upstream(tmp_path)})
    manager.tick()
    fake.links.clear()  # PID still exists, but the TUN is no longer usable
    for _ in range(UPSTREAM_HEALTH_FAILURES):
        _health_tick(manager, fake)
    assert not fake.probes
    assert len(fake.signals) == 1 and not fake.live
    assert fake.calls[-1] == "converge"


def test_interlink_and_unmonitored_upstreams_are_never_health_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired(
        {
            "interlink": replace(_spec(tmp_path, "hub"), check_host="10.99.0.1"),
            "upstream:office": _upstream(tmp_path, check_host=None),
        }
    )
    manager.tick()
    pids = dict(fake.live)
    for _ in range(10):
        _health_tick(manager, fake)
    assert fake.live == pids and not fake.probes and not fake.signals
    assert len(fake.argvs) == 2


@pytest.mark.parametrize("change", ["replace", "remove", "suspend", "reconnect", "stop_all"])
def test_desired_state_changes_and_commands_clear_old_health_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    spec = _upstream(tmp_path)
    manager.set_desired({"upstream:office": spec})
    manager.tick()
    for _ in range(2):
        _health_tick(manager, fake)
    assert manager._health_failures["upstream:office"] == 2
    if change == "replace":
        manager.set_desired({"upstream:office": replace(spec, check_host="10.60.0.2")})
    elif change == "remove":
        manager.set_desired({})
    elif change == "suspend":
        manager.suspend("upstream:office")
    elif change == "reconnect":
        assert manager.reconnect("upstream:office")
    else:
        manager.stop_all()
    assert "upstream:office" not in manager._health_failures
    if change != "reconnect":
        assert "upstream:office" not in manager._health_next
    else:
        assert manager._health_next["upstream:office"] == fake.now + UPSTREAM_HEALTH_INTERVAL
    if change in {"remove", "suspend"}:
        dial_count = len(fake.argvs)
        _health_tick(manager, fake)
        assert len(fake.argvs) == dial_count


def test_failed_reconciliation_never_allows_a_replacement_dial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired({"upstream:office": _upstream(tmp_path)})
    manager.tick()
    for _ in range(2):
        _health_tick(manager, fake)

    def fail() -> None:
        fake.calls.append("failed-converge")
        raise RuntimeError("reconciler unavailable")

    manager.converge = fail
    with pytest.raises(RuntimeError, match="reconciler unavailable"):
        _health_tick(manager, fake)
    assert not fake.live
    fake.now += BACKOFF_START
    manager.tick()  # _connect must also converge successfully before invoking the runner
    assert len(fake.argvs) == 1
    assert "reconciler unavailable" in manager.errors["upstream:office"]
    manager.converge = fake.converge
    fake.now += 60
    manager.tick()
    assert fake.calls[-3:] == ["converge", "dial", "converge"]
    assert manager.is_up("upstream:office")


@pytest.mark.parametrize("failure", ["timeout", "oserror", "nonzero"])
def test_default_health_probe_is_interface_bound_bounded_and_does_not_log_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: str,
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    manager.probe = ping_through
    manager.set_desired({"upstream:office": _upstream(tmp_path)})
    manager.tick()
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        assert argv == ["ping", "-I", "oc-office", "-c", "2", "-i", "0.3", "-W", "2", "10.60.0.1"]
        assert kwargs == {"capture_output": True, "timeout": 10, "check": False}
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, 10, output=b"private-probe-output")
        if failure == "oserror":
            raise OSError("private-probe-output")
        return subprocess.CompletedProcess(
            argv, 1, b"private-probe-output", b"private-probe-output"
        )

    monkeypatch.setattr("kornode_agent.health.subprocess.run", run)
    for _ in range(UPSTREAM_HEALTH_FAILURES):
        _health_tick(manager, fake)
    assert len(calls) == UPSTREAM_HEALTH_FAILURES
    assert len(fake.signals) == 1
    assert "private-probe-output" not in caplog.text + repr(manager.errors)


def test_health_reset_on_cached_bundle_removes_unicast_and_keeps_unreachable_before_redial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_agent_apply import World
    from tests.test_agent_inputs import CONFIG, FakeProbes
    from tests.test_net_reconciler import FakeKernel

    from kornode.net.reconciler import Reconciler
    from kornode_agent.inputs import AgentNetInputs
    from kornode_agent.store import State

    world = World(tmp_path)
    body, signature = world.bundle(5)
    world.store.write_bundle(5, body, signature)
    world.store.save_state(State(current=5, confirmed=[5], high_water=5))
    cached = world.restart().active
    assert cached is not None
    fake = HealthFake(tmp_path)
    old_manager = _health_manager(fake, monkeypatch)
    specs = specs_for(cached, CONFIG, tmp_path)
    old_manager.set_desired(specs)
    old_manager.tick()
    pid_map = dict(fake.live)
    # A restarted daemon adopts existing cached-bundle processes without dialing again.
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired(specs)
    probes = FakeProbes({})
    inputs = AgentNetInputs(CONFIG, probes, manager)
    inputs.set_bundle(cached)
    kernel = FakeKernel()
    reconciler = Reconciler(inputs.desired, kernel)

    def converge() -> None:
        fake.calls.append("converge")
        probes._links = {interface: True for interface in fake.links}
        reconciler.run_once()
        assert reconciler.status()["last_error"] is None

    manager.converge = converge
    converge()
    upstream_routes = [route for route in kernel.state.routes if route.dev == "oc-office"]
    assert upstream_routes and any(route.dst == "default" for route in upstream_routes)
    table = next(route.table for route in upstream_routes if route.dst == "default")
    interlink_routes = {route for route in kernel.state.routes if route.dev == "oc-hub0"}
    manager.tick()  # adopted PID has no grace timer: begin checking it immediately
    assert not fake.signals and len(fake.argvs) == 2
    for _ in range(UPSTREAM_HEALTH_FAILURES - 1):
        _health_tick(manager, fake)
    assert len(fake.signals) == 1 and len(fake.argvs) == 2
    assert not any(route.dev == "oc-office" for route in kernel.state.routes)
    assert any(
        route.table == table and route.dst == "default" and route.type == "unreachable"
        for route in kernel.state.routes
    )
    assert interlink_routes <= kernel.state.routes
    assert manager.is_up("interlink")
    assert fake.signals[0][0] in pid_map
    fake.now += BACKOFF_START
    manager.tick()
    assert any(
        route.table == table and route.dev == "oc-office" and route.type == "unicast"
        for route in kernel.state.routes
    )
    assert manager.is_up("interlink")
    saved = world.store.read_bundle(5)
    assert saved is not None and (saved.body, saved.signature) == (body, signature)


def test_reconciliation_under_manager_lock_does_not_deadlock_a_parallel_reconciler_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_net_reconciler import FakeKernel

    from kornode.net.reconciler import Reconciler
    from kornode.net.state import DesiredState

    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired({"upstream:office": _upstream(tmp_path)})
    manager.tick()
    for _ in range(2):
        _health_tick(manager, fake)
    provider_entered, read_snapshots, reset_entered = (threading.Event() for _ in range(3))
    errors: list[BaseException] = []

    def provider() -> DesiredState:
        provider_entered.set()
        assert read_snapshots.wait(2)
        assert "upstream:office" in manager.specs()
        assert manager.carrier("upstream:office") == ("203.0.113.9",)
        return DesiredState()

    reconciler = Reconciler(provider, FakeKernel())

    def converge() -> None:
        reset_entered.set()
        reconciler.run_once()
        assert reconciler.status()["last_error"] is None

    manager.converge = converge

    def run(action: Callable[[], object]) -> None:
        try:
            action()
        except BaseException as exc:
            errors.append(exc)

    other = threading.Thread(target=run, args=(reconciler.run_once,), daemon=True)
    reset = threading.Thread(target=run, args=(lambda: _health_tick(manager, fake),), daemon=True)
    try:
        other.start()
        assert provider_entered.wait(2)  # the other thread now owns the reconciler lock
        reset.start()
        assert reset_entered.wait(2)  # tick owns the manager lock and waits for the reconciler
        read_snapshots.set()  # provider must not acquire the manager lock to finish
        other.join(2)
        reset.join(2)
        assert not other.is_alive() and not reset.is_alive()
        assert not errors
    finally:
        read_snapshots.set()
        other.join(2)
        if reset.ident is not None:
            reset.join(2)


def test_stop_all_serializes_with_an_inflight_probe_without_blocking_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = HealthFake(tmp_path)
    manager = _health_manager(fake, monkeypatch)
    manager.set_desired({"upstream:office": _upstream(tmp_path)})
    manager.tick()
    entered, release, stopped = (threading.Event() for _ in range(3))
    errors: list[BaseException] = []

    def probe(interface: str, host: str) -> bool:
        entered.set()
        assert release.wait(2)
        return False

    manager.probe = probe

    def tick() -> None:
        try:
            _health_tick(manager, fake)
        except BaseException as exc:
            errors.append(exc)

    def stop() -> None:
        try:
            manager.stop_all()
        except BaseException as exc:
            errors.append(exc)
        finally:
            stopped.set()

    worker = threading.Thread(target=tick, daemon=True)
    stopper = threading.Thread(target=stop, daemon=True)
    try:
        worker.start()
        assert entered.wait(2)
        stopper.start()
        assert not stopped.wait(0.05)
        assert manager.is_up("upstream:office")
        assert manager.specs() and manager.carrier("upstream:office")
    finally:
        release.set()
        worker.join(2)
        if stopper.ident is not None:
            stopper.join(2)
    assert not worker.is_alive() and not stopper.is_alive() and not errors
    assert not fake.live and not manager._health_failures and not manager._health_next


def test_stop_escalates_term_to_kill_with_bounded_grace_and_clears_health_state(
    tmp_path: Path, fake: Fake, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    spec = _upstream(tmp_path)
    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready'); time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
    )
    fake.procs.append(process)
    assert process.stdout is not None
    assert select.select([process.stdout], [], [], 2)[0]
    assert process.stdout.readline() == b"ready\n"
    pid_file = spec.dials[0].pid_file
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(process.pid))
    manager = _manager(fake, tmp_path)
    manager.set_desired({"upstream:office": spec})
    manager.attached["upstream:office"] = fake.now
    manager._health_next["upstream:office"] = 5
    manager._health_failures["upstream:office"] = 2
    signals: list[int] = []
    original_kill = os.kill

    def kill(pid: int, sig: int) -> None:
        if sig:
            assert pid == process.pid
            signals.append(sig)
        original_kill(pid, sig)

    monkeypatch.setattr("kornode_agent.tunnels.os.kill", kill)
    manager.stop_all()
    assert process.wait(timeout=2) == -signal.SIGKILL
    process.stdout.close()
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert DISCONNECT_GRACE <= fake.now <= DISCONNECT_GRACE + 0.2
    assert not manager.attached and not manager._health_failures and not manager._health_next
