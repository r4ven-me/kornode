"""Fabric and upstream openconnect sessions of the agent (spec 06 "Tunnels").

Dialing pieces (argv, carrier, vpnc-script) are the shared ``kornode.tunnels``;
this module owns the lifecycle: ordering (carrier exemption and a reconciler
pass *before* the dial, so the kill-switch is in place), backoff with jitter,
liveness. It never touches routes or nft: that is the reconciler's alone.
"""

from __future__ import annotations

import contextlib
import functools
import os
import random
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from kornode.bundle.validator import Validated
from kornode.tunnels import vpnc_script_source
from kornode.tunnels.argv import DialSpec, config_lines, openconnect_argv
from kornode.tunnels.carrier import resolve_carrier_addresses
from kornode_agent.config import AgentConfig
from kornode_agent.store import atomic_write

BACKOFF_START = 1.0
BACKOFF_MAX = 60.0
DIAL_TIMEOUT = 60
BACKGROUND_GRACE = 5.0
DISCONNECT_GRACE = 5.0


def _locked[F: Callable[..., Any]](method: F) -> F:
    """tick (its own thread), the applier and commands all mutate tunnels."""

    @functools.wraps(method)
    def wrapper(self: TunnelManager, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]


class Runner(Protocol):
    def run(self, argv: list[str], *, input_text: str | None, timeout: int, log: Path) -> int: ...


class SubprocessRunner:
    def run(self, argv: list[str], *, input_text: str | None, timeout: int, log: Path) -> int:
        log.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(log, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "ab") as handle:
                result = subprocess.run(  # noqa: S603 - explicit argv, no shell
                    argv,
                    input=(input_text or "").encode() if input_text is not None else None,
                    stdout=handle,
                    stderr=handle,
                    timeout=timeout,
                    check=False,
                )
        except (OSError, subprocess.SubprocessError):
            return 1
        return result.returncode


@dataclass(frozen=True)
class TunnelSpec:
    exit_name: str  # "fabric" or "upstream:<name>"
    dials: tuple[DialSpec, ...]  # failover order; fabric: the bundle's hubs
    password: str | None = field(default=None, repr=False)
    check_host: str | None = None
    files: tuple[tuple[Path, bytes], ...] = field(
        default=(), repr=False
    )  # credentials materialized before dialing

    @property
    def interface(self) -> str:
        return self.dials[0].interface


def specs_for(
    validated: Validated | None, config: AgentConfig, root: Path
) -> dict[str, TunnelSpec]:
    """Tunnels the agent keeps up for `validated` (None = bootstrap)."""
    run = root / "run"
    script = run / "vpnc-script-kornode"
    tls = root / "tls"
    fabric = config.fabric
    camouflage = config.hub.camouflage
    interface = fabric.interface
    if validated:
        bundle = validated.bundle
        fabric_cfg = bundle.tunnels.fabric
        interface = fabric_cfg.interface
        camouflage = validated.secrets.get("/tunnels/fabric/camouflage", camouflage)
        transport = fabric_cfg.transport
        pins = [(hub.host, hub.port, hub.pin) for hub in bundle.hubs]
    else:
        transport = fabric.transport
        pins = [(config.hub.host, config.hub.port, config.hub.pin)]
    dials = tuple(
        DialSpec(
            server=host,
            port=port,
            interface=interface,
            pid_file=run / "oc-fabric.pid",
            script=script,
            auth_type="cert",
            cert_path=tls / "cert.pem",
            key_path=tls / "key.pem",
            server_cert_pin=pin,
            camouflage_secret=camouflage,
            transport="tcp" if transport == "tcp" else "auto",
            pfs=True,
        )
        for host, port, pin in pins
    )
    specs = {"fabric": TunnelSpec("fabric", dials)}
    if validated:
        for index, upstream in enumerate(validated.bundle.tunnels.upstreams):
            if not upstream.enabled or upstream.auth_type == "p12":
                continue
            prefix = f"/tunnels/upstreams/{index}/"
            secrets = validated.secrets
            cert_dir = root / "tunnels" / upstream.name
            cert = cert_dir / "cert.pem" if upstream.cert_pem else None
            key = cert_dir / "key.pem" if prefix + "key" in secrets else None
            files: list[tuple[Path, bytes]] = []
            if cert is not None and upstream.cert_pem:
                files.append((cert, upstream.cert_pem.encode()))
            if key is not None:
                files.append((key, secrets[prefix + "key"].encode()))
            dial = DialSpec(
                server=upstream.server,
                port=upstream.port,
                interface=upstream.interface,
                pid_file=run / f"oc-{upstream.name}.pid",
                script=script,
                auth_type=upstream.auth_type,
                username=upstream.username,
                password=secrets.get(prefix + "password"),
                server_cert_pin=upstream.server_cert_pin,
                cert_path=cert,
                key_path=key,
                camouflage_secret=secrets.get(prefix + "camouflage"),
                transport="tcp" if upstream.transport == "tcp" else "auto",
            )
            specs[f"upstream:{upstream.name}"] = TunnelSpec(
                f"upstream:{upstream.name}",
                (dial,),
                password=dial.password,
                check_host=upstream.check_host,
                files=tuple(files),
            )
    return specs


class TunnelManager:
    """Keeps the desired tunnels up. `tick()` is called by the run loop."""

    def __init__(
        self,
        root: Path,
        *,
        converge: Callable[[], None],
        link_up: Callable[[str], bool],
        runner: Runner | None = None,
        resolve: Callable[[str | None], list[str]] = resolve_carrier_addresses,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        self.root = root
        self.converge = converge
        self.link_up = link_up
        self.runner = runner or SubprocessRunner()
        self.resolve = resolve
        self.clock = clock
        self.sleep = sleep
        self.jitter = jitter
        self._specs: dict[str, TunnelSpec] = {}
        self._carriers: dict[str, tuple[str, ...]] = {}
        self._next_attempt: dict[str, float] = {}
        self._backoff: dict[str, float] = {}
        self._dial_index: dict[str, int] = {}
        self._suspended: set[str] = set()
        self._lock = threading.RLock()
        self.errors: dict[str, str] = {}
        self.attached: dict[str, float] = {}

    # ---------------------------------------------------------- desired set

    @_locked
    def set_desired(self, specs: dict[str, TunnelSpec]) -> None:
        """Stop what is gone or changed; new and changed tunnels dial on the next tick."""
        for name, old in list(self._specs.items()):
            new = specs.get(name)
            if new is None or new != old:
                self._stop(name, old)
                self._next_attempt.pop(name, None)
                self._backoff.pop(name, None)
                self._dial_index.pop(name, None)
                if new is None:
                    self._carriers.pop(name, None)
                    self.errors.pop(name, None)
        self._specs = dict(specs)

    def specs(self) -> dict[str, TunnelSpec]:
        """A snapshot for diagnostics and reconnect, never expose the mutable mapping.

        Deliberately lock-free: tick()/reconnect() hold the lock for a whole
        dial (up to ~65 s) and status/doctor must not wait for it. set_desired()
        replaces the dict by one assignment, so a copy is always consistent.
        """
        return dict(self._specs)

    def carrier(self, exit_name: str) -> tuple[str, ...]:
        return self._carriers.get(exit_name, ())

    @_locked
    def suspend(self, exit_name: str) -> None:
        """Stop redialing (the hub says this node is revoked)."""
        self._suspended.add(exit_name)
        if (spec := self._specs.get(exit_name)) is not None:
            self._stop(exit_name, spec)

    # ----------------------------------------------------------- liveness

    def _pid(self, spec: TunnelSpec) -> int | None:
        try:
            return int(spec.dials[0].pid_file.read_text().strip())
        except (OSError, ValueError):
            return None

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        try:
            return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
        except (OSError, IndexError):
            return True

    def is_up(self, exit_name: str) -> bool:
        spec = self._specs.get(exit_name)
        if spec is None:
            return False
        pid = self._pid(spec)
        return pid is not None and self._alive(pid) and self.link_up(spec.interface)

    # --------------------------------------------------------------- loop

    @_locked
    def tick(self) -> None:
        for name, spec in list(self._specs.items()):
            if name in self._suspended:
                continue
            pid = self._pid(spec)
            if pid is not None and self._alive(pid):
                self._backoff.pop(name, None)
                continue
            if self.clock() < self._next_attempt.get(name, 0.0):
                continue
            self._connect(name, spec)

    @_locked
    def reconnect(self, exit_name: str) -> bool:
        spec = self._specs.get(exit_name)
        if spec is None:
            return False
        self._stop(exit_name, spec)
        self._suspended.discard(exit_name)
        self._next_attempt.pop(exit_name, None)
        self._backoff.pop(exit_name, None)
        self._connect(exit_name, spec)
        return True

    @_locked
    def stop_all(self) -> None:
        for name, spec in list(self._specs.items()):
            self._stop(name, spec)

    # -------------------------------------------------------------- dial

    def _connect(self, name: str, spec: TunnelSpec) -> None:
        index = self._dial_index.get(name, 0) % len(spec.dials)
        dial = spec.dials[index]
        try:
            self._prepare(spec, dial)
            # Carrier exemption and a reconciler pass must exist before any TCP
            # to the server: the kill-switch is in place from the first packet.
            self._carriers[name] = tuple(self.resolve(dial.server))
            self.converge()
            config_path: Path | None = None
            lines = config_lines(dial)
            if lines:
                config_path = self.root / "run" / f"oc-{name.replace(':', '-')}.conf"
                atomic_write(config_path, ("\n".join(lines) + "\n").encode(), 0o600)
            argv = openconnect_argv(dial, config_path=config_path)
            stdin = (
                f"{spec.password or ''}\n"
                if spec.password or dial.auth_type == "password"
                else None
            )
            code = self.runner.run(
                argv,
                input_text=stdin,
                timeout=DIAL_TIMEOUT,
                log=self.root / "logs" / f"openconnect-{name.replace(':', '-')}.log",
            )
            if code != 0:
                raise RuntimeError(f"openconnect exited with {code}")
            self._verify_backgrounded(spec)
        except (OSError, RuntimeError, ValueError) as exc:
            self.errors[name] = f"{type(exc).__name__}: {exc}"
            self._dial_index[name] = index + 1  # next hub on the next attempt
            backoff = min(BACKOFF_MAX, self._backoff.get(name, BACKOFF_START / 2) * 2)
            self._backoff[name] = backoff
            self._next_attempt[name] = self.clock() + backoff * (0.5 + self.jitter() / 2)
            return
        self.errors.pop(name, None)
        self.attached[name] = self.clock()
        self._backoff.pop(name, None)
        with contextlib.suppress(Exception):
            self.converge()  # routes via the new interface

    def _prepare(self, spec: TunnelSpec, dial: DialSpec) -> None:
        run = self.root / "run"
        run.mkdir(parents=True, exist_ok=True, mode=0o700)
        if dial.script is not None:
            atomic_write(dial.script, vpnc_script_source().read_bytes(), 0o755)
        for path, content in spec.files:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_write(path, content, 0o600)

    def _verify_backgrounded(self, spec: TunnelSpec) -> None:
        deadline = self.clock() + BACKGROUND_GRACE
        while True:
            pid = self._pid(spec)
            if pid is not None and self._alive(pid) and self.link_up(spec.interface):
                return
            if self.clock() >= deadline:
                raise RuntimeError(
                    f"tunnel interface {spec.interface} did not appear "
                    f"within {BACKGROUND_GRACE:.0f}s"
                )
            self.sleep(0.2)

    def _stop(self, name: str, spec: TunnelSpec) -> None:
        pid = self._pid(spec)
        if pid is not None and self._alive(pid):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)
            deadline = self.clock() + DISCONNECT_GRACE
            while self._alive(pid) and self.clock() < deadline:
                self.sleep(0.2)
            if self._alive(pid):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
        self.attached.pop(name, None)


__all__ = ["Runner", "SubprocessRunner", "TunnelManager", "TunnelSpec", "specs_for"]
