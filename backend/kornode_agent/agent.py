"""The agent process: run loop, reports, commands, certificate renewal (spec 06)."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import platform
import subprocess
import tarfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from kornode.net.compile import compile_policy
from kornode.net.explain import explain
from kornode.net.kernel import Kernel
from kornode.net.reconciler import Reconciler, watch_netlink
from kornode_agent import __version__
from kornode_agent.apply import Applier, Convergence, Outcome
from kornode_agent.config import AgentConfig, load_config
from kornode_agent.control import Command, ControlClient, ControlError, HubUnreachable
from kornode_agent.enroll import load_seal_key
from kornode_agent.health import AgentHealth
from kornode_agent.inputs import AgentNetInputs, SystemProbes
from kornode_agent.store import Store, atomic_write
from kornode_agent.tunnels import TunnelManager, specs_for

log = logging.getLogger("kornode_agent")

POLL_WAIT = 60.0
DEFAULT_REPORT_INTERVAL = 30
DEFERRED_STABLE_SECONDS = 30.0
RENEW_FRACTION = 2 / 3
EXPIRY_WARNING = 14 * 86400
MAX_DIAG_BYTES = 5 * 1024 * 1024
RESTART_EXIT_CODE = 75
INVALID_BUNDLE_PAUSE = 30.0


class AgentRuntime:
    """The Applier's view of the process: provider, tunnels, reconciler."""

    def __init__(
        self,
        inputs: AgentNetInputs,
        tunnels: TunnelManager,
        reconciler: Reconciler,
        config: AgentConfig,
        root: Path,
    ) -> None:
        self.inputs = inputs
        self.tunnels = tunnels
        self.reconciler = reconciler
        self.config = config
        self.root = root

    def activate(self, validated: Any) -> None:
        # Kill-switches of the exits in use are part of every desired state, so
        # they stand before the tunnels of the new bundle are dialled (the
        # tunnel manager converges before each dial).
        self.inputs.set_bundle(validated)
        self.tunnels.set_desired(specs_for(validated, self.config, self.root))

    def converge(self) -> Convergence:
        plan = self.reconciler.run_once()
        return Convergence(empty=plan.is_empty, error=self.reconciler.status()["last_error"])


class Agent:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.probes = SystemProbes()
        self.store = Store(root)
        self.stop = asyncio.Event()
        self.exit_code = 0
        self.revoked = False
        self.rollbacks: list[dict[str, Any]] = []
        self._report_now = asyncio.Event()
        self._apply_lock = asyncio.Lock()
        self._fabric_healthy_since: float | None = None
        self._thread_stop = threading.Event()
        self._versions: dict[str, str] = {}

    # ----------------------------------------------------------------- setup

    async def run(self) -> int:
        self.loop = asyncio.get_running_loop()
        self.config: AgentConfig = load_config(self.root)
        self.client = ControlClient.enrolled(
            self.config.hub.control_url, self.root / "tls", self._fabric_address
        )
        self.reconciler: Reconciler
        self.tunnels = TunnelManager(
            self.root,
            converge=self._converge_or_raise,
            link_up=lambda iface: self.probes.links().get(iface, False),
        )
        self.inputs = AgentNetInputs(
            self.config, self.probes, self.tunnels, on_change=lambda: self.reconciler.wake()
        )
        self.reconciler = Reconciler(self.inputs.desired, Kernel())
        self.runtime = AgentRuntime(
            self.inputs, self.tunnels, self.reconciler, self.config, self.root
        )
        self.health = AgentHealth(self.tunnels, self._hub_ping)
        self.applier = Applier(
            store=self.store,
            runtime=self.runtime,
            health=self.health,
            node_id=self.config.node_id,
            seal_key=load_seal_key(self.root),
            agent_version=__version__,
            on_event=self._on_event,
        )
        self._versions = await asyncio.to_thread(_component_versions)
        # Boot first: a reconciler pass before the cached bundle is active would
        # drop the kill-switches the kernel still holds (fail closed).
        await asyncio.to_thread(self.applier.boot)
        for target in (
            self.reconciler.run_forever,
            lambda: watch_netlink(self.reconciler, self._thread_stop),
            self._tunnel_loop,
        ):
            threading.Thread(target=target, daemon=True).start()
        log.info("agent %d started at version %d", self.config.node_id, self.applier.state.current)
        tasks = [
            asyncio.create_task(coro)
            for coro in (
                self._poll_loop(),
                self._report_loop(),
                self._renew_loop(),
                self._deferred_loop(),
            )
        ]
        await self.stop.wait()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._thread_stop.set()
        self.reconciler.stop()
        await self.client.aclose()
        # Tunnels are left up: the data plane outlives the control plane.
        return self.exit_code

    def _fabric_address(self) -> str | None:
        inputs = getattr(self, "inputs", None)
        active = inputs.active if inputs else None
        iface = active.bundle.tunnels.fabric.interface if active else self.config.fabric.interface
        return self.probes.address(iface)

    def _converge_or_raise(self) -> None:
        """Fail closed: no dial unless the pass that installs the kill-switch worked."""
        self.reconciler.run_once()
        error = self.reconciler.status()["last_error"]
        if error:
            raise RuntimeError(f"reconciler: {error}")

    def _tunnel_loop(self) -> None:
        while not self._thread_stop.is_set():
            try:
                self.tunnels.tick()
            except Exception:
                log.exception("tunnel tick failed")
            self._thread_stop.wait(1.0)

    def _hub_ping(self) -> bool:
        future = asyncio.run_coroutine_threadsafe(self.client.ping(), self.loop)
        try:
            future.result(15)
        except ControlError as exc:
            if exc.revoked:
                self.loop.call_soon_threadsafe(self._mark_revoked)
            return False
        except Exception:
            return False
        return True

    def _mark_revoked(self) -> None:
        if not self.revoked:
            self.revoked = True
            log.error("the hub reports this node as revoked: tunnels are not redialled")
            self.loop.run_in_executor(None, self.tunnels.suspend, "fabric")

    def _on_event(self, event: dict[str, Any]) -> None:
        if event["type"] == "rolled_back":
            self.rollbacks.append(
                {
                    "from": event.get("version"),
                    "to": self.applier.state.current,
                    "at": _now(),
                    "reason": event.get("error") or "health: " + ", ".join(event["failed_checks"]),
                }
            )
            del self.rollbacks[:-10]
        self.loop.call_soon_threadsafe(self._report_now.set)

    # ------------------------------------------------------------------ loop

    async def _poll_loop(self) -> None:
        backoff = 1.0
        while True:
            try:
                result = await self.client.poll(self.applier.state.high_water, POLL_WAIT)
            except ControlError as exc:
                if exc.revoked:
                    self._mark_revoked()
                    await asyncio.sleep(300)
                else:
                    log.warning("poll refused: %s", exc)
                    await asyncio.sleep(_jitter(backoff))
                    backoff = min(60.0, backoff * 2)
                continue
            except HubUnreachable as exc:
                log.warning("hub unreachable: %s", exc)
                await asyncio.sleep(_jitter(backoff))
                backoff = min(60.0, backoff * 2)
                continue
            except Exception:
                log.exception("poll failed")
                await asyncio.sleep(_jitter(backoff))
                backoff = min(60.0, backoff * 2)
                continue
            backoff = 1.0
            try:
                if (
                    result.bundle is not None
                    and result.bundle.version > self.applier.state.high_water
                ):
                    async with self._apply_lock:
                        outcome = await asyncio.to_thread(
                            self.applier.apply_bundle, result.bundle.body, result.bundle.signature
                        )
                    _log_outcome(outcome)
                    self._report_now.set()
                    if outcome.result == "invalid_bundle":
                        # high-water did not move: the hub would resend it at once.
                        await asyncio.sleep(INVALID_BUNDLE_PAUSE)
                for command in result.commands:
                    await self._execute(command)
            except Exception:
                log.exception("applying the poll result failed")
                await asyncio.sleep(_jitter(backoff))

    async def _report_loop(self) -> None:
        while True:
            interval = self._report_interval()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._report_now.wait(), interval)
            self._report_now.clear()
            try:
                await self.client.report(await asyncio.to_thread(self.build_report))
            except Exception as exc:
                log.warning("report failed: %s", exc)

    def _report_interval(self) -> int:
        active = self.inputs.active
        if active and active.bundle.settings and active.bundle.settings.report_interval_seconds:
            return active.bundle.settings.report_interval_seconds
        return DEFAULT_REPORT_INTERVAL

    async def _deferred_loop(self) -> None:
        """A version rolled back while the hub path was down is retried once the
        fabric has been healthy for 30 s (at most 3 attempts)."""
        while True:
            await asyncio.sleep(5)
            if self.applier.state.deferred is None or self.applier.state.pending is not None:
                self._fabric_healthy_since = None
                continue
            healthy = await asyncio.to_thread(
                lambda: self.health.checks(self.applier.active).get("fabric", False)
            )
            now = time.monotonic()
            if not healthy:
                self._fabric_healthy_since = None
            elif self._fabric_healthy_since is None:
                self._fabric_healthy_since = now
            elif now - self._fabric_healthy_since >= DEFERRED_STABLE_SECONDS:
                self._fabric_healthy_since = None
                async with self._apply_lock:
                    outcome = await asyncio.to_thread(self.applier.retry_deferred)
                if outcome is not None:
                    _log_outcome(outcome)
                    self._report_now.set()

    # ------------------------------------------------------------ renewal

    async def _renew_loop(self) -> None:
        while True:
            await asyncio.sleep(3600)
            try:
                await self.renew_if_due()
            except Exception as exc:
                log.warning("certificate renewal failed: %s", exc)

    async def renew_if_due(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        cert = x509.load_pem_x509_certificate((self.root / "tls" / "cert.pem").read_bytes())
        start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
        remaining = (end - now).total_seconds()
        if remaining <= EXPIRY_WARNING:
            log.warning("the agent certificate expires at %s", end.isoformat())
        if now < start + (end - start) * RENEW_FRACTION:
            return False
        key = serialization.load_pem_private_key(
            (self.root / "tls" / "key.pem").read_bytes(), password=None
        )
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kornode-agent")]))
            .sign(key, hashes.SHA256())  # type: ignore[arg-type]
        )
        # The key is kept: replacing only the certificate is one atomic rename,
        # whereas a new key would need two files to change together.
        cert_pem = await self.client.renew(csr.public_bytes(serialization.Encoding.PEM).decode())
        atomic_write(self.root / "tls" / "cert.pem", cert_pem.encode(), 0o644)
        old = self.client
        self.client = ControlClient.enrolled(
            self.config.hub.control_url, self.root / "tls", self._fabric_address
        )
        await old.aclose()
        return True

    # ------------------------------------------------------------- commands

    async def _execute(self, command: Command) -> None:
        ok, output, artefact = True, "", None
        try:
            if command.type == "reconnect":
                ok, output = await asyncio.to_thread(self._reconnect, command.args.get("tunnel"))
            elif command.type == "explain":
                output = json.dumps(await asyncio.to_thread(self._explain, command.args))
            elif command.type == "collect_diag":
                artefact = await asyncio.to_thread(self._diag)
            elif command.type == "restart":
                output = "restarting"
            elif command.type == "rollback":
                async with self._apply_lock:
                    outcome = await asyncio.to_thread(
                        self.applier.rollback_to, int(command.args["to_version"])
                    )
                ok = outcome.result == "confirmed"
                output = outcome.error or outcome.result
            else:
                ok, output = False, f"unknown command {command.type!r}"
        except (ValueError, KeyError, OSError) as exc:
            ok, output = False, f"{type(exc).__name__}: {exc}"
        for attempt in range(3):
            try:
                await self.client.command_result(
                    command.id, ok=ok, output=output[:1_000_000], artefact=artefact
                )
                break
            except (ControlError, HubUnreachable) as exc:
                log.warning("command result not delivered (%s)", exc)
                await asyncio.sleep(2**attempt)
        if command.type == "restart":
            self.exit_code = RESTART_EXIT_CODE
            self.stop.set()
        self._report_now.set()

    def _reconnect(self, name: str | None) -> tuple[bool, str]:
        names = [name] if name else list(self.tunnels._specs)  # noqa: SLF001
        done = [n for n in names if self.tunnels.reconnect(n)]
        return bool(done), ", ".join(done) or f"unknown tunnel {name!r}"

    def _explain(self, args: dict[str, Any]) -> dict[str, Any]:
        policy, facts = self.inputs.policy(), self.inputs.facts()
        compiled = compile_policy(policy, facts)
        return explain(compiled, policy, facts, str(args["src"]), str(args["dst"])).as_dict()

    def _diag(self) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, argv in (
                ("ip-rule.txt", ["ip", "rule", "show"]),
                ("ip-route.txt", ["ip", "route", "show", "table", "all"]),
                ("nft.txt", ["nft", "list", "ruleset"]),
            ):
                _add(archive, name, _capture(argv))
            _add(archive, "report.json", json.dumps(self.build_report(), indent=1).encode())
            _add(archive, "state.json", self.store.state_path.read_bytes())
            for log_file in sorted((self.root / "logs").glob("*.log")):
                _add(archive, f"logs/{log_file.name}", log_file.read_bytes()[-100_000:])
        data = buffer.getvalue()
        if len(data) > MAX_DIAG_BYTES:
            raise ValueError("diagnostic archive exceeds 5 MB")
        return data

    # --------------------------------------------------------------- report

    def build_report(self) -> dict[str, Any]:
        state = self.applier.state
        active = self.inputs.active
        links = self.probes.links()
        status = self.reconciler.status()
        tunnels = []
        for name, spec in sorted(self.tunnels._specs.items()):  # noqa: SLF001
            dial = spec.dials[0]
            tunnels.append(
                {
                    "name": name,
                    "iface": spec.interface,
                    "up": self.tunnels.is_up(name),
                    "carrier": f"{dial.server}:{dial.port}",
                    "transport": dial.transport,
                    "error": self.tunnels.errors.get(name),
                }
            )
        sources = [
            {"name": s.name, "iface": s.interface, "present": s.interface in links}
            for s in (active.bundle.policy.sources if active else ())
        ]
        return {
            "node_id": self.config.node_id,
            "agent_version": __version__,
            "time": _now(),
            "applied_version": state.current,
            "pending_version": state.pending.version if state.pending else None,
            "high_water_version": state.high_water,
            "last_apply": state.last_apply.model_dump() if state.last_apply else None,
            "rollbacks": list(self.rollbacks),
            "failed_versions": dict(state.failed),
            "tunnels": tunnels,
            "sources": sources,
            "local_networks": [str(n) for n in self.probes.local_networks(set(links))],
            "reconciler": {
                "last_apply": status["last_apply_at"],
                "drift_events": status["drift"],
                "last_error": status["last_error"],
            },
            "versions": self._versions,
            "revoked": self.revoked,
        }


def _component_versions() -> dict[str, str]:
    versions = {"agent": __version__, "kernel": platform.release()}
    for name, argv in (
        ("openconnect", ["openconnect", "--version"]),
        ("nft", ["nft", "--version"]),
    ):
        first = _capture(argv).decode(errors="replace").splitlines()
        versions[name] = first[0] if first else "unavailable"
    return versions


def _capture(argv: list[str]) -> bytes:
    try:
        return subprocess.run(argv, capture_output=True, timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return b""


def _add(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = int(time.time())
    archive.addfile(info, io.BytesIO(data))


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _jitter(seconds: float) -> float:
    import random

    return seconds * (0.5 + random.random() / 2)  # noqa: S311 - not security relevant


def _log_outcome(outcome: Outcome) -> None:
    log.info("bundle %d: %s %s", outcome.version, outcome.result, outcome.error or "")


__all__ = ["Agent", "AgentRuntime"]
