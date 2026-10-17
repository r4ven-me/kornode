"""Management surface of the hub's routing core: plan, apply, explain, run.

`korctl net ...`, `/api/net/*` and the panel all call this service
(docs/spec/08-interfaces-parity.md). Kernel state is only ever changed by
kornode.net (the reconciler); `apply` just wakes it through its socket, or
runs one pass in-process when no reconciler is running.
"""

from __future__ import annotations

import signal
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.net.diff import Plan, describe, diff
from kornode.net.explain import explain
from kornode.net.kernel import Kernel
from kornode.net.reconciler import (
    Reconciler,
    WriterLockBusy,
    control_request,
    serve_control,
    watch_netlink,
    writer_lock,
)
from kornode.services.command import CommandRunner
from kornode.services.netinputs import HubNetInputs

APPLY_TIMEOUT_SECONDS = 30.0


class NetApplyError(RuntimeError):
    """The reconciler could not converge the kernel (its last pass failed)."""


def reconciler_socket(config: AppConfig) -> Path:
    return config.system.generated_dir / "reconciler.sock"


def reconciler_lock(config: AppConfig) -> Path:
    return config.system.generated_dir / "reconciler.lock"


def _plan_dict(plan: Plan) -> list[dict[str, str]]:
    return [{"op": type(op).__name__, "text": describe(op)} for op in plan.ops]


class NetService:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        kernel: Kernel | None = None,
    ) -> None:
        self.config = config
        self.inputs = HubNetInputs(config, runner=runner)
        self.kernel = kernel or Kernel()

    def plan(self) -> dict[str, Any]:
        compiled = self.inputs.compiled()
        keys = [sysctl.key for sysctl in compiled.desired.sysctls]
        chains = sorted({rule.chain_key for rule in compiled.desired.foreign_rules})
        devs = sorted({address.dev for address in compiled.desired.addresses})
        plan = diff(self.kernel.read(keys, chains, devs), compiled.desired)
        return {
            "ops": _plan_dict(plan),
            "warnings": list(compiled.warnings),
            "exits": [
                {
                    "name": exit_.name,
                    "mark": f"0x{exit_.mark:08x}",
                    "table": exit_.table if exit_.has_table else None,
                    "interface": exit_.interface,
                    "up": exit_.up,
                    "kill_switch": exit_.kill_switch,
                }
                for exit_ in compiled.exits
            ],
            "schema_hash": compiled.desired.nft.schema_hash if compiled.desired.nft else None,
        }

    def apply(self, *, dry_run: bool = False) -> dict[str, Any]:
        if dry_run:
            return {"applied": False, "dry_run": True, **self.plan()}
        sock = reconciler_socket(self.config)
        deadline = time.monotonic() + APPLY_TIMEOUT_SECONDS
        while True:
            if sock.exists():
                try:
                    reply = control_request(sock, "apply", timeout=APPLY_TIMEOUT_SECONDS)
                except (FileNotFoundError, ConnectionRefusedError):
                    pass  # stale socket, nobody listens (yet)
                except (OSError, ValueError) as exc:
                    # Somebody listens but did not answer (timeout, garbage): a
                    # second in-process writer would race the reconciler's pass.
                    raise NetApplyError(f"reconciler did not answer: {exc}") from exc
                else:
                    status = reply.get("status")
                    if reply.get("ok") is not True or not isinstance(status, dict):
                        detail = reply.get("error") or "empty reply"
                        raise NetApplyError(f"reconciler refused the pass: {detail}")
                    return {
                        "applied": status.get("last_error") is None,
                        "via": "reconciler",
                        "status": {"running": True, **status},
                    }
            try:
                with writer_lock(reconciler_lock(self.config)):
                    return self._apply_in_process()
            except WriterLockBusy:
                # The daemon holds the lock but has not bound its socket yet
                # (start or autorestart): never become a second kernel writer,
                # wait for it to answer.
                if time.monotonic() >= deadline:
                    raise NetApplyError(
                        "reconciler is starting but did not open its socket"
                    ) from None
                time.sleep(0.1)

    def _apply_in_process(self) -> dict[str, Any]:
        reconciler = Reconciler(self.inputs.desired, self.kernel)
        plan = reconciler.run_once()
        status = reconciler.status()
        return {
            "applied": status["last_error"] is None,
            "via": "in-process",
            "ops": _plan_dict(plan),
            "status": status,
        }

    def wake(self) -> bool:
        """Fire-and-forget nudge for callers that only changed an input
        (domain resolver, vpnc/ocserv hooks). No reconciler running is fine:
        it converges on its own start and on its 10 s timer."""
        try:
            control_request(reconciler_socket(self.config), "wake")
        except OSError:
            return False
        return True

    def converge(self) -> dict[str, Any]:
        """`apply` for internal callers: a failed pass is an error, not a
        silent success (a missing kill-switch must stop a connect)."""
        result = self.apply()
        error = result.get("status", {}).get("last_error")
        if error:
            raise NetApplyError(f"kernel did not converge: {error}")
        return result

    def status(self) -> dict[str, Any]:
        sock = reconciler_socket(self.config)
        try:
            reply = control_request(sock, "status")
        except OSError:
            return {"running": False}
        return {"running": True, **reply.get("status", {})}

    def explain(self, src: str, dst: str) -> dict[str, Any]:
        compiled = self.inputs.compiled()
        decision = explain(
            compiled,
            self.inputs.policy(),
            self.inputs.facts(),
            src,
            dst,
            route_get=self.kernel.route_get,
        )
        return decision.as_dict()


def run_reconciler(config_path: Path, env_file: Path | None = None) -> None:
    """`korctl net run`: the hub's reconciler process (supervisor program).
    Re-reads config on every pass so edits apply without a restart."""

    def provider() -> Any:
        config = load_config(config_path, env_file=env_file)
        return HubNetInputs(config).desired()

    config = load_config(config_path, env_file=env_file)
    with writer_lock(reconciler_lock(config)):
        _run_locked(config, provider)


def _run_locked(config: AppConfig, provider: Callable[[], Any]) -> None:
    reconciler = Reconciler(provider, Kernel())
    stop = threading.Event()

    def shutdown(*_: object) -> None:
        stop.set()
        reconciler.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server = serve_control(reconciler, reconciler_socket(config))
    threading.Thread(target=watch_netlink, args=(reconciler, stop), daemon=True).start()
    try:
        reconciler.run_forever()
    finally:
        server.shutdown()
        server.server_close()
