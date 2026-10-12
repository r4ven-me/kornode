"""Management surface of the hub's routing core: plan, apply, explain, run.

`korctl net ...`, `/api/net/*` and the panel all call this service
(docs/spec/08-interfaces-parity.md). Kernel state is only ever changed by
kornode.net (the reconciler); `apply` just wakes it through its socket, or
runs one pass in-process when no reconciler is running.
"""

from __future__ import annotations

import signal
import threading
from pathlib import Path
from typing import Any

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.net.diff import Plan, describe, diff
from kornode.net.explain import explain
from kornode.net.kernel import Kernel
from kornode.net.reconciler import Reconciler, control_request, serve_control, watch_netlink
from kornode.services.command import CommandRunner
from kornode.services.netinputs import HubNetInputs


def reconciler_socket(config: AppConfig) -> Path:
    return config.system.generated_dir / "reconciler.sock"


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
        plan = diff(self.kernel.read(keys), compiled.desired)
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
        if sock.exists():
            try:
                control_request(sock, "wake")
                return {"applied": True, "via": "reconciler", "status": self.status()}
            except OSError:
                pass  # stale socket: fall through to an in-process pass
        reconciler = Reconciler(self.inputs.desired, self.kernel)
        plan = reconciler.run_once()
        return {
            "applied": True,
            "via": "in-process",
            "ops": _plan_dict(plan),
            "status": reconciler.status(),
        }

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
