"""Offline plan and explicitly authorized VM preflight/recovery entrypoints."""

from __future__ import annotations

import argparse
import json
import os
import re

from tests.e2e.fleet import REPOSITORY, Fleet
from tests.e2e.inventory import E2EError, Inventory
from tests.e2e.test_routed_fabric import BLOCKED
from tests.e2e.worker import atomic


def recover(inventory: Inventory, run_id: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{24}", run_id):
        raise E2EError("invalid recovery run ID")
    instance = Fleet(inventory, run_id=run_id)
    failed = False
    for role in instance.connections:
        try:
            instance.call(role, "recover")
        except E2EError:
            failed = True
    if failed:
        raise E2EError("E2E recovery incomplete; inspect designated VM leases")
    path = instance.artifacts / "active.json"
    if path.is_file():
        atomic(path, {"run_id": run_id, "roles": [], "closed": True})


def main() -> int:
    parser = argparse.ArgumentParser(description="Disposable four-VM E2E tooling")
    parser.add_argument("action", choices=("plan", "preflight", "cleanup"))
    parser.add_argument("--run-id")
    parser.add_argument("--all-owned", action="store_true")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    if args.action == "plan":
        print(
            json.dumps(
                {
                    "network_actions": False,
                    "runnable_cases": [
                        "E2E-01",
                        "E2E-02",
                        "E2E-03",
                        "E2E-04",
                        "E2E-05",
                        "E2E-06 (previous images required)",
                        "NL-13 (cache/upstream only)",
                        "NL-10",
                        "NL-11",
                        "NL-12",
                    ],
                    "blocked_contracts": BLOCKED,
                    "requires": [
                        "four owner-designated disposable VMs",
                        "hub self-hosted runner",
                        "pinned SSH hosts",
                        "explicit destructive opt-in",
                    ],
                },
                indent=2,
            )
        )
        return 0
    try:
        inventory = Inventory.from_env(os.environ)
        if args.action == "preflight":
            Fleet(inventory).preflight()
            print(json.dumps({"preflight": "passed", "roles": 4}))
            return 0
        if not args.yes or bool(args.run_id) == bool(args.all_owned):
            raise E2EError("cleanup requires --yes and exactly one of --run-id/--all-owned")
        runs = [args.run_id] if args.run_id else []
        if args.all_owned:
            for path in (REPOSITORY / "artifacts" / "e2e").glob("*/active.json"):
                if path.is_symlink() or not re.fullmatch(r"[0-9a-f]{24}", path.parent.name):
                    raise E2EError("invalid local recovery ledger")
                value = json.loads(path.read_text())
                if value.get("run_id") != path.parent.name:
                    raise E2EError("invalid local recovery ledger")
                if not value.get("closed"):
                    runs.append(value["run_id"])
        for run_id in runs:
            recover(inventory, run_id)
        print(json.dumps({"cleanup": "passed", "runs": len(runs)}))
        return 0
    except Exception:
        # Never echo env values, command output, inventory, or exception repr.
        print(
            json.dumps(
                {
                    "error": "e2e_operation_failed",
                    "message": (
                        "check opt-in, designated VM markers, SSH pins and leases; "
                        "raw output withheld"
                    ),
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
