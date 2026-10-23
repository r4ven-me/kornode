"""P3-06: the real agent (`kornode-agent enroll` / `run`) against the real hub.

Everything is real: token -> enroll session -> CSR -> certificate, the interlink
tunnel, the control API over it, apply-with-confirm of the first bundle, boot
from the cache while the control API is down.
"""

# ruff: noqa: F811 - pytest fixtures imported from test_p3_groups
from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from tests.netlab.kornode_nodes import _popen_in_namespace, _terminate_process, _wait_until
from tests.netlab.lab import Namespace
from tests.netlab.test_p3_enrollment import NEW_ID, _decode, _hub_call
from tests.netlab.test_p3_groups import (  # noqa: F401 - fixtures
    HUB_INTERLINK_ADDR,
    RenderedHub,
    node_tmp,
    rendered_hub,
)

pytestmark = pytest.mark.netlab


def _agent_argv(root: Path, *args: str) -> list[str]:
    return [sys.executable, "-m", "kornode_agent.cli", "--root", str(root), *args]


def _token_for_peer(hub: RenderedHub) -> str:
    """The hub names itself `hub:443`; the lab's peer reaches it by address."""
    doc = _decode(_hub_call(hub, "token", str(NEW_ID)).strip())
    doc["hub"] = f"{hub.agent.hub_addr}:443"
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _state(root: Path) -> dict[str, object]:
    try:
        return json.loads((root / "state.json").read_text())
    except (OSError, ValueError):
        return {}


def _applied_on_hub(hub: RenderedHub) -> int | None:
    conn = sqlite3.connect(f"file:{hub.root.data_dir / 'registry.db'}?mode=ro", uri=True)
    try:
        row = conn.execute("SELECT applied_version FROM nodes WHERE id = ?", (NEW_ID,)).fetchone()
    finally:
        conn.close()
    return None if row is None else row[0]


def _net_dump(ns: Namespace) -> str:
    out = []
    for argv in (
        ["ip", "-br", "addr"],
        ["ip", "rule"],
        ["ip", "route", "show", "table", "all"],
        ["nft", "list", "ruleset"],
    ):
        out.append(f"$ {' '.join(argv)}\n{ns.run(argv, check=False).stdout}")
    return "\n".join(out)


def _logs(root: Path) -> str:
    return "\n".join(p.read_text(errors="replace") for p in sorted(root.glob("**/*.log")))


def test_agent_enrolls_confirms_its_bundle_and_boots_from_cache(
    rendered_hub: RenderedHub, node_tmp: Path
) -> None:
    hub = rendered_hub
    ns = hub.agent.ns
    root = node_tmp / "agent-root"
    root.mkdir(mode=0o755)
    # A real host has a default route; the interlink exit re-routes marked packets.
    ns.run(["ip", "route", "add", "default", "via", hub.agent.hub_addr])
    # The bundle names the hub by its certificate CN ("hub"), as DNS would.
    hosts = Path("/etc/netns") / ns.full_name / "hosts"
    hosts.parent.mkdir(parents=True, exist_ok=True)
    hosts.write_text(f"127.0.0.1 localhost\n{hub.agent.hub_addr} hub\n", encoding="utf-8")
    _hub_call(hub, "create", str(NEW_ID))
    token = _token_for_peer(hub)

    enrolled = ns.run(_agent_argv(root, "enroll", token), check=False, timeout=120)
    assert enrolled.ok, enrolled.stderr + _logs(root)
    assert (root / "tls" / "cert.pem").exists() and (root / "agent.yaml").exists()

    env = ["env", f"PATH={Path(sys.executable).absolute().parent}{os.pathsep}{os.environ['PATH']}"]
    agent = _popen_in_namespace(ns, [*env, *_agent_argv(root, "run")], root / "logs" / "agent.log")
    try:
        try:
            _wait_until(
                lambda: agent.poll() is None and _state(root).get("current", 0) >= 1,  # type: ignore[operator]
                "the first bundle is confirmed",
                timeout=150,
            )
        except TimeoutError as exc:
            raise AssertionError(
                f"{exc}\nstate={_state(root)}\n{_logs(root)}\n{_net_dump(ns)}"
            ) from exc
        assert _state(root)["pending"] is None
        assert ns.run(["ip", "link", "show", "dev", "oc-hub0"], check=False).ok
        _wait_until(lambda: _applied_on_hub(hub) == _state(root)["current"], "report reached hub")

        # P3-07: CLI talks to this process, never starts a second reconciler.
        status = ns.run(_agent_argv(root, "status", "--json"), check=False, timeout=120)
        assert status.ok, status.stdout + status.stderr
        report = json.loads(status.stdout)
        assert report["running"] and report["hub_reachable"]
        assert report["applied_version"] == _state(root)["current"]
        for args in (
            ("bundle", "show"),
            ("bundle", "history"),
            ("explain", "host", HUB_INTERLINK_ADDR),
            ("reconnect", "interlink", "--dry-run"),
        ):
            result = ns.run(_agent_argv(root, *args, "--json"), check=False, timeout=120)
            assert result.ok, result.stdout + result.stderr
            json.loads(result.stdout)
        doctor = ns.run(_agent_argv(root, "doctor", "--json"), check=False, timeout=120)
        assert doctor.returncode in (0, 1)
        assert "findings" in json.loads(doctor.stdout)
        diag_path = root / "diagnostic.tar.gz"
        diag = ns.run(
            _agent_argv(root, "diag", "--out", str(diag_path), "--json"), check=False, timeout=120
        )
        assert diag.ok and diag_path.stat().st_mode & 0o777 == 0o600
        assert diag_path.stat().st_size <= 5 * 1024 * 1024
        assert (root / "run/agent.sock").stat().st_mode & 0o777 == 0o600

        # Hub control plane down: the agent keeps its state and restarts from the cache.
        control = next(
            p for p in hub.processes if isinstance(p.args, list) and "kornode.control" in p.args
        )
        _terminate_process(control)
        current = _state(root)["current"]
        down = ns.run(_agent_argv(root, "status", "--json"), check=False, timeout=120)
        assert down.returncode == 4 and json.loads(down.stdout)["hub_reachable"] is False
        _terminate_process(agent)
        offline = ns.run(_agent_argv(root, "status", "--json"), check=False, timeout=120)
        assert offline.ok and json.loads(offline.stdout)["running"] is False
        assert ns.run(_agent_argv(root, "bundle", "show", "--json"), check=False).ok
        agent = _popen_in_namespace(
            ns, [*env, *_agent_argv(root, "run")], root / "logs" / "agent2.log"
        )
        time.sleep(5)
        assert agent.poll() is None, _logs(root)
        assert _state(root)["current"] == current
        assert ns.run(["ip", "link", "show", "dev", "oc-hub0"], check=False).ok
    finally:
        _terminate_process(agent)
        shutil.rmtree(hosts.parent, ignore_errors=True)
