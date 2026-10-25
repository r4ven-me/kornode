from __future__ import annotations

import asyncio
import io
import tarfile
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from tests.test_agent_apply import World
from tests.test_agent_cli import enrolled

from kornode.net.compile import NodeFacts
from kornode.net.model import EgressPolicy
from kornode_agent.agent import Agent
from kornode_agent.config import load_config
from kornode_agent.control import Command, HubUnreachable
from kornode_agent.local import LocalError, LocalServer, Request, request


def fake_agent(tmp_path: Path) -> tuple[Agent, World]:
    w = World(tmp_path)
    w.applier.boot()
    root = enrolled(w)
    agent = Agent(root)
    agent.applier = w.applier
    agent.config = load_config(root)
    agent.inputs = SimpleNamespace(active=None)  # type: ignore[assignment]
    agent.tunnels = SimpleNamespace(  # type: ignore[assignment]
        specs=lambda: {"interlink": object()}, errors={}, reconnect=lambda name: True
    )
    return agent, w


def test_local_and_remote_rollback_share_confirm_and_high_water(tmp_path: Path) -> None:
    async def run() -> None:
        agent, w = fake_agent(tmp_path)
        w.applier.apply_bundle(*w.bundle(5))
        w.applier.apply_bundle(*w.bundle(6))
        before = w.store.state_path.read_bytes()
        preview = await agent.perform(Request(op="rollback", version=5, dry_run=True))
        assert preview["to_version"] == 5 and preview["high_water"] == 6
        assert w.store.state_path.read_bytes() == before
        result = await agent.perform(Request(op="rollback", version=5))
        assert result == {"version": 5, "result": "confirmed"}
        assert w.store.load_state().current == 5 and w.store.load_state().high_water == 6
        replies = []

        class Client:
            async def command_result(self, *args: Any, **kwargs: Any) -> None:
                replies.append(kwargs)

        agent.client = Client()  # type: ignore[assignment]
        await agent._execute(Command("id", "rollback", {"to_version": 6}, "later"))
        assert replies[0]["ok"] and w.store.load_state().current == 6
        assert w.store.load_state().high_water == 6
        assert agent._report_now.is_set()

    asyncio.run(run())


def test_cancel_does_not_release_mutation_lock_before_worker_finishes(tmp_path: Path) -> None:
    async def run() -> None:
        agent, _ = fake_agent(tmp_path)
        entered, release = threading.Event(), threading.Event()
        calls = []

        def reconnect(name: str | None, dry_run: bool) -> dict[str, Any]:
            calls.append(name)
            entered.set()
            assert release.wait(3)
            return {"reconnected": [name]}

        agent._reconnect = reconnect  # type: ignore[method-assign]
        first = asyncio.create_task(agent.perform(Request(op="reconnect", tunnel="interlink")))
        await asyncio.to_thread(entered.wait, 3)
        first.cancel()
        second = asyncio.create_task(agent.perform(Request(op="reconnect", tunnel="interlink")))
        await asyncio.sleep(0.03)
        assert agent._apply_lock.locked() and len(calls) == 1
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        await second
        assert len(calls) == 2 and not agent._apply_lock.locked()

    asyncio.run(run())


def test_reconnect_dry_run_revoked_unknown_and_failed(tmp_path: Path) -> None:
    async def run() -> None:
        agent, _ = fake_agent(tmp_path)
        calls = []
        agent.tunnels.reconnect = calls.append  # type: ignore[method-assign, assignment]
        assert (await agent.perform(Request(op="reconnect", dry_run=True)))["would_reconnect"] == [
            "interlink"
        ]
        assert calls == []
        with pytest.raises(LocalError) as exc:
            await agent.perform(Request(op="reconnect", tunnel="upstream:missing"))
        assert exc.value.exit_code == 3
        agent.revoked = True
        with pytest.raises(LocalError, match="revoked"):
            await agent.perform(Request(op="reconnect", tunnel="interlink"))
        assert calls == []
        agent.revoked = False
        agent.tunnels.errors["interlink"] = "failed"
        with pytest.raises(LocalError, match="dial failed"):
            await agent.perform(Request(op="reconnect", tunnel="interlink"))

    asyncio.run(run())


def test_diag_archive_redacted_bounded_and_no_symlink_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, w = fake_agent(tmp_path)
    w.applier.apply_bundle(*w.bundle(5))
    agent.build_report = lambda: {
        "doctor": [],
        "error": "hide-this-camouflage",
        "pw_hash": "never-hash",
    }  # type: ignore[method-assign]
    monkeypatch.setattr("kornode_agent.agent._capture", lambda argv: b"routes\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "agent.log").write_text(
        'password="secret with spaces"\nhttps://hub/?hide-this-camouflage\n'
        "-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----\n"
    )
    target = tmp_path / "operator-secret"
    target.write_text("symlink-secret")
    (logs / "link.log").symlink_to(target)
    data = agent._diag()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        names = archive.getnames()
        assert {"report.json", "state.json", "doctor.json", "logs/agent.log"} <= set(names)
        assert "logs/link.log" not in names
        text = "\n".join(archive.extractfile(name).read().decode() for name in names)  # type: ignore[union-attr]
    for value in (
        "secret with spaces",
        "hide-this-camouflage",
        "key-material",
        "never-hash",
        "symlink-secret",
    ):
        assert value not in text
    assert len(data) <= 5 * 1024 * 1024


def test_explain_uses_kernel_read_only_and_discloses_l4_limitation(tmp_path: Path) -> None:
    async def run() -> None:
        agent, _ = fake_agent(tmp_path)
        policy = EgressPolicy.model_validate(
            {"egress": [{"from": ["host"], "to": "any", "via": "local"}]}
        )
        facts = NodeFacts(node_id=3, client_pool=None)
        agent.inputs = SimpleNamespace(active=None, policy=lambda: policy, facts=lambda: facts)  # type: ignore[assignment]
        queries = []
        agent.kernel = SimpleNamespace(route_get=lambda *args: queries.append(args))  # type: ignore[assignment]
        result = await agent.perform(
            Request(op="explain", src="host", dst="1.1.1.1", proto="tcp", port=443)
        )
        assert queries and result["query"]["port"] == 443
        assert "not protocol/port" in result["warnings"][-1]

    asyncio.run(run())


def test_worker_error_cannot_swallow_shutdown_cancellation() -> None:
    from kornode_agent.agent import _worker

    async def run() -> None:
        entered, release = threading.Event(), threading.Event()

        def fail() -> None:
            entered.set()
            assert release.wait(3)
            raise RuntimeError("worker failed during cancellation")

        task = asyncio.create_task(_worker(fail))
        assert await asyncio.to_thread(entered.wait, 3)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())


def test_live_status_over_real_socket_when_hub_is_down(tmp_path: Path) -> None:
    async def run() -> None:
        agent, _ = fake_agent(tmp_path)
        agent.build_report = lambda: {"applied_version": 5}  # type: ignore[method-assign]

        class Client:
            async def ping(self) -> None:
                raise HubUnreachable("offline")

        agent.client = Client()  # type: ignore[assignment]
        server = LocalServer(tmp_path, agent.perform)
        await server.start()
        try:
            result = await asyncio.to_thread(request, tmp_path, Request(op="status"))
            assert result == {"running": True, "hub_reachable": False, "applied_version": 5}
        finally:
            await server.close()

    asyncio.run(run())


def test_local_diag_returns_a_decodable_archive_not_a_redaction(tmp_path: Path) -> None:
    # The redactor's base64-line rule would swallow a one-line base64 blob.
    import base64

    async def run() -> None:
        agent, _ = fake_agent(tmp_path)
        agent._diag = lambda: b"\x1f\x8b" + bytes(range(256)) * 12  # type: ignore[method-assign]
        result = await agent.perform(Request(op="diag"))
        assert base64.b64decode(result["archive_b64"], validate=True)[:2] == b"\x1f\x8b"

    asyncio.run(run())


def test_report_reuses_doctor_until_version_changes_or_cache_expires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, w = fake_agent(tmp_path)
    runs: list[int] = []
    agent._doctor = lambda: runs.append(1) or []  # type: ignore[method-assign,func-returns-value]
    clock = [1000.0]
    monkeypatch.setattr("kornode_agent.agent.time.monotonic", lambda: clock[0])

    agent._doctor_for_report(5)
    agent._doctor_for_report(5)
    assert len(runs) == 1
    agent._doctor_for_report(6)  # a new applied version invalidates the cache
    assert len(runs) == 2
    clock[0] += 121
    agent._doctor_for_report(6)
    assert len(runs) == 3
