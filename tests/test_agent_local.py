from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest
from pydantic import ValidationError

from kornode_agent.local import (
    MAX_REQUEST,
    LocalError,
    LocalServer,
    ProcessLock,
    Request,
    request,
    socket_path,
)


def test_process_lock_is_exclusive_and_never_removes_user_files(tmp_path: Path) -> None:
    with (
        ProcessLock(tmp_path),
        pytest.raises(LocalError, match="already running"),
        ProcessLock(tmp_path),
    ):
        pytest.fail("second writer")
    with ProcessLock(tmp_path):
        pass
    assert (tmp_path / "run" / "agent.lock").exists()


@pytest.mark.parametrize(
    "fields",
    [
        {"op": "shell"},
        {"op": "status", "version": 2},
        {"op": "rollback", "version": True},
        {"op": "rollback", "version": -1},
        {"op": "rollback"},
        {"op": "explain", "src": "bad", "dst": "1.1.1.1"},
        {"op": "explain", "src": "host", "dst": "example.org"},
        {"op": "explain", "src": "host", "dst": "::1", "port": 70000},
        {"op": "explain", "src": "host", "dst": "::1", "proto": "icmp", "port": 80},
        {"op": "reconnect", "tunnel": "../../key"},
    ],
)
def test_request_rejects_bad_or_irrelevant_arguments(fields: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Request.model_validate(fields)


def test_unix_protocol_permissions_limits_and_shutdown(tmp_path: Path) -> None:
    async def run() -> None:
        seen: list[Request] = []

        async def dispatch(req: Request) -> dict[str, object]:
            seen.append(req)
            if req.op == "reconnect":
                raise LocalError("unknown_tunnel", "unknown tunnel", 3)
            return {"running": True}

        server = LocalServer(tmp_path, dispatch)
        await server.start()
        path = socket_path(tmp_path)
        assert path.stat().st_mode & 0o777 == 0o600
        assert await asyncio.to_thread(request, tmp_path, Request(op="status")) == {"running": True}
        with pytest.raises(LocalError) as exc:
            await asyncio.to_thread(request, tmp_path, Request(op="reconnect", tunnel="fabric"))
        assert exc.value.exit_code == 3
        for payload in (b"{}\n", b'{"op":"shell"}\n', b"x" * (MAX_REQUEST + 1) + b"\n"):
            reader, writer = await asyncio.open_unix_connection(str(path))
            writer.write(payload)
            await writer.drain()
            reply = json.loads(await reader.readline())
            assert reply["ok"] is False and reply["exit_code"] == 2
            writer.close()
            await writer.wait_closed()
        assert len(seen) == 2
        await server.close()
        assert not path.exists()

    asyncio.run(run())


def test_socket_refuses_to_replace_a_regular_file(tmp_path: Path) -> None:
    async def run() -> None:
        path = socket_path(tmp_path)
        path.parent.mkdir()
        path.write_text("operator file")

        async def dispatch(req: Request) -> dict[str, object]:
            return {}

        with pytest.raises(LocalError):
            await LocalServer(tmp_path, dispatch).start()
        assert path.read_text() == "operator file"

    asyncio.run(run())


def test_stale_socket_recovered_and_missing_process_distinguished(tmp_path: Path) -> None:
    async def run() -> None:
        path = socket_path(tmp_path)
        path.parent.mkdir()
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(path))
        with pytest.raises(LocalError) as exc:
            await asyncio.to_thread(request, tmp_path, Request(op="status"))
        assert exc.value.error == "agent_unavailable" and exc.value.exit_code == 1

        async def dispatch(req: Request) -> dict[str, object]:
            return {}

        server = LocalServer(tmp_path, dispatch)
        await server.start()
        await server.close()

    asyncio.run(run())


def test_live_socket_not_replaced_and_bad_response_bounded(tmp_path: Path) -> None:
    async def run() -> None:
        from kornode_agent.local import MAX_RESPONSE

        async def dispatch(req: Request) -> dict[str, object]:
            return {"large": "x" * MAX_RESPONSE}

        server = LocalServer(tmp_path, dispatch)
        await server.start()
        try:
            with pytest.raises(LocalError, match="already listening"):
                await LocalServer(tmp_path, dispatch).start()
            with pytest.raises(LocalError) as exc:
                await asyncio.to_thread(request, tmp_path, Request(op="status"))
            assert exc.value.error == "too_large"
        finally:
            await server.close()

    asyncio.run(run())


def test_slow_incomplete_request_has_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> None:
        monkeypatch.setattr("kornode_agent.local.READ_TIMEOUT", 0.03)

        async def dispatch(req: Request) -> dict[str, object]:
            pytest.fail("incomplete request must not dispatch")

        server = LocalServer(tmp_path, dispatch)
        await server.start()
        try:
            reader, writer = await asyncio.open_unix_connection(str(socket_path(tmp_path)))
            writer.write(b'{"op":')
            await writer.drain()
            reply = json.loads(await asyncio.wait_for(reader.readline(), 1))
            assert reply["exit_code"] == 2
            writer.close()
            await writer.wait_closed()
        finally:
            await server.close()

    asyncio.run(run())


def test_second_agent_run_refused_before_boot(tmp_path: Path) -> None:
    from kornode_agent.agent import Agent

    with ProcessLock(tmp_path), pytest.raises(LocalError, match="already running"):
        asyncio.run(Agent(tmp_path).run())
    assert not (tmp_path / "state.json").exists()
