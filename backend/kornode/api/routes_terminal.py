from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import os
import pty
import secrets
import select
import signal
import struct
import termios
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.config.models import AppConfig
from kornode.services.audit import AuditService
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.secrets import collect_config_secrets, mask_text

router = APIRouter()


class TerminalCommandRequest(BaseModel):
    command: str = Field(min_length=1, max_length=4000)
    cwd: str = "/"
    timeout: int = Field(default=30, ge=1, le=300)


class TerminalSessionRequest(BaseModel):
    cwd: str = "/"
    rows: int = Field(default=30, ge=10, le=80)
    cols: int = Field(default=100, ge=40, le=240)


@dataclass(frozen=True)
class TerminalTicket:
    cwd: str
    rows: int
    cols: int
    expires_at: float
    actor: str
    source_ip: str | None


class TerminalRegistry:
    def __init__(self, max_sessions: int) -> None:
        self._tickets: dict[str, TerminalTicket] = {}
        self._active_sessions = 0
        self._max_sessions = max_sessions
        self._lock = threading.Lock()

    def issue(
        self,
        *,
        cwd: str,
        rows: int,
        cols: int,
        actor: str,
        source_ip: str | None,
        ttl: int = 60,
    ) -> str:
        with self._lock:
            self._prune()
            if self._active_sessions + len(self._tickets) >= self._max_sessions:
                raise RuntimeError("terminal session limit reached")
            token = secrets.token_urlsafe(32)
            self._tickets[token] = TerminalTicket(
                cwd=cwd,
                rows=rows,
                cols=cols,
                expires_at=time.monotonic() + ttl,
                actor=actor,
                source_ip=source_ip,
            )
            return token

    def consume(self, token: str) -> TerminalTicket | None:
        with self._lock:
            self._prune()
            ticket = self._tickets.pop(token, None)
            if ticket is not None:
                self._active_sessions += 1
            return ticket

    def release(self) -> None:
        with self._lock:
            self._active_sessions = max(0, self._active_sessions - 1)

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [token for token, ticket in self._tickets.items() if ticket.expires_at <= now]
        for token in expired:
            self._tickets.pop(token, None)


def command_result(result: CommandResult) -> dict[str, object]:
    return {
        "argv": list(result.argv),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


@router.post("/run", dependencies=[Depends(require_admin)])
def run_command(request: Request, payload: TerminalCommandRequest) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    _require_terminal_enabled(config)
    cwd = _validate_cwd(payload.cwd)

    runner = CommandRunner(secrets=collect_config_secrets(config))
    result = runner.run(
        ["/bin/bash", "-lc", payload.command],
        cwd=str(cwd),
        timeout=payload.timeout,
        check=False,
    )
    return command_result(result)


@router.post("/sessions", dependencies=[Depends(require_admin)])
def create_terminal_session(
    request: Request,
    payload: TerminalSessionRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    _require_terminal_enabled(config)
    cwd = _validate_cwd(payload.cwd)
    try:
        token = _registry(request).issue(
            cwd=str(cwd),
            rows=payload.rows,
            cols=payload.cols,
            actor=getattr(request.state, "admin_username", config.web.admin_user),
            source_ip=request.client.host if request.client else None,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return {"token": token, "cwd": str(cwd), "rows": payload.rows, "cols": payload.cols}


@router.websocket("/ws")
async def terminal_websocket(websocket: WebSocket) -> None:
    config: AppConfig = websocket.app.state.config
    if not config.web.terminal_enabled:
        await websocket.close(code=1008)
        return
    token = websocket.query_params.get("token", "")
    registry = _registry(websocket)
    ticket = registry.consume(token)
    if ticket is None:
        await websocket.close(code=1008)
        return

    secrets_to_mask = collect_config_secrets(config)
    await websocket.accept()
    audit = AuditService(config)
    audit.record(
        actor=ticket.actor,
        action="terminal.session",
        outcome="opened",
        source_ip=ticket.source_ip,
        details={"cwd": ticket.cwd},
    )
    try:
        await _run_terminal(
            websocket,
            ticket,
            secrets_to_mask,
            idle_timeout=config.web.terminal_idle_timeout,
        )
    finally:
        registry.release()
        audit.record(
            actor=ticket.actor,
            action="terminal.session",
            outcome="closed",
            source_ip=ticket.source_ip,
        )


def _registry(request: Request | WebSocket) -> TerminalRegistry:
    registry = getattr(request.app.state, "terminal_registry", None)
    if not isinstance(registry, TerminalRegistry):
        config: AppConfig = request.app.state.config
        registry = TerminalRegistry(config.web.terminal_max_sessions)
        request.app.state.terminal_registry = registry
    return registry


def _require_terminal_enabled(config: AppConfig) -> None:
    if not config.web.terminal_enabled:
        raise HTTPException(status_code=403, detail="web terminal is disabled")


def _validate_cwd(value: str) -> Path:
    cwd = Path(value)
    if not cwd.is_absolute():
        raise HTTPException(status_code=400, detail="cwd must be an absolute path")
    if not cwd.exists() or not cwd.is_dir():
        raise HTTPException(status_code=400, detail="cwd does not exist or is not a directory")
    return cwd


async def _run_terminal(
    websocket: WebSocket,
    ticket: TerminalTicket,
    secrets_to_mask: list[str],
    idle_timeout: int,
) -> None:
    env = {
        **os.environ,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "xterm-256color",
        "COLORTERM": "truecolor",
        "PS1": "kornode# " if os.geteuid() == 0 else "kornode$ ",
        "PROMPT_COMMAND": "",
    }
    pid = -1
    master_fd = -1
    child_exited = False
    try:
        pid, master_fd = pty.fork()
        if pid == 0:
            os.chdir(ticket.cwd)
            _resize_pty(0, ticket.rows, ticket.cols)
            os.execvpe("/bin/bash", ["/bin/bash", "--noprofile", "--norc", "-i"], env)

        _resize_pty(master_fd, ticket.rows, ticket.cols)
        await websocket.send_text(f"Connected to /bin/bash in {ticket.cwd}\r\n")
        reader = asyncio.create_task(_pty_to_websocket(websocket, master_fd, pid, secrets_to_mask))
        writer = asyncio.create_task(
            _websocket_to_pty(websocket, master_fd, idle_timeout=idle_timeout)
        )
        done, pending = await asyncio.wait(
            {reader, writer},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        for task in done:
            with contextlib.suppress(WebSocketDisconnect, asyncio.CancelledError):
                result = task.result()
                if task is reader and result is True:
                    child_exited = True
    finally:
        if master_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(master_fd)
        if pid > 0 and not child_exited:
            _terminate_child(pid)


async def _pty_to_websocket(
    websocket: WebSocket,
    master_fd: int,
    pid: int,
    secrets_to_mask: list[str],
) -> bool:
    child_exited = False
    while True:
        chunk = await asyncio.to_thread(_read_pty_chunk, master_fd)
        if chunk:
            await websocket.send_text(mask_text(chunk, secrets_to_mask))
        if not child_exited:
            child_exited = _child_exited(pid)
        if child_exited and not chunk:
            await websocket.send_text("\r\n[terminal exited]\r\n")
            return True


async def _websocket_to_pty(
    websocket: WebSocket,
    master_fd: int,
    *,
    idle_timeout: int,
) -> None:
    while True:
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=idle_timeout)
        except TimeoutError:
            await websocket.send_text("\r\n[terminal closed after idle timeout]\r\n")
            return
        message = _terminal_message(raw)
        message_type = message.get("type")
        if message_type == "input":
            data = str(message.get("data", ""))
            if data:
                os.write(master_fd, data.encode())
        elif message_type == "resize":
            rows = _bounded_int(message.get("rows"), 10, 80, 30)
            cols = _bounded_int(message.get("cols"), 40, 240, 100)
            _resize_pty(master_fd, rows, cols)


def _terminal_message(raw: str) -> dict[str, Any]:
    try:
        message = json.loads(raw)
    except json.JSONDecodeError:
        return {"type": "input", "data": raw}
    return message if isinstance(message, dict) else {"type": "input", "data": raw}


def _read_pty_chunk(master_fd: int) -> str:
    readable, _, _ = select.select([master_fd], [], [], 0.2)
    if not readable:
        return ""
    with contextlib.suppress(OSError):
        return os.read(master_fd, 8192).decode(errors="replace")
    return ""


def _child_exited(pid: int) -> bool:
    try:
        waited_pid, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return waited_pid == pid


def _terminate_child(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if _child_exited(pid):
            return
        time.sleep(0.05)

    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    _child_exited(pid)


def _resize_pty(fd: int, rows: int, cols: int) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    with contextlib.suppress(OSError):
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def _bounded_int(value: object, minimum: int, maximum: int, fallback: int) -> int:
    if isinstance(value, bool):
        return fallback
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value)
        except ValueError:
            return fallback
    else:
        return fallback
    return min(max(parsed, minimum), maximum)
