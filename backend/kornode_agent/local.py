"""Owner-only local RPC. No network listener, shell operations or kernel writer."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import ipaddress
import json
import logging
import os
import socket
import stat
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

MAX_REQUEST = 8192
MAX_RESPONSE = 8 * 1024 * 1024
READ_TIMEOUT = 5.0
# A confirm window can take 600 s, plus baseline/blame and a queued apply.
ACTION_TIMEOUT = 1500.0


class LocalError(RuntimeError):
    def __init__(self, error: str, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.error = error
        self.exit_code = exit_code

    def as_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": self.error, "message": str(self), "exit_code": self.exit_code}


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    op: Literal["status", "explain", "doctor", "diag", "rollback", "reconnect"]
    src: str | None = None
    dst: str | None = None
    proto: Literal["tcp", "udp", "icmp", "icmpv6"] | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    version: int | None = Field(default=None, ge=1, le=2**31 - 1)
    dry_run: bool = False
    tunnel: str | None = Field(default=None, pattern=r"^(interlink|upstream:[a-zA-Z0-9_-]+)$")

    @model_validator(mode="after")
    def check_args(self) -> Self:
        allowed = {
            "explain": {"src", "dst", "proto", "port"},
            "rollback": {"version", "dry_run"},
            "reconnect": {"tunnel", "dry_run"},
        }
        supplied = self.model_fields_set - {"op"}
        if supplied - allowed.get(self.op, set()):
            raise ValueError("irrelevant arguments for operation")
        if self.op == "rollback" and self.version is None:
            raise ValueError("rollback requires a version")
        if self.op == "explain":
            if self.src != "host":
                ipaddress.ip_address(self.src or "")
            ipaddress.ip_address(self.dst or "")
            if self.port is not None and self.proto not in (None, "tcp", "udp"):
                raise ValueError("port requires TCP or UDP")
        return self


def socket_path(root: Path) -> Path:
    return root / "run" / "agent.sock"


class ProcessLock:
    """Held before boot until workers stop. Never unlink a lock inode."""

    def __init__(self, root: Path) -> None:
        self.path = root / "run" / "agent.lock"
        self.fd: int | None = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise LocalError("already_running", "agent is already running", 3) from exc
        self.fd = fd
        return self

    def __exit__(self, *args: Any) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


log = logging.getLogger("kornode_agent.local")
Dispatch = Callable[[Request], Awaitable[dict[str, Any]]]


class LocalServer:
    def __init__(self, root: Path, dispatch: Dispatch) -> None:
        self.path = socket_path(root)
        self.dispatch = dispatch
        self.server: asyncio.Server | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self.identity: tuple[int, int] | None = None

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise LocalError("socket_conflict", "refusing to replace a symlink at agent socket", 3)
        if self.path.exists():
            info = self.path.stat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise LocalError("socket_conflict", "refusing to replace agent socket path", 3)
            # The process lock is acquired by Agent before this point. An active
            # listener still means a conflict, not permission to unlink it.
            with socket.socket(socket.AF_UNIX) as probe:
                probe.settimeout(0.2)
                try:
                    probe.connect(str(self.path))
                except ConnectionRefusedError:
                    self.path.unlink()
                else:
                    raise LocalError("already_running", "agent socket is already listening", 3)
        # Set permissions before listen: no world-accessible window even if
        # this directory pre-exists with more permissive mode bits.
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            self.path.chmod(0o600)
            info = self.path.stat()
            self.identity = (info.st_dev, info.st_ino)
            listener.listen(16)
            listener.setblocking(False)
            self.server = await asyncio.start_unix_server(
                self._accept, sock=listener, limit=MAX_REQUEST
            )
        except BaseException:
            listener.close()
            raise

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(self._handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                line = await asyncio.wait_for(reader.readline(), READ_TIMEOUT)
                if not line.endswith(b"\n") or len(line) > MAX_REQUEST:
                    raise ValueError("invalid frame")
                req = Request.model_validate_json(line)
            except (ValueError, ValidationError, TimeoutError):
                raise LocalError("usage", "invalid or oversized local request", 2) from None
            result = await self.dispatch(req)
            reply = {"ok": True, "data": result}
        except LocalError as exc:
            reply = exc.as_dict()
        except asyncio.CancelledError:
            writer.close()
            raise
        except Exception as exc:
            # Exceptions can include pydantic input values, URLs or credentials:
            # log only the type, never the message or traceback.
            log.error("local action failed: %s", type(exc).__name__)
            reply = LocalError(
                "internal_error", "local action failed; inspect agent diagnostics"
            ).as_dict()
        try:
            data = json.dumps(reply).encode() + b"\n"
            if len(data) > MAX_RESPONSE:
                data = (
                    json.dumps(
                        LocalError("too_large", "local response exceeds 8 MiB").as_dict()
                    ).encode()
                    + b"\n"
                )
            writer.write(data)
            await asyncio.wait_for(writer.drain(), READ_TIMEOUT)
        except (OSError, TimeoutError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
        # Cancel handlers before wait_closed(): on Python 3.12+ it waits for
        # every open connection, so a slow handler would stall shutdown.
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.server is not None:
            await self.server.wait_closed()
        with contextlib.suppress(FileNotFoundError):
            info = self.path.lstat()
            if (info.st_dev, info.st_ino) == self.identity:
                self.path.unlink()


def request(root: Path, req: Request, *, timeout: float | None = None) -> dict[str, Any]:
    """One request per connection. Never retry a mutation after a timeout."""
    timeout = (
        timeout
        if timeout is not None
        else (ACTION_TIMEOUT if req.op in ("rollback", "reconnect") else 120.0)
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(socket_path(root)))
            sock.sendall(req.model_dump_json(exclude_unset=True).encode() + b"\n")
            with sock.makefile("rb") as stream:
                line = stream.readline(MAX_RESPONSE + 1)
        if len(line) > MAX_RESPONSE or not line.endswith(b"\n"):
            raise ValueError("bad frame")
        reply = json.loads(line)
        if not isinstance(reply, dict) or not isinstance(reply.get("ok"), bool):
            raise ValueError("bad reply")
        if not reply["ok"]:
            code = reply.get("exit_code", 1)
            if type(code) is not int or code not in range(1, 5):
                raise ValueError("bad error code")
            raise LocalError(
                str(reply.get("error", "error")), str(reply.get("message", "failed")), code
            )
        if not isinstance(reply.get("data"), dict):
            raise ValueError("bad result")
        return dict(reply["data"])
    except (FileNotFoundError, ConnectionRefusedError) as exc:
        raise LocalError(
            "agent_unavailable", "agent is not running; start kornode-agent run"
        ) from exc
    except TimeoutError as exc:
        raise LocalError(
            "local_timeout", "local action timed out; check status before retrying"
        ) from exc
    except (OSError, ValueError) as exc:
        raise LocalError(
            "local_transport", "cannot read agent response (permissions or protocol)"
        ) from exc
