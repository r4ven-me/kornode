"""Per-request authentication of agents: client certificate, CRL, node state."""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from starlette.responses import JSONResponse

from kornode.control.errors import ControlError
from kornode.control.tls import PEER_CERT_KEY

ENROLL_PATH = "/agent/v1/enroll"
AGENTS_OU = "agents"
NODE_ID_KEY = "node_id"

type Authenticate = Callable[[bytes | None, str | None], int]


class RevocationList:
    """CRL of the kornode CA, re-read when the file changes.

    Fail closed: a missing, unreadable, forged or expired list refuses every
    request (503) instead of letting revoked agents through."""

    def __init__(
        self,
        crl_path: Path,
        ca_path: Path,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._crl_path = crl_path
        self._ca_path = ca_path
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._stamp: tuple[int, int] | None = None
        self._serials: frozenset[int] = frozenset()
        self._next_update: datetime | None = None

    def is_revoked(self, serial: int) -> bool:
        with self._lock:
            self._refresh()
            return serial in self._serials

    def _refresh(self) -> None:
        try:
            stat = self._crl_path.stat()
        except OSError as exc:
            raise ControlError("internal", "revocation list is missing", 503) from exc
        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp != self._stamp:
            try:
                ca = x509.load_pem_x509_certificate(self._ca_path.read_bytes())
                crl = x509.load_pem_x509_crl(self._crl_path.read_bytes())
                if not crl.is_signature_valid(ca.public_key()):  # type: ignore[arg-type]
                    raise ValueError("signature")
            except (OSError, ValueError) as exc:
                self._stamp = None
                raise ControlError("internal", "revocation list is unreadable", 503) from exc
            self._serials = frozenset(item.serial_number for item in crl)
            self._next_update = crl.next_update_utc
            self._stamp = stamp
        if self._next_update is not None and self._clock() >= self._next_update:
            raise ControlError("internal", "revocation list is stale", 503)


def agent_identity(der: bytes | None) -> tuple[int, int]:
    """(node id, certificate serial) of a verified client certificate."""
    if not der:
        raise ControlError("unauthorized", "client certificate required")
    try:
        cert = x509.load_der_x509_certificate(der)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        units = [
            attribute.value
            for attribute in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        ]
    except (ValueError, IndexError) as exc:
        raise ControlError("unauthorized", "unusable client certificate") from exc
    name = cn if isinstance(cn, str) else cn.decode("utf-8", errors="replace")
    prefix, _, number = name.partition("-")
    if prefix != "agent" or not number.isdigit() or AGENTS_OU not in units:
        raise ControlError("unauthorized", "certificate is not an agent certificate")
    return int(number), cert.serial_number


class MutualTLSMiddleware:
    """Requires an authenticated agent on every route except `POST /enroll`."""

    def __init__(self, app: Any, authenticate: Authenticate) -> None:
        self.app = app
        self.authenticate = authenticate

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state: dict[str, Any] = scope.setdefault("state", {})
        public = scope["method"] == "POST" and scope["path"] == ENROLL_PATH
        if public:
            # Whatever certificate came along does not identify anybody here.
            state.pop(NODE_ID_KEY, None)
        else:
            client = scope.get("client")
            source_ip = client[0] if client else None
            try:
                state[NODE_ID_KEY] = await asyncio.to_thread(
                    self.authenticate, state.get(PEER_CERT_KEY), source_ip
                )
            except ControlError as exc:
                await JSONResponse(exc.body(), status_code=exc.status)(
                    scope,
                    receive,
                    send,  # type: ignore[arg-type]
                )
                return
        await self.app(scope, receive, send)


class RateLimiter:
    """Sliding window per key, in process (the control API is one process)."""

    def __init__(
        self, limit: int, window_seconds: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Count the attempt; False once `limit` attempts fall in the window."""
        now = self._clock()
        with self._lock:
            recent = [stamp for stamp in self._hits.get(key, []) if now - stamp < self.window]
            if len(recent) >= self.limit:
                self._hits[key] = recent
                return False
            recent.append(now)
            self._hits[key] = recent
            if len(self._hits) > 4096:
                self._evict(now)
            return True

    def _evict(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or now - v[-1] >= self.window]:
            with contextlib.suppress(KeyError):
                del self._hits[key]
