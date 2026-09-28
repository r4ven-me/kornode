from __future__ import annotations

import base64
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status

from kornode.services.password_hash import verify_password

SESSION_COOKIE = "kornode_session"

# A session renews (slides) its expiry on every use via get() below, so a
# cookie that's actively used never naturally expires on its own. Cap the
# total lifetime at a fixed multiple of the configured session_lifetime
# regardless of activity, so a leaked/stolen cookie can't stay valid
# indefinitely just by being periodically replayed -- while still letting an
# admin who is actively using the panel stay logged in past one raw
# session_lifetime window, unlike a hard `now - created_at > lifetime` cap.
ABSOLUTE_SESSION_LIFETIME_MULTIPLIER = 4


@dataclass(frozen=True)
class BasicCredentials:
    username: str
    password: str


@dataclass
class AdminSession:
    username: str
    csrf_token: str
    expires_at: float
    created_at: float


class AuthSessionRegistry:
    def __init__(self, lifetime_seconds: int = 3600) -> None:
        self._lifetime_seconds = lifetime_seconds
        self._absolute_lifetime_seconds = lifetime_seconds * ABSOLUTE_SESSION_LIFETIME_MULTIPLIER
        self._sessions: dict[str, AdminSession] = {}
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def create(self, username: str) -> tuple[str, AdminSession]:
        with self._lock:
            self._prune()
            token = secrets.token_urlsafe(48)
            now = time.monotonic()
            session = AdminSession(
                username=username,
                csrf_token=secrets.token_urlsafe(32),
                expires_at=now + self._lifetime_seconds,
                created_at=now,
            )
            self._sessions[token] = session
            return token, session

    def get(self, token: str) -> AdminSession | None:
        with self._lock:
            self._prune()
            session = self._sessions.get(token)
            if session is None:
                return None
            session.expires_at = time.monotonic() + self._lifetime_seconds
            return session

    def revoke(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def login_allowed(self, source: str, limit: int = 5, window_seconds: int = 300) -> bool:
        with self._lock:
            cutoff = time.monotonic() - window_seconds
            attempts = [item for item in self._failures.get(source, []) if item >= cutoff]
            self._failures[source] = attempts
            return len(attempts) < limit

    def record_failure(self, source: str) -> None:
        with self._lock:
            self._failures.setdefault(source, []).append(time.monotonic())

    def clear_failures(self, source: str) -> None:
        with self._lock:
            self._failures.pop(source, None)

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [
            token
            for token, session in self._sessions.items()
            if session.expires_at <= now
            or now - session.created_at > self._absolute_lifetime_seconds
        ]
        for token in expired:
            self._sessions.pop(token, None)


def auth_registry(request: Request) -> AuthSessionRegistry:
    registry = getattr(request.app.state, "auth_sessions", None)
    if not isinstance(registry, AuthSessionRegistry):
        registry = AuthSessionRegistry(request.app.state.config.web.session_lifetime)
        request.app.state.auth_sessions = registry
    return registry


def authenticate_password(request: Request, username: str, password: str) -> None:
    config = request.app.state.config
    expected_password = config.web.admin_password
    expected_hash = config.web.admin_password_hash
    if expected_password is None and expected_hash is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin password is not configured",
        )
    source = request.client.host if request.client else "unknown"
    registry = auth_registry(request)
    if not registry.login_allowed(source):
        raise HTTPException(status_code=429, detail="too many failed login attempts")
    password_matches = (
        verify_password(password, expected_hash)
        if expected_hash is not None
        else expected_password is not None
        and secrets.compare_digest(password, expected_password)
    )
    if not (secrets.compare_digest(username, config.web.admin_user) and password_matches):
        registry.record_failure(source)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    registry.clear_failures(source)


def require_admin(request: Request) -> None:
    session_token = request.cookies.get(SESSION_COOKIE)
    if session_token:
        session = auth_registry(request).get(session_token)
        if session is not None:
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                csrf_token = request.headers.get("x-kornode-csrf", "")
                if not secrets.compare_digest(csrf_token, session.csrf_token):
                    raise HTTPException(status_code=403, detail="CSRF validation failed")
            request.state.admin_username = session.username
            request.state.admin_session = session
            return

    credentials = parse_basic_authorization(request.headers.get("authorization"))
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
        )
    authenticate_password(request, credentials.username, credentials.password)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        _reject_cross_origin_basic_request(request)
    request.state.admin_username = credentials.username


def _reject_cross_origin_basic_request(request: Request) -> None:
    """Same-origin check for mutating requests authenticated via HTTP Basic.

    Basic Auth has no CSRF token to check the way the cookie-session branch
    above does: unlike a JS-issued header, there is no session for a
    non-browser API client (curl, a script) to have fetched one from. But a
    BROWSER that has ever authenticated to this origin with Basic Auth
    caches those credentials and resends them automatically on *any*
    request to the same origin -- including one triggered by a third-party
    page's plain `<form method=post>`, which needs no JS and isn't stopped
    by SameSite cookie rules since no cookie is involved at all. Without
    this check, that made every mutating endpoint CSRF-exploitable against
    an admin who had ever used Basic Auth in a browser.

    A browser always sends Origin (or, lacking that, Referer) on a
    cross-origin state-changing request; a legitimate non-browser client
    typically sends neither. So only a header that's present AND names a
    different host is rejected -- its absence is not.
    """
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return
    origin_host = urlparse(origin).hostname
    request_host = (request.headers.get("host") or "").split(":", 1)[0]
    if origin_host and request_host and origin_host != request_host:
        raise HTTPException(status_code=403, detail="cross-origin request rejected")


def parse_basic_authorization(value: str | None) -> BasicCredentials | None:
    if not value:
        return None
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "basic" or not token:
        return None
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    username, separator, password = decoded.partition(":")
    if not separator:
        return None
    return BasicCredentials(username=username, password=password)


def admin_identity(request: Request) -> dict[str, object]:
    config = request.app.state.config
    session = getattr(request.state, "admin_session", None)
    return {
        "authenticated": True,
        "username": getattr(request.state, "admin_username", config.web.admin_user),
        "csrf_token": session.csrf_token if isinstance(session, AdminSession) else None,
    }
