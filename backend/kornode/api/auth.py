from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status

from kornode.config.models import AppConfig
from kornode.services.admin_totp import AdminTotpService
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
        self._auth_fingerprint: bytes | None = None
        self._generation = 0
        # Replay protection for sign-in TOTP: the last accepted time step. Per process;
        # a restart forgets it (the window reopens for at most ~90 s).
        self._totp_step = -1

    def accept_totp_step(self, step: int) -> bool:
        """Accept a sign-in TOTP step once: not newer than the last accepted one is a replay."""
        with self._lock:
            if step <= self._totp_step:
                return False
            self._totp_step = step
            return True

    def synchronize(self, config: AppConfig) -> None:
        """Invalidate cookies when the running application's auth config changes."""
        fingerprint = _auth_fingerprint(config)
        with self._lock:
            if self._auth_fingerprint != fingerprint:
                self._sessions.clear()
                self._generation += 1
                self._auth_fingerprint = fingerprint
                # A replay now also needs the new credentials.
                self._totp_step = -1

    def revoke_all(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._generation += 1
            self._totp_step = -1

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def require_current_authority(self, generation: int, session_token: str | None) -> None:
        with self._lock:
            self._prune()
            if generation != self._generation or (
                session_token is not None and session_token not in self._sessions
            ):
                raise HTTPException(status_code=401, detail="authentication_changed")

    def create(
        self, username: str, *, expected_generation: int | None = None
    ) -> tuple[str, AdminSession]:
        with self._lock:
            # A credential change must also reject logins that started before
            # revocation but finish verifying the old credentials afterward.
            if expected_generation is not None and expected_generation != self._generation:
                raise HTTPException(status_code=401, detail="authentication_changed")
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
    registry.synchronize(request.app.state.config)
    return registry


def _auth_fingerprint(config: AppConfig) -> bytes:
    web = config.web
    # Keep an opaque snapshot, not another plaintext copy of credentials.
    return hashlib.sha256(
        json.dumps(
            [
                web.admin_user,
                web.admin_password,
                web.admin_password_hash,
                web.admin_totp_enabled,
                web.admin_totp_secret,
            ],
            ensure_ascii=True,
        ).encode("utf-8")
    ).digest()


def invalidate_auth_sessions(
    request: Request, previous_config: AppConfig, new_config: AppConfig
) -> None:
    """Call after a successful config update; unrelated settings preserve sessions.

    This is process-local, like the session registry itself. Config files modified
    by an external CLI are not reloaded by the API; once a new config is installed
    in app.state, auth_registry() also detects the change on the next auth check.
    """
    if _auth_fingerprint(previous_config) != _auth_fingerprint(new_config):
        registry = getattr(request.app.state, "auth_sessions", None)
        if isinstance(registry, AuthSessionRegistry):
            registry.revoke_all()
            registry.synchronize(new_config)


def authenticate_totp(request: Request, code: str | None, *, consume: bool = False) -> None:
    """consume=True (sign-in) accepts a code once; reauthentication of an existing
    session also needs the password, the session and CSRF, so it may reuse the code
    that just signed in."""
    config = request.app.state.config
    if not config.web.admin_totp_enabled:
        return
    if not code:
        raise HTTPException(status_code=401, detail="totp_code_required")
    registry = auth_registry(request)
    # Separate from password failures, which are cleared by a valid password.
    source = f"totp:{request.client.host if request.client else 'unknown'}"
    if not registry.login_allowed(source):
        raise HTTPException(status_code=429, detail="too many failed login attempts")
    secret = config.web.admin_totp_secret
    try:
        step = AdminTotpService(config).matching_step(secret, code) if secret else None
        valid = step is not None and (not consume or registry.accept_totp_step(step))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        registry.record_failure(source)
        raise HTTPException(status_code=401, detail="invalid_totp_code")
    registry.clear_failures(source)


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
        and secrets.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))
    )
    if not (
        secrets.compare_digest(username.encode("utf-8"), config.web.admin_user.encode("utf-8"))
        and password_matches
    ):
        registry.record_failure(source)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    registry.clear_failures(source)


def require_admin(request: Request) -> None:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        _reject_cross_origin_basic_request(request)
    registry = auth_registry(request)
    generation = registry.generation
    session_token = request.cookies.get(SESSION_COOKIE)
    if session_token:
        session = registry.get(session_token)
        if session is not None:
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                csrf_token = request.headers.get("x-kornode-csrf", "")
                if not secrets.compare_digest(csrf_token, session.csrf_token):
                    raise HTTPException(status_code=403, detail="CSRF validation failed")
            request.state.admin_username = session.username
            request.state.admin_session = session
            request.state.admin_auth_generation = generation
            return

    credentials = parse_basic_authorization(request.headers.get("authorization"))
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
        )
    if request.app.state.config.web.admin_totp_enabled:
        raise HTTPException(status_code=401, detail="totp_session_required")
    authenticate_password(request, credentials.username, credentials.password)
    request.state.admin_username = credentials.username
    request.state.admin_auth_generation = generation


def _reject_cross_origin_basic_request(request: Request) -> None:
    """Validate the full browser origin; headerless scripted Basic still works.

    Use the ASGI URL (including its scheme), not untrusted forwarding headers.
    Trusted reverse-proxy scheme/host normalization belongs at the server boundary.
    """
    origins = request.headers.getlist("origin")
    referers = request.headers.getlist("referer")
    values = origins if origins else referers
    if not values:
        return
    try:
        if len(values) != 1 or not values[0] or any(c.isspace() for c in values[0]):
            raise ValueError
        origin = urlparse(values[0])
        target = urlparse(str(request.url))
        if (
            origin.scheme not in {"http", "https"}
            or not origin.hostname
            or origin.username is not None
            or origin.password is not None
            or origin.fragment
            or (origins and (origin.path or origin.query))
        ):
            raise ValueError
        defaults = {"http": 80, "https": 443}
        origin_port = origin.port if origin.port is not None else defaults[origin.scheme]
        target_port = target.port if target.port is not None else defaults[target.scheme]
        origin_tuple = (origin.scheme, origin.hostname, origin_port)
        target_tuple = (target.scheme, target.hostname, target_port)
        if origin_tuple == target_tuple:
            return
    except (ValueError, KeyError):
        pass
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
