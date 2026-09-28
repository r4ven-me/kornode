from __future__ import annotations

import contextlib
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from kornode import __version__
from kornode.api import (
    routes_auth,
    routes_certificates,
    routes_client_sync,
    routes_config,
    routes_diagnostics,
    routes_groups,
    routes_identity,
    routes_internal_dns,
    routes_logs,
    routes_routing,
    routes_server,
    routes_sessions,
    routes_terminal,
    routes_upstream,
    routes_users,
    routes_web_config,
)
from kornode.config.loader import DEFAULT_CONFIG_PATH, load_config
from kornode.config.models import AppConfig
from kornode.services.audit import AuditService
from kornode.services.command import CommandError


def create_app(
    config: AppConfig | None = None,
    config_path: Path | str | None = None,
) -> FastAPI:
    if config_path is None:
        config_path_env = os.getenv("KORNODE_CONFIG")
        resolved_config_path = Path(config_path_env) if config_path_env else DEFAULT_CONFIG_PATH
    else:
        resolved_config_path = Path(config_path)
    if config is None:
        config = load_config(resolved_config_path)

    app = FastAPI(title="Korvus Node API", version=__version__)
    app.state.config = config
    app.state.config_path = resolved_config_path

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            f"http://{config.web.listen}:{config.web.port}",
            f"https://{config.web.listen}:{config.web.port}",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'"
        )
        if config.web.tls:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if (
            request.url.path.startswith("/api/")
            and request.method in {"POST", "PUT", "PATCH", "DELETE"}
        ):
            # Best-effort, same tradeoff as UpstreamService._append_log: the
            # mutating action itself already fully executed and its
            # response is already built by the time this runs -- disk
            # full/read-only/permission issues writing audit.jsonl must not
            # turn an otherwise-successful request into an unhandled 500
            # with no indication the action actually succeeded, and must
            # not swallow the response either (unlike record() failing, the
            # response itself is unaffected).
            with contextlib.suppress(OSError):
                AuditService(request.app.state.config).record(
                    actor=getattr(request.state, "admin_username", "anonymous"),
                    action=f"{request.method} {request.url.path}",
                    outcome="success" if response.status_code < 400 else "failure",
                    source_ip=request.client.host if request.client else None,
                    details={"status_code": response.status_code},
                )
        return response

    @app.exception_handler(ValueError)
    def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(CommandError)
    def command_error_handler(_request: Request, exc: CommandError) -> JSONResponse:
        result = exc.result
        detail = result.stderr.strip() or result.stdout.strip() or str(exc)
        return JSONResponse(
            status_code=502,
            content={
                "detail": detail,
                "argv": list(result.argv),
                "returncode": result.returncode,
            },
        )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(routes_auth.router, prefix="/api/auth", tags=["auth"])
    app.include_router(routes_config.router, prefix="/api/config", tags=["config"])
    app.include_router(
        routes_certificates.router,
        prefix="/api/certificates",
        tags=["certificates"],
    )
    app.include_router(routes_server.router, prefix="/api/server", tags=["server"])
    app.include_router(routes_users.router, prefix="/api/users", tags=["users"])
    app.include_router(routes_groups.router, prefix="/api/groups", tags=["groups"])
    app.include_router(routes_sessions.router, prefix="/api/sessions", tags=["sessions"])
    app.include_router(routes_identity.router, prefix="/api/identity", tags=["identity"])
    app.include_router(routes_routing.router, prefix="/api/routing", tags=["routing"])
    app.include_router(
        routes_internal_dns.router,
        prefix="/api/internal-dns",
        tags=["internal-dns"],
    )
    app.include_router(
        routes_client_sync.router,
        prefix="/api/client",
        tags=["client-sync"],
    )
    app.include_router(routes_upstream.router, prefix="/api/upstream", tags=["upstream"])
    app.include_router(routes_terminal.router, prefix="/api/terminal", tags=["terminal"])
    app.include_router(routes_diagnostics.router, prefix="/api/diagnostics", tags=["diagnostics"])
    app.include_router(routes_logs.router, prefix="/api/logs", tags=["logs"])
    app.include_router(routes_web_config.router, prefix="/api/web-config", tags=["web-config"])

    if config.web.enabled and config.web.static_dir.exists():
        app.mount("/", StaticFiles(directory=config.web.static_dir, html=True), name="frontend")

    return app
