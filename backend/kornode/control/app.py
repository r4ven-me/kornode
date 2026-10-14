"""ASGI app of the control API: thin handlers over `ControlService`."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.background import BackgroundTask

from kornode import __version__
from kornode.config.loader import DEFAULT_CONFIG_PATH, load_config
from kornode.config.models import AppConfig
from kornode.control.auth import NODE_ID_KEY, MutualTLSMiddleware
from kornode.control.errors import ControlError
from kornode.control.service import (
    MAX_ENROLL_BYTES,
    MAX_REPORT_BYTES,
    MAX_RESULT_BYTES,
    POLL_INTERVAL_SECONDS,
    ControlService,
    check_version,
)
from kornode.registry.models import Command, StoredBundle

ENROLL_SESSION_GRACE_SECONDS = 5.0
LOGGER = logging.getLogger("kornode.control")
PREFIX = "/agent/v1"


def command_json(command: Command) -> dict[str, Any]:
    return {
        "id": command.id,
        "type": command.type,
        "args": command.args,
        "expires_at": command.expires_at,
    }


def bundle_json(bundle: StoredBundle) -> dict[str, Any]:
    return {
        "version": bundle.version,
        "body_b64": base64.b64encode(bundle.body).decode("ascii"),
        "signature": bundle.signature,
    }


async def read_json(request: Request, limit: int) -> Any:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise ControlError("invalid", "request body is too large", 413)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise ControlError("invalid", "request body is too large", 413)
    try:
        return json.loads(bytes(body))
    except ValueError as exc:
        raise ControlError("invalid", "request body is not JSON") from exc


async def long_poll[ResultT](check: Callable[[], ResultT | None], wait: float) -> ResultT | None:
    """Run `check` (blocking, registry access) until it yields or `wait` runs out."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    while True:
        found = await asyncio.to_thread(check)
        remaining = deadline - loop.time()
        if found is not None or remaining <= 0:
            return found
        await asyncio.sleep(min(POLL_INTERVAL_SECONDS, remaining))


def create_app(
    config: AppConfig | None = None,
    service: ControlService | None = None,
    config_path: Path | str | None = None,
    enroll_grace_seconds: float = ENROLL_SESSION_GRACE_SECONDS,
) -> FastAPI:
    if config is None:
        path = config_path or os.getenv("KORNODE_CONFIG") or DEFAULT_CONFIG_PATH
        config = load_config(Path(path))
    if not config.control.enabled:
        raise RuntimeError("control.enabled is false")
    control = service or ControlService(config)
    max_wait = float(config.control.long_poll_seconds)

    app = FastAPI(
        title="kornode control API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.control = control

    def wait_param(wait: float) -> float:
        return min(max(wait, 0.0), max_wait)

    def node_id(request: Request) -> int:
        return int(request.scope["state"][NODE_ID_KEY])

    @app.exception_handler(ControlError)
    async def control_error(_: Request, exc: ControlError) -> JSONResponse:
        return JSONResponse(exc.body(), status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            ControlError("invalid", "invalid request parameters").body(), status_code=400
        )

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("control API failure", exc_info=exc)
        return JSONResponse(ControlError("internal", "internal error").body(), status_code=500)

    @app.get(f"{PREFIX}/ping", status_code=204)
    async def ping(request: Request) -> Response:
        await asyncio.to_thread(control.touch, node_id(request))
        return Response(status_code=204)

    @app.get(f"{PREFIX}/bundle")
    async def bundle(
        request: Request,
        since: Annotated[int, Query()] = 0,
        wait: Annotated[float, Query()] = 0.0,
    ) -> Response:
        agent = node_id(request)
        check_version(since)
        await asyncio.to_thread(control.touch, agent)
        found = await long_poll(lambda: control.latest_for(agent, since), wait_param(wait))
        if found is None:
            return Response(status_code=304)
        return Response(
            found.body,
            media_type="application/json",
            headers={
                "X-Kornode-Signature": found.signature,
                "X-Kornode-Version": str(found.version),
            },
        )

    @app.get(f"{PREFIX}/poll")
    async def poll(
        request: Request,
        since: Annotated[int, Query()] = 0,
        wait: Annotated[float, Query()] = 0.0,
    ) -> JSONResponse:
        agent = node_id(request)
        check_version(since)
        await asyncio.to_thread(control.touch, agent)

        def check() -> tuple[StoredBundle | None, list[Command]] | None:
            found = control.latest_for(agent, since)
            commands = control.pending_commands(agent) if control.has_commands(agent) else []
            return (found, commands) if found is not None or commands else None

        result = await long_poll(check, wait_param(wait))
        found, commands = result if result is not None else (None, [])
        return JSONResponse(
            {
                "bundle": None if found is None else bundle_json(found),
                "commands": [command_json(item) for item in commands],
            }
        )

    @app.get(f"{PREFIX}/commands")
    async def commands(request: Request, wait: Annotated[float, Query()] = 0.0) -> Response:
        agent = node_id(request)
        await asyncio.to_thread(control.touch, agent)

        def check() -> list[Command] | None:
            return control.pending_commands(agent) or None if control.has_commands(agent) else None

        found = await long_poll(check, wait_param(wait))
        if not found:
            return Response(status_code=204)
        return JSONResponse([command_json(item) for item in found])

    @app.post(f"{PREFIX}/report", status_code=204)
    async def report(request: Request) -> Response:
        data = await read_json(request, MAX_REPORT_BYTES)
        await asyncio.to_thread(control.store_report, node_id(request), data)
        return Response(status_code=204)

    @app.post(f"{PREFIX}/commands/{{command_id}}/result", status_code=204)
    async def command_result(request: Request, command_id: str) -> Response:
        data = await read_json(request, MAX_RESULT_BYTES)
        await asyncio.to_thread(control.finish_command, node_id(request), command_id, data)
        return Response(status_code=204)

    @app.post(f"{PREFIX}/renew")
    async def renew(request: Request) -> JSONResponse:
        data = await read_json(request, MAX_ENROLL_BYTES)
        return JSONResponse(await asyncio.to_thread(control.renew, node_id(request), data))

    @app.post(f"{PREFIX}/enroll")
    async def enroll(request: Request) -> JSONResponse:
        client = request.scope.get("client")
        source_ip = client[0] if client else None
        data = await read_json(request, MAX_ENROLL_BYTES)
        result, token_id = await asyncio.to_thread(control.enroll, data, source_ip)

        async def end_session() -> None:
            # The answer rides the enroll tunnel being cut: give TCP time to deliver it.
            await asyncio.sleep(enroll_grace_seconds)
            await asyncio.to_thread(control.end_enroll_session, token_id)

        return JSONResponse(result, background=BackgroundTask(end_session))

    app.add_middleware(MutualTLSMiddleware, authenticate=control.authenticate)
    return app
