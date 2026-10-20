"""Authenticated operator API; all domain logic lives in AgentService."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from kornode.api.auth import require_admin
from kornode.services.agent_models import AgentCreate, AgentPatch, ManagementError, PrefixInput
from kornode.services.agents import AgentService, parse
from kornode.services.control_management import ControlManagement

router = APIRouter(dependencies=[Depends(require_admin)])
control_router = APIRouter(dependencies=[Depends(require_admin)])
MAX_BODY = 1024 * 1024


def service(request: Request) -> AgentService:
    override: AgentService | None = getattr(request.app.state, "agent_management", None)
    return override or AgentService(request.app.state.config)


async def payload(request: Request) -> dict[str, Any]:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise ManagementError(413, "too_large", "management body exceeds 1 MiB")
    try:
        data = json.loads(body or b"{}")
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except (ValueError, UnicodeError):
        raise ManagementError(422, "invalid", "expected a JSON object") from None


def flags(data: dict[str, Any]) -> bool:
    if set(data) - {"dry_run"} or type(data.get("dry_run", False)) is not bool:
        raise ManagementError(422, "invalid", "expected only a boolean dry_run")
    return bool(data.get("dry_run", False))


@router.get("")
def agent_list(request: Request) -> dict[str, Any]:
    return service(request).list()


@router.post("")
async def agent_create(request: Request) -> dict[str, Any]:
    data = parse(AgentCreate, await payload(request))
    return await run_in_threadpool(service(request).create, data)


@router.get("/{name}")
def agent_show(name: str, request: Request) -> dict[str, Any]:
    return service(request).show(name)


@router.patch("/{name}")
async def agent_update(name: str, request: Request) -> dict[str, Any]:
    data = parse(AgentPatch, await payload(request))
    return await run_in_threadpool(service(request).update, name, data)


@router.post("/{name}/token")
async def agent_token(name: str, request: Request) -> dict[str, Any]:
    if await payload(request):
        raise ManagementError(422, "invalid", "token issuance takes no arguments")
    return await run_in_threadpool(service(request).token, name)


@router.delete("/{name}/token")
def agent_token_revoke(name: str, request: Request) -> dict[str, Any]:
    return service(request).token(name, revoke=True)


@router.post("/{name}/revoke")
async def agent_revoke(name: str, request: Request) -> dict[str, Any]:
    dry_run = flags(await payload(request))
    return await run_in_threadpool(service(request).revoke, name, dry_run=dry_run)


@router.delete("/{name}")
async def agent_delete(name: str, request: Request) -> dict[str, Any]:
    dry_run = flags(await payload(request))
    return await run_in_threadpool(service(request).delete, name, dry_run=dry_run)


@router.get("/{name}/prefixes")
def agent_prefixes(name: str, request: Request) -> dict[str, Any]:
    return service(request).prefixes(name)


@router.post("/{name}/prefixes")
async def agent_prefix_add(name: str, request: Request) -> dict[str, Any]:
    data = parse(PrefixInput, await payload(request))
    return await run_in_threadpool(service(request).add_prefix, name, data)


@router.delete("/{name}/prefixes")
async def agent_prefix_delete(name: str, request: Request) -> dict[str, Any]:
    data = await payload(request)
    if set(data) != {"prefix"} or not isinstance(data["prefix"], str):
        raise ManagementError(422, "invalid", "prefix is required")
    return await run_in_threadpool(service(request).delete_prefix, name, data["prefix"])


@router.get("/{name}/policy")
def agent_policy(name: str, request: Request) -> dict[str, Any]:
    return service(request).policy(name)


@router.put("/{name}/policy")
async def agent_policy_set(name: str, request: Request) -> dict[str, Any]:
    return await run_in_threadpool(service(request).set_policy, name, await payload(request))


@router.get("/{name}/sources")
def agent_sources(name: str, request: Request) -> dict[str, Any]:
    return service(request).sources(name)


@router.put("/{name}/sources/{source}")
async def agent_source_set(name: str, source: str, request: Request) -> dict[str, Any]:
    return await run_in_threadpool(
        service(request).set_source, name, source, await payload(request)
    )


@router.delete("/{name}/sources/{source}")
def agent_source_delete(name: str, source: str, request: Request) -> dict[str, Any]:
    return service(request).set_source(name, source, None)


@router.get("/{name}/upstreams")
def agent_upstreams(name: str, request: Request) -> dict[str, Any]:
    return service(request).upstreams(name)


@router.put("/{name}/upstreams/{upstream}")
async def agent_upstream_set(name: str, upstream: str, request: Request) -> dict[str, Any]:
    return await run_in_threadpool(
        service(request).set_upstream, name, upstream, await payload(request)
    )


@router.delete("/{name}/upstreams/{upstream}")
def agent_upstream_delete(name: str, upstream: str, request: Request) -> dict[str, Any]:
    return service(request).set_upstream(name, upstream, None)


@router.get("/{name}/access")
def agent_access(name: str, request: Request) -> dict[str, Any]:
    return service(request).access(name)


@router.put("/{name}/access")
async def agent_access_set(name: str, request: Request) -> dict[str, Any]:
    return await run_in_threadpool(service(request).set_access, name, await payload(request))


@router.delete("/{name}/access")
def agent_access_delete(name: str, request: Request) -> dict[str, Any]:
    return service(request).set_access(name, None)


@router.get("/{name}/users")
def agent_users(name: str, request: Request) -> dict[str, Any]:
    return service(request).users(name)


@router.put("/{name}/users/{username}")
async def agent_user_set(name: str, username: str, request: Request) -> dict[str, Any]:
    return await run_in_threadpool(
        service(request).set_user, name, username, await payload(request)
    )


@router.delete("/{name}/users/{username}")
def agent_user_delete(name: str, username: str, request: Request) -> dict[str, Any]:
    return service(request).set_user(name, username, None)


@router.get("/{name}/reports")
def agent_reports(name: str, request: Request, limit: int = 50) -> dict[str, Any]:
    return service(request).reports(name, limit)


@router.get("/{name}/bundles")
def agent_bundles(name: str, request: Request) -> dict[str, Any]:
    return service(request).bundles_list(name)


@router.get("/{name}/bundles/diff")
def agent_bundle_diff(name: str, a: int, b: int, request: Request) -> dict[str, Any]:
    return service(request).bundle_diff(name, a, b)


@router.get("/{name}/bundles/{version}")
def agent_bundle_show(name: str, version: int, request: Request) -> dict[str, Any]:
    return service(request).bundle(name, version)


@router.get("/{name}/commands")
def agent_commands(name: str, request: Request) -> dict[str, Any]:
    return service(request).commands(name)


@router.post("/{name}/commands")
async def agent_command_enqueue(name: str, request: Request) -> dict[str, Any]:
    return await run_in_threadpool(service(request).enqueue, name, await payload(request))


@router.get("/{name}/commands/{command_id}")
def agent_command(name: str, command_id: str, request: Request) -> dict[str, Any]:
    return service(request).command(name, command_id)


@router.get("/{name}/commands/{command_id}/artifact")
def agent_command_artifact(name: str, command_id: str, request: Request) -> Response:
    data = service(request).artifact(name, command_id)
    return Response(
        data,
        media_type="application/gzip",
        headers={
            "Content-Disposition": 'attachment; filename="agent-diagnostic.tar.gz"',
            "Cache-Control": "no-store",
        },
    )


@control_router.get("")
def control_status(request: Request) -> dict[str, Any]:
    override = getattr(request.app.state, "control_management", None)
    manager = override or ControlManagement(request.app.state.config)
    result: dict[str, Any] = manager.status()
    return result


@control_router.post("/rotate-signing-key")
async def control_rotate(request: Request) -> dict[str, Any]:
    dry_run = flags(await payload(request))
    manager = getattr(request.app.state, "control_management", None) or ControlManagement(
        request.app.state.config
    )
    result: dict[str, Any] = await run_in_threadpool(manager.rotate, dry_run=dry_run)
    return result
