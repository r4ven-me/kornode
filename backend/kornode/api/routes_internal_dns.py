from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch
from kornode.config.models import AppConfig
from kornode.services.apply import apply_dns_configuration, client_dns_signature
from kornode.services.command import CommandResult
from kornode.services.internal_dns import InternalDnsService

router = APIRouter(dependencies=[Depends(require_admin)])


class InternalDnsSettingsRequest(BaseModel):
    server_dns: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    search_domains: list[str] = Field(default_factory=list)
    listen: str = "10.10.10.1"
    port: int = Field(default=53, ge=1, le=65535)
    blocklist_enabled: bool = False
    local_records_enabled: bool = False
    blocklist_domains: list[str] = Field(default_factory=list)
    blocklist_files: list[str] = Field(default_factory=list)
    blocklist_urls: list[str] = Field(default_factory=list)
    cache_size: int = Field(default=150, ge=0, le=10000)
    log_queries: bool = False
    local_records: list[str] = Field(default_factory=list)
    upstreams: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    forward_upstreams: list[str] = Field(default_factory=list)
    forward_domains: list[str] = Field(default_factory=list)


class BlocklistRefreshRequest(BaseModel):
    url: str
    preview: bool = False


@router.get("/status")
def internal_dns_status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return InternalDnsService(config).status()


@router.get("/blocklist")
def internal_dns_blocklist(
    request: Request,
    limit: int = Query(default=1000, ge=1, le=100000),
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    merged = InternalDnsService(config).merged_blocklist()
    return {"total": len(merged), "domains": merged[:limit]}


@router.post("/settings")
def save_internal_dns_settings(
    request: Request,
    payload: InternalDnsSettingsRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, object]:
    previous_config: AppConfig = request.app.state.config
    previous_client_dns = client_dns_signature(previous_config)
    patch: dict[str, object] = {
        "server": {
            "dns": payload.server_dns,
            "search_domains": payload.search_domains,
        },
        "internal_dns": {
            "listen": payload.listen,
            "port": payload.port,
            "blocklist_enabled": payload.blocklist_enabled,
            "local_records_enabled": payload.local_records_enabled,
            "blocklist_domains": payload.blocklist_domains,
            "blocklist_files": payload.blocklist_files,
            "blocklist_urls": payload.blocklist_urls,
            "cache_size": payload.cache_size,
            "log_queries": payload.log_queries,
            "local_records": payload.local_records,
            "upstreams": payload.upstreams,
            "forward_upstreams": payload.forward_upstreams,
            "forward_domains": payload.forward_domains,
        },
    }
    loaded_config, written = apply_config_patch(request, patch)
    reconnect_required = previous_client_dns != client_dns_signature(loaded_config)
    commands = apply_dns_configuration(
        loaded_config,
        background_tasks,
        reconnect_clients=reconnect_required,
    )
    return {
        "status": "saved_and_applied",
        "written": written,
        "reconnect_required": reconnect_required,
        "commands": [_command_payload(result) for result in commands],
        "internal_dns": InternalDnsService(loaded_config).status(),
    }


def _command_payload(result: CommandResult) -> dict[str, object]:
    return {
        "argv": list(result.argv),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


@router.post("/apply")
def apply_internal_dns(
    request: Request,
    background_tasks: BackgroundTasks,
) -> list[dict[str, object]]:
    """Explicitly apply DNS configuration and reconnect active clients."""
    config: AppConfig = request.app.state.config
    results = apply_dns_configuration(config, background_tasks, reconnect_clients=True)
    return [_command_payload(result) for result in results]


@router.post("/blocklist/refresh")
def refresh_blocklist(
    request: Request,
    payload: BlocklistRefreshRequest,
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    if payload.url not in config.internal_dns.blocklist_urls:
        raise HTTPException(
            status_code=400,
            detail="url is not one of the saved internal_dns.blocklist_urls; save it first",
        )
    result = InternalDnsService(config).refresh_url_blocklist(payload.url, preview=payload.preview)
    written: list[str] = []
    if result.saved and config.internal_dns.blocklist_enabled:
        from kornode.services.config import ConfigService

        written = [str(path) for path in ConfigService().write_rendered_files(config)]
    return {
        "status": "previewed" if payload.preview else "refreshed",
        "url": result.url,
        "total_lines": result.total_lines,
        "valid": result.valid,
        "skipped": result.skipped,
        "sample": result.sample,
        "saved": result.saved,
        "written": written,
    }
