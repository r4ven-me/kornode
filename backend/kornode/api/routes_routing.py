from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch
from kornode.config.models import AppConfig
from kornode.services.apply import apply_dns_configuration, client_dns_signature
from kornode.services.command import CommandResult
from kornode.services.config import ConfigService
from kornode.services.host_dns import HostDnsService
from kornode.services.nftables import NftablesService
from kornode.services.routing import RoutingService

router = APIRouter(dependencies=[Depends(require_admin)])


class ItemRequest(BaseModel):
    value: str


class ItemsRequest(BaseModel):
    items: list[str]


class DryRunRequest(BaseModel):
    dry_run: bool = False


class ListUrlRefreshRequest(BaseModel):
    url: str
    preview: bool = False


class RoutingSettingsRequest(BaseModel):
    client_policy: Literal["off", "full", "split"] = "full"
    host_policy: Literal["off", "full", "split"] = "off"
    host_dns: str | None = None
    main_interface: str | None = None
    fwmark: str | None = None
    table_id: int | None = None
    nft_prefix: str | None = None
    routes_urls: list[str] = Field(default_factory=list)
    domains_urls: list[str] = Field(default_factory=list)
    host_routes_urls: list[str] = Field(default_factory=list)
    host_domains_urls: list[str] = Field(default_factory=list)


def command_results(
    results: list[CommandResult],
    argv: tuple[str, ...] | None = None,
) -> list[dict[str, object]]:
    return [
        {
            "argv": list(argv or result.argv),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "dry_run": result.dry_run,
        }
        for result in results
    ]


@router.get("/routes")
def list_routes(request: Request) -> list[str]:
    config: AppConfig = request.app.state.config
    return RoutingService(config).list_routes()


@router.get("/routes/status")
def routes_status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    service = RoutingService(config)
    return {"urls": service.routes_urls_status()}


@router.get("/domains/status")
def domains_status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    service = RoutingService(config)
    return {"urls": service.domains_urls_status()}


@router.post("/routes/refresh")
def refresh_routes_url(request: Request, payload: ListUrlRefreshRequest) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    if payload.url not in config.routing.split.routes_urls:
        raise HTTPException(
            status_code=400,
            detail="url is not one of the saved routing.split.routes_urls; save it first",
        )
    result = RoutingService(config).refresh_route_url(payload.url, preview=payload.preview)
    written: list[str] = []
    if result.saved:
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


@router.post("/domains/refresh")
def refresh_domains_url(request: Request, payload: ListUrlRefreshRequest) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    if payload.url not in config.routing.split.domains_urls:
        raise HTTPException(
            status_code=400,
            detail="url is not one of the saved routing.split.domains_urls; save it first",
        )
    result = RoutingService(config).refresh_domain_url(payload.url, preview=payload.preview)
    written: list[str] = []
    if result.saved:
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


@router.get("/host-routes")
def list_host_routes(request: Request) -> list[str]:
    config: AppConfig = request.app.state.config
    return RoutingService(config).list_host_routes()


@router.put("/host-routes")
def set_host_routes(
    request: Request,
    payload: ItemsRequest,
) -> list[str]:
    config: AppConfig = request.app.state.config
    RoutingService(config).set_host_routes(payload.items)
    return RoutingService(config).list_host_routes()


@router.get("/host-routes/status")
def host_routes_status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    service = RoutingService(config)
    return {"urls": service.host_routes_urls_status()}


@router.post("/host-routes/refresh")
def refresh_host_routes_url(
    request: Request, payload: ListUrlRefreshRequest
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    if payload.url not in config.routing.host_split.routes_urls:
        raise HTTPException(
            status_code=400,
            detail="url is not one of the saved routing.host_split.routes_urls; save it first",
        )
    result = RoutingService(config).refresh_host_route_url(payload.url, preview=payload.preview)
    written: list[str] = []
    if result.saved:
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


@router.get("/host-domains")
def list_host_domains(request: Request) -> list[str]:
    config: AppConfig = request.app.state.config
    return RoutingService(config).list_host_domains()


@router.put("/host-domains")
def set_host_domains(
    request: Request,
    payload: ItemsRequest,
) -> list[str]:
    config: AppConfig = request.app.state.config
    RoutingService(config).set_host_domains(payload.items)
    return RoutingService(config).list_host_domains()


@router.get("/host-domains/status")
def host_domains_status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    service = RoutingService(config)
    return {"urls": service.host_domains_urls_status()}


@router.post("/host-domains/refresh")
def refresh_host_domains_url(
    request: Request, payload: ListUrlRefreshRequest
) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    if payload.url not in config.routing.host_split.domains_urls:
        raise HTTPException(
            status_code=400,
            detail="url is not one of the saved routing.host_split.domains_urls; save it first",
        )
    result = RoutingService(config).refresh_host_domain_url(payload.url, preview=payload.preview)
    written: list[str] = []
    if result.saved:
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


@router.post("/settings")
def save_routing_settings(
    request: Request,
    payload: RoutingSettingsRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, object]:
    split: dict[str, object] = {
        "routes_urls": payload.routes_urls,
        "domains_urls": payload.domains_urls,
    }
    host_split: dict[str, object] = {
        "routes_urls": payload.host_routes_urls,
        "domains_urls": payload.host_domains_urls,
    }
    patch: dict[str, object] = {
        "client_policy": payload.client_policy,
        "host_policy": payload.host_policy,
        "split": split,
        "host_split": host_split,
    }
    if payload.host_dns is not None:
        patch["host_dns"] = payload.host_dns
    if payload.main_interface is not None:
        patch["main_interface"] = payload.main_interface
    if payload.fwmark is not None:
        patch["fwmark"] = payload.fwmark
    if payload.table_id is not None:
        patch["table_id"] = payload.table_id
    if payload.nft_prefix is not None:
        patch["nft_prefix"] = payload.nft_prefix
    previous_client_dns = client_dns_signature(request.app.state.config)
    loaded_config, written = apply_config_patch(request, {"routing": patch})
    reconnect_required = previous_client_dns != client_dns_signature(loaded_config)
    # Same path as the DNS page: dnsmasq and ocserv follow the saved settings
    # right away, and clients reconnect only when what they see changed.
    # RUNTIME: starts/stops dnsmasq and may reload ocserv.
    dns_commands = apply_dns_configuration(
        loaded_config,
        background_tasks,
        reconnect_clients=reconnect_required,
    )
    # RUNTIME: rewrites live nftables state, same as the Upstream Apply button.
    nft_results = NftablesService(loaded_config).apply()
    # Apply right away instead of waiting for host-dns-guard's next cycle.
    # RUNTIME: touches the mounted host resolver files, if any.
    host_dns = HostDnsService(loaded_config).apply()
    return {
        "status": "saved_and_applied",
        "written": written,
        "reconnect_required": reconnect_required,
        "routing": loaded_config.routing.model_dump(mode="json"),
        "dns": command_results(dns_commands),
        "nft": command_results(nft_results),
        "host_dns": host_dns.as_dict(),
    }


@router.get("/host-dns")
def host_dns_status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return HostDnsService(config).status()


@router.post("/routes")
def add_route(
    request: Request,
    payload: ItemRequest,
) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    RoutingService(config).add_route(payload.value)
    return {"status": "added"}


@router.delete("/routes")
def delete_route(
    request: Request,
    payload: ItemRequest,
) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    RoutingService(config).delete_route(payload.value)
    return {"status": "deleted"}


@router.put("/routes")
def set_routes(
    request: Request,
    payload: ItemsRequest,
) -> list[str]:
    config: AppConfig = request.app.state.config
    RoutingService(config).set_routes(payload.items)
    return RoutingService(config).list_routes()


@router.get("/domains")
def list_domains(request: Request) -> list[str]:
    config: AppConfig = request.app.state.config
    return RoutingService(config).list_domains()


@router.post("/domains")
def add_domain(
    request: Request,
    payload: ItemRequest,
) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    RoutingService(config).add_domain(payload.value)
    return {"status": "added"}


@router.delete("/domains")
def delete_domain(
    request: Request,
    payload: ItemRequest,
) -> dict[str, str]:
    config: AppConfig = request.app.state.config
    RoutingService(config).delete_domain(payload.value)
    return {"status": "deleted"}


@router.put("/domains")
def set_domains(
    request: Request,
    payload: ItemsRequest,
) -> list[str]:
    config: AppConfig = request.app.state.config
    RoutingService(config).set_domains(payload.items)
    return RoutingService(config).list_domains()


@router.post("/reload")
def reload_routing(
    request: Request,
    payload: DryRunRequest | None = None,
) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    if not (payload and payload.dry_run):
        ConfigService().write_rendered_files(config)
    return command_results(
        NftablesService(config).apply(dry_run=payload.dry_run if payload else False),
        ("korctl", "routes", "reload"),
    )


@router.get("/nft")
def show_nft(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    result = NftablesService(config).show()
    return {
        "argv": ["korctl", "nft", "show"],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "dry_run": result.dry_run,
    }


@router.post("/nft/apply")
def apply_nft(
    request: Request,
    payload: DryRunRequest | None = None,
) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    return command_results(
        NftablesService(config).apply(dry_run=payload.dry_run if payload else False)
    )


@router.post("/nft/cleanup")
def cleanup_nft(
    request: Request,
    payload: DryRunRequest | None = None,
) -> list[dict[str, object]]:
    config: AppConfig = request.app.state.config
    return command_results(
        NftablesService(config).cleanup(dry_run=payload.dry_run if payload else False),
        ("korctl", "nft", "cleanup"),
    )
