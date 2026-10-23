from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import BaseModel

from kornode.api.auth import require_admin
from kornode.api.routes_config import apply_config_patch, runtime_config_path
from kornode.config.models import AppConfig
from kornode.services.apply import apply_dns_configuration, client_dns_signature
from kornode.services.command import CommandResult
from kornode.services.host_dns import HostDnsService
from kornode.services.net import NetApplyError, NetService

router = APIRouter(dependencies=[Depends(require_admin)])


class DryRunRequest(BaseModel):
    dry_run: bool = False


class RoutingSettingsRequest(BaseModel):
    host_dns: str | None = None
    main_interface: str | None = None


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


@router.post("/settings")
def save_routing_settings(
    request: Request,
    payload: RoutingSettingsRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, object]:
    patch: dict[str, object] = {}
    if payload.host_dns is not None:
        patch["host_dns"] = payload.host_dns
    if payload.main_interface is not None:
        patch["main_interface"] = payload.main_interface
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
        config_path=runtime_config_path(request),
    )
    # RUNTIME: one reconciler pass over the live kernel state.
    try:
        net_result: dict[str, object] = NetService(loaded_config).apply()
    except NetApplyError as exc:
        net_result = {"applied": False, "error": str(exc)}
    # Apply right away instead of waiting for host-dns-guard's next cycle.
    # RUNTIME: touches the mounted host resolver files, if any.
    host_dns = HostDnsService(loaded_config).apply()
    return {
        "status": "saved_and_applied",
        "written": written,
        "reconnect_required": reconnect_required,
        "routing": loaded_config.routing.model_dump(mode="json"),
        "dns": command_results(dns_commands),
        "net": net_result,
        "host_dns": host_dns.as_dict(),
    }


@router.get("/host-dns")
def host_dns_status(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return HostDnsService(config).status()
