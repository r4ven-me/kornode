from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from kornode.api.auth import require_admin
from kornode.config.models import AppConfig
from kornode.services.diagnostics import DiagnosticsService
from kornode.services.network_stats import NetworkStatsService
from kornode.services.software_versions import SoftwareVersionService

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("")
def diagnostics(request: Request) -> dict[str, dict[str, object]]:
    config: AppConfig = request.app.state.config
    return {
        name: {
            "argv": result.argv,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "dry_run": result.dry_run,
        }
        for name, result in DiagnosticsService(config).run().items()
    }


@router.get("/interface-stats")
def interface_stats(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    return NetworkStatsService(config).snapshot()


@router.get("/software")
def software_versions() -> list[dict[str, object]]:
    return [
        {
            "name": row.name,
            "version": row.version,
            "command": list(row.command) if row.command else None,
            "status": row.status,
        }
        for row in SoftwareVersionService().collect()
    ]
