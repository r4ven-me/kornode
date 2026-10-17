"""Admin-only recovery transport. Upload is ciphertext; no plaintext archive on disk."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response, StreamingResponse

from kornode.api.auth import require_admin
from kornode.services.agent_models import ManagementError
from kornode.services.backup import BackupService
from kornode.services.backup_crypto import MAX_ARCHIVE, password_bytes

router = APIRouter(dependencies=[Depends(require_admin)])


async def bounded_body(request: Request, limit: int) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise ManagementError(413, "too_large", "backup request exceeds size limit")
        body.extend(chunk)
    return bytes(body)


@router.post("/backup")
async def hub_backup(request: Request) -> Response:
    try:
        data = json.loads(await bounded_body(request, 8192))
        if (
            not isinstance(data, dict)
            or set(data) != {"passphrase"}
            or not isinstance(data["passphrase"], str)
        ):
            raise ValueError()
        passphrase = data["passphrase"]
        password_bytes(passphrase)
    except (ValueError, UnicodeError):
        raise ManagementError(422, "invalid", "expected a backup passphrase") from None
    archive = await run_in_threadpool(BackupService(request.app.state.config).create, passphrase)
    name = datetime.now(UTC).strftime("hub-%Y%m%dT%H%M%SZ.knbackup")
    return StreamingResponse(
        (archive[offset : offset + 65536] for offset in range(0, len(archive), 65536)),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/restore")
async def hub_restore(request: Request) -> dict[str, Any]:
    # Base64 is just HTTP-header encoding, not encryption: use HTTPS. The
    # standard audit middleware records route/status only, never headers/body.
    encoded = request.headers.get("X-Kornode-Backup-Passphrase", "")
    try:
        if len(encoded) > 1400:
            raise ValueError()
        passphrase = base64.b64decode(encoded, validate=True).decode("utf-8")
        password_bytes(passphrase)
        if set(request.query_params) - {"dry_run", "confirm"}:
            raise ValueError()
        dry = request.query_params.get("dry_run", "true")
        if dry not in {"true", "false"}:
            raise ValueError()
        if dry == "false" and request.query_params.get("confirm") != "restore":
            raise ManagementError(422, "confirmation_required", "confirm staging the hub restore")
    except (ValueError, UnicodeError):
        raise ManagementError(
            422, "invalid", "invalid restore options or passphrase encoding"
        ) from None
    archive = await bounded_body(request, MAX_ARCHIVE)
    return await run_in_threadpool(
        BackupService(request.app.state.config).restore,
        archive,
        passphrase,
        dry_run=dry == "true",
    )
