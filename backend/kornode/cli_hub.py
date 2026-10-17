"""Hub recovery CLI; passphrases never appear in argv, JSON, or exceptions."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer

from kornode.cli_agents import Json, confirmed, invoke
from kornode.config.models import AppConfig
from kornode.services.agent_models import ManagementError
from kornode.services.backup import BackupService
from kornode.services.backup_crypto import MAX_ARCHIVE, password_bytes


def passphrase_value(path: Path | None, *, confirm: bool, json_output: bool) -> str:
    if path is None:
        if json_output:
            raise ManagementError(422, "passphrase_required", "use --passphrase-file with --json")
        value = str(typer.prompt("Backup passphrase", hide_input=True, confirmation_prompt=confirm))
    else:
        try:
            with path.open("rb") as handle:
                data = handle.read(1026)
            value = data.removesuffix(b"\n").decode("utf-8")
        except (OSError, UnicodeError):
            raise ManagementError(
                422, "invalid_passphrase", "could not read passphrase file"
            ) from None
    password_bytes(value)
    return value


def register(app: typer.Typer, config: Callable[[], AppConfig]) -> None:
    hub = typer.Typer(help="Encrypted hub backup and staged restore (no live network changes)")

    @hub.command("backup")
    def backup(
        out: Path | None = typer.Option(
            None, "--out", help="New encrypted archive file; never overwritten."
        ),
        passphrase_file: Path | None = typer.Option(
            None,
            "--passphrase-file",
            help="Private UTF-8 passphrase file; otherwise hidden prompt.",
        ),
        json: Json = False,
    ) -> None:
        def run() -> dict[str, Any]:
            password = passphrase_value(passphrase_file, confirm=True, json_output=json)
            destination = out or Path(datetime.now(UTC).strftime("hub-%Y%m%dT%H%M%SZ.knbackup"))
            data = BackupService(config()).create(password)
            BackupService.publish(destination, data)
            return {"archive": str(destination), "bytes": len(data), "encrypted": True}

        invoke(run, json)

    @hub.command("restore")
    def restore(
        archive: Path,
        target: Path | None = typer.Option(
            None,
            "--target",
            help="New, nonexistent staging directory; defaults to data_dir/restores/.",
        ),
        passphrase_file: Path | None = typer.Option(None, "--passphrase-file"),
        dry_run: bool = typer.Option(
            False, "--dry-run", help="Decrypt and validate without writing a restore tree."
        ),
        yes: bool = typer.Option(False, "--yes", help="Confirm writing a private restore tree."),
        json: Json = False,
    ) -> None:
        def run() -> dict[str, Any]:
            confirmed(
                yes, dry_run, json, "Restore hub into a NEW private directory (live hub unchanged)?"
            )
            password = passphrase_value(passphrase_file, confirm=False, json_output=json)
            try:
                with archive.open("rb") as handle:
                    data = handle.read(MAX_ARCHIVE + 1)
            except OSError:
                raise ManagementError(
                    422, "invalid_archive", "could not read encrypted archive"
                ) from None
            return BackupService(config()).restore(data, password, target=target, dry_run=dry_run)

        invoke(run, json)

    app.add_typer(hub, name="hub")
