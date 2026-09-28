from __future__ import annotations

import base64
import secrets
import threading
import urllib.parse
from dataclasses import dataclass

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.files import FileManager
from kornode.services.users import UserService

# Serializes the read-modify-write cycle on users.oath, the same hazard
# users.py's _PASSWD_REWRITE_LOCK protects against for ocpasswd: two
# concurrent enable/disable calls would otherwise each read the same
# original file and the last write would silently discard the other's
# change.
_OATH_REWRITE_LOCK = threading.Lock()


@dataclass(frozen=True)
class OtpRecord:
    username: str
    enabled: bool


class OtpService:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.oath_file = config.secret_path("users.oath")
        self.users = UserService(config, runner=self.runner, files=self.files)

    def list_records(self) -> list[OtpRecord]:
        records: list[OtpRecord] = []
        for line in self.files.read_lines(self.oath_file):
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                records.append(OtpRecord(username=parts[1], enabled=True))
        return records

    def generate_secret(self) -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

    def enable(self, username: str) -> str:
        self.users.validate_username(username)
        secret = self.generate_secret()
        self.files.ensure_dir(self.config.system.secrets_dir, mode=0o700)
        with _OATH_REWRITE_LOCK:
            lines = [
                line
                for line in self.files.read_lines(self.oath_file)
                if line.split()[1:2] != [username]
            ]
            lines.append(f"HOTP/T30/6 {username} - {secret}")
            self.files.atomic_write_private_text(self.oath_file, "\n".join(lines) + "\n")
        return secret

    def disable(self, username: str) -> bool:
        self.users.validate_username(username)
        # Explicit, not just relying on atomic_write_private_text's own
        # auto-created-parent fallback (which uses a world-readable 0o755
        # default) -- matches enable() above so this directory is never
        # created with looser permissions depending on which OTP operation
        # happens to run first.
        self.files.ensure_dir(self.config.system.secrets_dir, mode=0o700)
        with _OATH_REWRITE_LOCK:
            lines = self.files.read_lines(self.oath_file)
            kept = [line for line in lines if line.split()[1:2] != [username]]
            changed = len(kept) != len(lines)
            if changed:
                self.files.atomic_write_private_text(
                    self.oath_file,
                    "\n".join(kept) + ("\n" if kept else ""),
                )
        return changed

    def secret_for_user(self, username: str) -> str | None:
        self.users.validate_username(username)
        for line in self.files.read_lines(self.oath_file):
            parts = line.split()
            if len(parts) >= 4 and parts[1] == username:
                return parts[3]
        return None

    def otpauth_uri(self, username: str) -> str:
        secret = self.secret_for_user(username)
        if secret is None:
            raise ValueError(f"OTP is not enabled for {username}")
        issuer = self.config.auth.otp.issuer
        label = urllib.parse.quote(f"{issuer}:{username}")
        query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "digits": "6"})
        return f"otpauth://totp/{label}?{query}"

    def qr_ansi(self, username: str) -> CommandResult:
        uri = self.otpauth_uri(username)
        return self.runner.run(
            ["qrencode", "-t", "ANSIUTF8", "-o", "-"],
            input_text=uri,
            timeout=10,
            extra_secrets=[uri, self.secret_for_user(username) or ""],
        )

    def qr_svg(self, username: str) -> CommandResult:
        uri = self.otpauth_uri(username)
        return self.runner.run(
            ["qrencode", "-t", "SVG", "-o", "-"],
            input_text=uri,
            timeout=10,
            extra_secrets=[uri, self.secret_for_user(username) or ""],
        )
