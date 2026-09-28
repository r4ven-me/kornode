from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner

_TOTP_STEP_SECONDS = 30
_TOTP_DIGITS = 6


class AdminTotpService:
    def __init__(self, config: AppConfig, runner: CommandRunner | None = None) -> None:
        self.config = config
        self.runner = runner or CommandRunner()

    def generate_secret(self) -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

    def otpauth_uri(self, secret: str) -> str:
        issuer = "Korvus Node"
        admin_user = self.config.web.admin_user
        label = urllib.parse.quote(f"{issuer}:{admin_user}")
        query = urllib.parse.urlencode(
            {"secret": secret, "issuer": issuer, "digits": str(_TOTP_DIGITS)}
        )
        return f"otpauth://totp/{label}?{query}"

    def qr_svg(self, secret: str) -> CommandResult:
        uri = self.otpauth_uri(secret)
        return self.runner.run(
            ["qrencode", "-t", "SVG", "-o", "-"],
            input_text=uri,
            timeout=10,
            extra_secrets=[uri, secret],
        )

    def _code_at(self, secret: str, counter: int) -> str:
        padded = secret.upper()
        padded += "=" * (-len(padded) % 8)
        key = base64.b32decode(padded)
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(truncated % (10**_TOTP_DIGITS)).zfill(_TOTP_DIGITS)

    def verify_code(self, secret: str, code: str, window: int = 1) -> bool:
        code = code.strip()
        if not code.isdigit() or len(code) != _TOTP_DIGITS:
            return False
        counter = int(time.time()) // _TOTP_STEP_SECONDS
        for offset in range(-window, window + 1):
            if hmac.compare_digest(self._code_at(secret, counter + offset), code):
                return True
        return False
