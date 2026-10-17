"""Safe management views of bundles and untrusted reports (no runtime dependencies)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

REDACTED = "[redacted]"
_SECRET = re.compile(
    r"password|passphrase|pw_hash|passwd|secret|token|camouflage|private|server_key|^key$|^seal$|cookie|authorization"
    r"|credential|psk|preshared|api[_-]?key|auth[_-]?key|(?<![a-z])session(?![a-z])|(?<![a-z])otp(?![a-z])|bearer",
    re.I,
)
# Public by design: keeping them readable is what makes a rotation checkable.
_PUBLIC = re.compile(r"pub(?:lic)?[_-]?key|fingerprint|sha256|digest", re.I)
_PEM = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", re.S)
_ASSIGN = re.compile(
    r"""(?im)(["']?(?:[\w-]*(?:password|passphrase|pw_hash|passwd|private|secret|token|camouflage|cookie|authorization|server_key|credential|psk|preshared|api[_-]?key|auth[_-]?key|session|otp)[\w-]*)["']?\s*[:=]\s*)("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|[^\s,;\n}]+)"""
)


class Redactor:
    def __init__(self, known: Iterable[str] = ()) -> None:
        self.known = sorted({value for value in known if value}, key=len, reverse=True)

    def text(self, value: str) -> str:
        value = _PEM.sub(REDACTED, value)
        value = re.sub(r"(?m)^(?![0-9a-f]{32,}$)[A-Za-z0-9+/]{32,}={0,2}$", REDACTED, value)
        value = re.sub(r"(?im)^.*(?:authorization|set-cookie|cookie)\s*:.*$", REDACTED, value)
        value = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", r"\1 " + REDACTED, value)
        value = re.sub(r"(https?://)[^/\s@]+@", r"\1[redacted]@", value)
        value = re.sub(r"(https?://[^\s?]+)\?[^\s\"'<>]+", r"\1?[redacted]", value)
        value = re.sub(r'\{[^{}]*"(?:ct|epk)"\s*:[^{}]*\}', REDACTED, value)
        value = _ASSIGN.sub(lambda m: m[1] + REDACTED, value)
        for secret in self.known:
            value = value.replace(secret, REDACTED)
        return value

    def data(self, value: Any) -> Any:
        if isinstance(value, dict):
            if {"alg", "epk", "nonce", "ct"} <= value.keys():
                return REDACTED
            return {key: self._item(str(key), item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.data(item) for item in value]
        return self.text(value) if isinstance(value, str) else value

    def _item(self, key: str, item: Any) -> Any:
        if _SECRET.search(key):
            # A flag like `credentials_set: false` carries no secret.
            return item if item is None or isinstance(item, bool) else REDACTED
        if isinstance(item, str) and _PUBLIC.search(key):
            return item
        return self.data(item)
