from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from kornode.bundle.errors import BundleError

MAX_BODY_BYTES = 1024 * 1024
_VOLATILE = ("version", "generated_at")


def canonical_json(value: Any) -> bytes:
    """Stable encoding used by the hub. The agent never re-encodes a body."""
    _reject_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise BundleError("malformed", "floats are not allowed in a bundle body")
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _reject_floats(item)


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def content_hash(digested: Mapping[str, Any]) -> str:
    """Hash of the content that survives re-sealing (D-37).

    `digested` is the body with every secret already replaced by its HMAC
    (`sealing.digest_secrets`); `version` and `generated_at` are dropped here.
    """
    stripped = {key: value for key, value in digested.items() if key not in _VOLATILE}
    return hashlib.sha256(canonical_json(stripped)).hexdigest()
