from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from kornode.bundle.canonical import MAX_BODY_BYTES
from kornode.bundle.errors import BundleError

DOMAIN = b"kornode.bundle.v1\x00"


def raw_public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id(public_key: Ed25519PublicKey | bytes) -> str:
    raw = public_key if isinstance(public_key, bytes) else raw_public_bytes(public_key)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_or_create_signing_key(path: Path) -> Ed25519PrivateKey:
    """PKCS#8 PEM, 0600, created on first use (spec 05)."""
    if path.exists():
        key = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise BundleError("malformed", f"{path} is not an Ed25519 key")
        return key
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(tmp, path)  # never replace a key another process just created
    except FileExistsError:
        tmp.unlink()
        return load_or_create_signing_key(path)
    tmp.unlink()
    return key


def sign(body: bytes, key: Ed25519PrivateKey) -> str:
    signature = key.sign(DOMAIN + body)
    return f"ed25519:{key_id(key.public_key())}:{base64.b64encode(signature).decode('ascii')}"


def verify(body: bytes, envelope: str, trusted: dict[str, Ed25519PublicKey]) -> str:
    """Verify before any parsing; returns the key id that signed."""
    if len(body) > MAX_BODY_BYTES:
        raise BundleError("too_large", "bundle body exceeds 1 MiB")
    parts = envelope.split(":")
    if len(parts) != 3 or parts[0] != "ed25519":
        raise BundleError("bad_signature", "malformed signature envelope")
    public_key = trusted.get(parts[1])
    if public_key is None:
        raise BundleError("bad_signature", f"untrusted signing key {parts[1]!r}")
    try:
        public_key.verify(base64.b64decode(parts[2], validate=True), DOMAIN + body)
    except (InvalidSignature, ValueError) as exc:
        raise BundleError("bad_signature", "signature does not verify") from exc
    return parts[1]
