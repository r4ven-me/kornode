"""Per-value secret sealing (D-16, D-36).

The hub builds a *plan* in which every secret is `{"$secret": "<plaintext>"}`.
`seal_secrets` turns the plan into the wire form, `digest_secrets` into the
form hashed for dedup; the agent only ever sees the sealed form.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import os
from collections.abc import Iterator, Mapping
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kornode.bundle.errors import BundleError

SEAL_ALG = "x25519-hkdf-sha256-chacha20poly1305"
SECRET_MARKER = "$secret"
_INFO_PREFIX = "kornode-bundle-secret-v1"
_SEALED_KEYS = frozenset({"alg", "epk", "nonce", "ct"})


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise BundleError("malformed", "invalid base64 in sealed value") from exc


def secret_info(node_id: int, pointer: str) -> str:
    return f"{_INFO_PREFIX}|{node_id}|{pointer}"


def public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _derive(shared: bytes, epk: bytes, seal_pubkey: bytes, info: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=epk + seal_pubkey,
        info=info.encode(),
    ).derive(shared)


def seal(plaintext: str, seal_pubkey: bytes, node_id: int, pointer: str) -> dict[str, str]:
    info = secret_info(node_id, pointer)
    ephemeral = X25519PrivateKey.generate()
    epk = public_bytes(ephemeral.public_key())
    try:
        recipient = X25519PublicKey.from_public_bytes(seal_pubkey)
        shared = ephemeral.exchange(recipient)
    except ValueError as exc:
        raise BundleError("malformed", "invalid seal public key") from exc
    key = _derive(shared, epk, seal_pubkey, info)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode(), info.encode())
    return {"alg": SEAL_ALG, "epk": _b64(epk), "nonce": _b64(nonce), "ct": _b64(ct)}


def unseal(
    sealed: Mapping[str, Any],
    private_key: X25519PrivateKey,
    node_id: int,
    pointer: str,
) -> str:
    if set(sealed) != _SEALED_KEYS or sealed["alg"] != SEAL_ALG:
        raise BundleError("malformed", f"{pointer}: not a sealed value")
    info = secret_info(node_id, pointer)
    epk = _unb64(str(sealed["epk"]))
    nonce = _unb64(str(sealed["nonce"]))
    ct = _unb64(str(sealed["ct"]))
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(epk))
        key = _derive(shared, epk, public_bytes(private_key.public_key()), info)
        return ChaCha20Poly1305(key).decrypt(nonce, ct, info.encode()).decode()
    except (InvalidTag, ValueError) as exc:
        raise BundleError("unseal_failed", f"{pointer}: cannot unseal value") from exc


def escape_pointer(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _walk(value: Any, pointer: str, marker: bool) -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        is_leaf = (SECRET_MARKER in value) if marker else (set(value) == _SEALED_KEYS)
        if is_leaf:
            yield pointer, value
            return
        for key, item in value.items():
            yield from _walk(item, f"{pointer}/{escape_pointer(str(key))}", marker)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, f"{pointer}/{index}", marker)


def walk_sealed(body: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    """(JSON pointer, sealed object) for every sealed value in a wire body."""
    return _walk(body, "", marker=False)


def walk_secrets(plan: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    return _walk(plan, "", marker=True)


def _rewrite(plan: Any, convert: Any) -> Any:
    result = copy.deepcopy(plan)
    for pointer, _ in list(walk_secrets(plan)):
        parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]
        node = result
        for part in parts[:-1]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        leaf = parts[-1]
        slot = int(leaf) if isinstance(node, list) else leaf
        node[slot] = convert(pointer, str(node[slot][SECRET_MARKER]))
    return result


def seal_secrets(plan: Mapping[str, Any], seal_pubkey: bytes, node_id: int) -> dict[str, Any]:
    result: dict[str, Any] = _rewrite(
        plan, lambda pointer, text: seal(text, seal_pubkey, node_id, pointer)
    )
    return result


def digest_secrets(plan: Mapping[str, Any], master_key: bytes, node_id: int) -> dict[str, Any]:
    """Replace each secret by HMAC(master key, info || 0 || plaintext) (D-37)."""

    def convert(pointer: str, text: str) -> dict[str, str]:
        info = secret_info(node_id, pointer).encode()
        digest = hmac.new(master_key, info + b"\x00" + text.encode(), hashlib.sha256)
        return {"hmac": digest.hexdigest()}

    result: dict[str, Any] = _rewrite(plan, convert)
    return result
