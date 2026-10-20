"""Versioned, bounded backup envelope. No attacker-controlled KDF cost parameters."""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from kornode.services.agent_models import ManagementError

MAGIC = b"KORNODE-BACKUP\x00\x01"
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_PLAINTEXT = MAX_ARCHIVE - 128
SALT_SIZE = 16
NONCE_SIZE = 12


def password_bytes(passphrase: str) -> bytes:
    encoded = passphrase.encode("utf-8")
    if not 12 <= len(encoded) <= 1024:
        raise ManagementError(422, "invalid_passphrase", "use a passphrase of 12–1024 UTF-8 bytes")
    return encoded


def _key(passphrase: str, salt: bytes) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(
        password_bytes(passphrase)
    )


def encrypt(data: bytes, passphrase: str) -> bytes:
    if len(data) > MAX_PLAINTEXT:
        raise ManagementError(413, "too_large", "hub backup exceeds the 128 MiB archive limit")
    salt, nonce = secrets.token_bytes(SALT_SIZE), secrets.token_bytes(NONCE_SIZE)
    header = MAGIC + salt + nonce
    return header + ChaCha20Poly1305(_key(passphrase, salt)).encrypt(nonce, data, header)


def decrypt(archive: bytes, passphrase: str) -> bytes:
    password_bytes(passphrase)
    offset = len(MAGIC)
    if (
        len(archive) > MAX_ARCHIVE
        or len(archive) < offset + SALT_SIZE + NONCE_SIZE + 16
        or not archive.startswith(MAGIC)
    ):
        raise ManagementError(422, "invalid_archive", "unsupported or invalid backup envelope")
    salt = archive[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = archive[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    try:
        return ChaCha20Poly1305(_key(passphrase, salt)).decrypt(
            nonce, archive[offset:], archive[:offset]
        )
    except InvalidTag:
        raise ManagementError(
            422, "invalid_archive", "incorrect passphrase or damaged backup"
        ) from None
