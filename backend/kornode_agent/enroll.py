"""Enrollment, agent side (spec 05 "Enrollment")."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import NameOID

from kornode.bundle.errors import BundleError
from kornode.bundle.sealing import public_bytes
from kornode.bundle.validator import validate
from kornode_agent import __version__
from kornode_agent.config import AgentConfig, FabricConfig, HubConfig, save_config
from kornode_agent.control import ControlClient, decode_enroll_bundle
from kornode_agent.store import (
    State,
    Store,
    StoreError,
    atomic_write,
    trust_from_enroll,
)


class TokenError(ValueError):
    pass


@dataclass(frozen=True)
class EnrollToken:
    host: str
    port: int
    pin: str
    control_url: str
    token_id: str
    user: str
    secret: str = field(repr=False)
    expires: datetime
    camouflage: str | None = field(repr=False)


def parse_token(text: str) -> EnrollToken:
    """base64url JSON, padding optional; the hub strips it."""
    text = text.strip()
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        doc: dict[str, Any] = json.loads(raw)
        if doc["v"] != 1:
            raise TokenError(f"unsupported token version {doc['v']!r}")
        host, _, port = str(doc["hub"]).rpartition(":")
        control_url = str(doc["control"])
        if urlsplit(control_url).scheme != "https":
            raise TokenError("control URL must be https")
        return EnrollToken(
            host=host,
            port=int(port),
            pin=str(doc["pin"]),
            control_url=control_url,
            token_id=str(doc["id"]),
            user=str(doc["user"]),
            secret=str(doc["secret"]),
            expires=datetime.fromisoformat(str(doc["exp"]).replace("Z", "+00:00")),
            camouflage=str(doc["camouflage"]) if doc.get("camouflage") else None,
        )
    except TokenError:
        raise
    except (ValueError, KeyError, TypeError) as exc:
        raise TokenError(f"malformed enrollment token: {exc}") from exc


def token_expired(token: EnrollToken, now: datetime | None = None) -> bool:
    return (now or datetime.now(UTC)) >= token.expires


@dataclass(frozen=True)
class Keys:
    tls_key_pem: bytes
    csr_pem: str
    seal_key: X25519PrivateKey

    @property
    def seal_pubkey_b64(self) -> str:
        return base64.b64encode(public_bytes(self.seal_key.public_key())).decode("ascii")


def generate_keys() -> Keys:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kornode-agent")]))
        .sign(key, hashes.SHA256())
    )
    return Keys(
        tls_key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        seal_key=X25519PrivateKey.generate(),
    )


def write_seal_key(root: Path, key: X25519PrivateKey) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    atomic_write(root / "seal" / "x25519.key", pem, 0o600)


def load_seal_key(root: Path) -> X25519PrivateKey:
    key = serialization.load_pem_private_key(
        (root / "seal" / "x25519.key").read_bytes(), password=None
    )
    if not isinstance(key, X25519PrivateKey):
        raise StoreError("seal/x25519.key is not an X25519 key")
    return key


def is_enrolled(root: Path) -> bool:
    return (root / "agent.yaml").exists() and (root / "tls" / "cert.pem").exists()


async def enroll(
    root: Path, token: EnrollToken, client: ControlClient, *, now: datetime | None = None
) -> State:
    """Exchange the token for a certificate; the enroll bundle is only verified.

    It is not cached: the run loop's first `poll(since=0)` delivers the same
    bundle and applies it with confirm (spec 05 step 5), keeping a single path.

    The caller has dialed the enroll session. Nothing is written to `root`
    until the response is complete and its bundle verifies, so a failed
    attempt leaves the directory untouched.
    """
    if token_expired(token, now):
        raise TokenError("enrollment token has expired")
    keys = generate_keys()
    result = await client.enroll(
        token_id=token.token_id,
        secret=token.secret,
        csr_pem=keys.csr_pem,
        seal_pubkey_b64=keys.seal_pubkey_b64,
        facts={"agent_version": __version__},
    )
    node_id = int(result["node_id"])
    trust = trust_from_enroll(list(result["signing_keys"]))
    payload = decode_enroll_bundle(result)
    store = Store(root)
    state = State()
    if payload is not None:
        try:
            validate(
                payload.body,
                payload.signature,
                trusted=trust.keys_for(),
                high_water_version=0,
                agent_version=__version__,
                expected_node_id=node_id,
                seal_private_key=keys.seal_key,
            )
        except BundleError as exc:
            raise StoreError(f"first bundle rejected ({exc.code}): {exc}") from exc
    atomic_write(root / "tls" / "key.pem", keys.tls_key_pem, 0o600)
    atomic_write(root / "tls" / "cert.pem", str(result["cert_pem"]).encode(), 0o644)
    atomic_write(root / "tls" / "ca.pem", str(result["ca_pem"]).encode(), 0o644)
    write_seal_key(root, keys.seal_key)
    store.save_trust(trust)
    store.save_state(state)
    save_config(
        root,
        AgentConfig(
            node_id=node_id,
            hub=HubConfig(
                host=token.host,
                port=token.port,
                pin=token.pin,
                control_url=token.control_url,
                camouflage=token.camouflage,
            ),
            fabric=FabricConfig(),
        ),
    )
    return state
