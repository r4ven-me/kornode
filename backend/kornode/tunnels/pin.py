"""Certificate pins in the format openconnect's --servercert accepts.

openconnect removed --no-cert-check; a server whose certificate isn't signed
by a trusted CA (kornode's own auto CA, for one) can only be accepted by
pinning it: ``--servercert pin-sha256:<base64 SHA-256 of the public key>``.
The pin covers the SubjectPublicKeyInfo, so it survives a certificate renewal
that keeps the same key.
"""

from __future__ import annotations

import base64
import hashlib
import re
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.DOTALL
)
_SEQUENCE = 0x30
_CONTEXT_0 = 0xA0


@dataclass(frozen=True)
class CertificatePin:
    pin: str
    sha256: str

    def as_dict(self) -> dict[str, str]:
        return {"pin": self.pin, "sha256": self.sha256}


def pem_to_der(pem: bytes | str) -> bytes:
    """DER of the first CERTIFICATE block (the leaf, for a chain file)."""
    data = pem.encode("ascii") if isinstance(pem, str) else pem
    match = _PEM_CERT_RE.search(data)
    if match is None:
        raise ValueError("no PEM certificate found")
    return base64.b64decode(b"".join(match.group(1).split()))


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the DER element at offset."""
    if offset + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    length = data[offset + 1]
    pos = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("truncated DER")
    return tag, pos, end


def subject_public_key_info(cert_der: bytes) -> bytes:
    """Raw DER of tbsCertificate.subjectPublicKeyInfo (RFC 5280 §4.1)."""
    tag, cert_start, _ = _read_tlv(cert_der, 0)
    if tag != _SEQUENCE:
        raise ValueError("not an X.509 certificate")
    tag, tbs_start, tbs_end = _read_tlv(cert_der, cert_start)
    if tag != _SEQUENCE:
        raise ValueError("not an X.509 certificate")
    offset = tbs_start
    if cert_der[offset] == _CONTEXT_0:  # optional explicit version
        offset = _read_tlv(cert_der, offset)[2]
    # serialNumber, signature, issuer, validity, subject
    for _ in range(5):
        offset = _read_tlv(cert_der, offset)[2]
    tag, _, spki_end = _read_tlv(cert_der, offset)
    if tag != _SEQUENCE or spki_end > tbs_end:
        raise ValueError("malformed subjectPublicKeyInfo")
    return cert_der[offset:spki_end]


def certificate_pin(cert_der: bytes) -> CertificatePin:
    spki = subject_public_key_info(cert_der)
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
    return CertificatePin(
        pin=f"pin-sha256:{pin}",
        sha256=f"sha256:{hashlib.sha256(cert_der).hexdigest()}",
    )


def certificate_file_pin(path: Path) -> CertificatePin:
    return certificate_pin(pem_to_der(path.read_bytes()))


def fetch_server_certificate(host: str, port: int, *, timeout: float = 10.0) -> bytes:
    """DER of the certificate a TLS server presents. RUNTIME: network access.

    Deliberately does NOT verify the certificate -- the point is to show
    (or, for trusted_cert profiles, accept) whatever the server presents so
    it can be pinned.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError(f"{host}:{port} presented no certificate")
    return der


def fetch_server_pin(host: str, port: int, *, timeout: float = 10.0) -> CertificatePin:
    return certificate_pin(fetch_server_certificate(host, port, timeout=timeout))
