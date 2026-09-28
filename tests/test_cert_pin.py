from __future__ import annotations

import socket
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from kornode.services.cert_pin import (
    certificate_file_pin,
    fetch_server_pin,
    pem_to_der,
    subject_public_key_info,
)

FIXTURES = Path(__file__).parent / "fixtures"
CERT = FIXTURES / "test-server.pem"
KEY = FIXTURES / "test-server.key"
# Reference values from `certtool -i` and `openssl x509 -fingerprint -sha256`.
EXPECTED_PIN = "pin-sha256:bkNrvtXA+3ZD7n3iUJDkGuRZhhmQmhE6xv92QL3QRDc="
EXPECTED_SHA256 = "sha256:a8f64b12961e87d9d2c08a51dae3e3587907eb4b355d01e22016679f55b0adfa"


def test_certificate_file_pin_matches_certtool() -> None:
    pin = certificate_file_pin(CERT)

    assert pin.pin == EXPECTED_PIN
    assert pin.sha256 == EXPECTED_SHA256


def test_pem_to_der_uses_the_first_certificate_of_a_chain() -> None:
    leaf = CERT.read_text(encoding="ascii")
    intermediate = "-----BEGIN CERTIFICATE-----\nAAECAw==\n-----END CERTIFICATE-----\n"

    assert pem_to_der(leaf + intermediate) == pem_to_der(leaf)
    assert pem_to_der(intermediate + leaf) == b"\x00\x01\x02\x03"


@pytest.mark.parametrize("data", [b"", b"not a certificate", b"\x30\x05\x02"])
def test_malformed_input_raises_value_error(data: bytes) -> None:
    with pytest.raises(ValueError):
        subject_public_key_info(data)
    with pytest.raises(ValueError):
        pem_to_der(data)


@pytest.fixture
def tls_server() -> Iterator[int]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve() -> None:
        conn, _ = listener.accept()
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (OSError, ssl.SSLError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        listener.close()
        thread.join(timeout=5)


def test_fetch_server_pin_reads_an_untrusted_certificate(tls_server: int) -> None:
    # Self-signed, so a verifying client would refuse it: fetching must not verify.
    assert fetch_server_pin("127.0.0.1", tls_server, timeout=5).pin == EXPECTED_PIN


def test_fetch_server_pin_reports_unreachable_server() -> None:
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()

    with pytest.raises(OSError):
        fetch_server_pin("127.0.0.1", port, timeout=2)
