"""mTLS plumbing for the control listener.

uvicorn applies one `ssl_cert_reqs` to a listener and never exposes the peer
certificate, but `POST /agent/v1/enroll` must work without a client
certificate. The listener therefore asks for a certificate optionally
(`CERT_OPTIONAL`: one that is presented must chain to the kornode CA or the
handshake fails) and `H11Protocol` is subclassed to hand the verified DER to
the ASGI app through the per-connection state; `MutualTLSMiddleware` then
requires it everywhere except enroll.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

PEER_CERT_KEY = "peer_cert_der"


class PeerCertProtocol(H11Protocol):
    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        der: bytes | None = None
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is not None:
            der = ssl_object.getpeercert(binary_form=True)
        # A fresh dict: app_state is shared by every connection of the server.
        state: dict[str, Any] = dict(self.app_state)
        state[PEER_CERT_KEY] = der
        self.app_state = state


def server_config(
    app: Any,
    *,
    host: str,
    port: int,
    certfile: str,
    keyfile: str,
    ca_certs: str,
    **kwargs: Any,
) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=host,
        port=port,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        ssl_ca_certs=ca_certs,
        ssl_cert_reqs=ssl.CERT_OPTIONAL,
        http=PeerCertProtocol,
        lifespan="off",
        access_log=False,
        **kwargs,
    )
