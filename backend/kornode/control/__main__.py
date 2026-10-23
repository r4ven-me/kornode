"""`python -m kornode.control`: the supervisor program `control-api`."""

from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path

import uvicorn

from kornode.config.loader import DEFAULT_CONFIG_PATH, load_config
from kornode.control.app import create_app
from kornode.control.service import ControlService
from kornode.control.tls import server_config
from kornode.net.addressing import derive_addresses
from kornode.services.certificates import CertificateService


def main() -> int:
    config = load_config(Path(os.getenv("KORNODE_CONFIG") or DEFAULT_CONFIG_PATH))
    if not config.control.enabled:
        print("control.enabled is false; nothing to serve", file=sys.stderr)
        return 1
    address = str(
        derive_addresses(
            config.node.id,
            interlink_cidr=config.interlink.cidr,
            client_pool=config.interlink.client_pool,
            source_pool=config.interlink.source_pool,
            domain=config.interlink.domain,
        ).interlink_address
    )
    ipaddress.ip_address(address)
    certificates = CertificateService(config)
    certificates.ensure_crl()
    certificates.ensure_control_certificate(address)
    service = ControlService(config)
    service.compile_all("control API start")
    app = create_app(config, service)
    server = uvicorn.Server(
        server_config(
            app,
            host=address,
            port=config.control.port,
            certfile=str(config.cert_path("control.crt")),
            keyfile=str(config.cert_path("control.key")),
            ca_certs=str(config.cert_path("ca.crt")),
        )
    )
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
