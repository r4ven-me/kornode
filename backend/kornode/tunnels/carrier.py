from __future__ import annotations

import ipaddress
import socket


def resolve_carrier_addresses(server: str | None) -> list[str]:
    """The literal IPv4 address(es) a tunnel's own TCP session dials.

    A literal IP is returned as-is; a hostname is resolved on every call
    since it may change between connects. Resolution failure yields an empty
    list: callers must tolerate "nothing to exclude yet" rather than block a
    connection attempt on a DNS hiccup.
    """
    if not server:
        return []
    try:
        ipaddress.ip_address(server)
        return [server]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(server, None, family=socket.AF_INET)
    except OSError:
        return []
    addresses: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in addresses:
            addresses.append(addr)
    return addresses
