from __future__ import annotations

import hashlib
import ipaddress
import json

from fastapi import APIRouter, HTTPException, Request

from kornode.config.models import AppConfig
from kornode.services.groups import GroupConfigService
from kornode.services.sessions import SessionService
from kornode.services.users import UserService

# No admin dependency on purpose: this read-only endpoint serves connected VPN
# clients (korclient sync). Callers are identified by their VPN session: the
# request must originate from an address inside server.ipv4_network that
# occtl reports as an active session, so it is only reachable through the
# established tunnel. Because of that missing admin auth, the endpoint also
# needs its own explicit opt-in (web.client_sync_enabled, default off) on top
# of web.enabled -- see the field's docstring in config/models.py.
router = APIRouter()


@router.get("/routing")
def client_routing(request: Request) -> dict[str, object]:
    config: AppConfig = request.app.state.config
    if not config.web.client_sync_enabled:
        raise HTTPException(status_code=403, detail="client routing sync is disabled")
    username = _authenticate_vpn_client(request, config)
    routes, split_dns = _effective_routing(config, username)
    payload = {"routes": routes, "split_dns": split_dns}
    version = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return {"username": username, "version": version, **payload}


def _authenticate_vpn_client(request: Request, config: AppConfig) -> str:
    client_ip = request.client.host if request.client else None
    if not client_ip:
        raise HTTPException(status_code=403, detail="client address unavailable")
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="client address unavailable") from exc
    vpn_network = ipaddress.ip_network(config.server.ipv4_network, strict=False)
    if address not in vpn_network:
        raise HTTPException(
            status_code=403,
            detail="client routing sync is only available through the VPN tunnel",
        )
    for session in SessionService(config).list_sessions():
        if session.vpn_ip == client_ip and session.username:
            return session.username
    raise HTTPException(status_code=403, detail="no active VPN session for this address")


def _effective_routing(config: AppConfig, username: str) -> tuple[list[str], list[str]]:
    """Collect the routes/split-DNS the server would push to this user.

    Mirrors ocserv's merge order: global server config, then the user's
    groups (config-per-group files), then the per-user config.
    """
    routes: list[str] = []
    split_dns: list[str] = []

    def extend(route_items: list[str], dns_items: list[str]) -> None:
        for item in route_items:
            if item not in routes:
                routes.append(item)
        for item in dns_items:
            if item not in split_dns:
                split_dns.append(item)

    extend(config.server.routes, config.server.search_domains)

    users = UserService(config)
    groups = GroupConfigService(config)
    for group in users.read_user_groups(username):
        try:
            group_config = groups.read_group_config(group)
        except ValueError:
            continue
        extend(group_config.routes, group_config.split_dns)

    user_config = users.read_user_config(username)
    extend(user_config.routes, user_config.split_dns)
    return routes, split_dns
