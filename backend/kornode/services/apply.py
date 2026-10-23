"""Single apply path for DNS and routing changes.

Every save endpoint that touches routing or DNS settings goes through here,
so a change takes effect immediately instead of waiting for a manual Apply
or the next restart.

RUNTIME: this module starts/stops dnsmasq, reloads ocserv, kicks sessions
and rewrites nftables state. Dry-run is not threaded through the save path.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import BackgroundTasks

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.internal_dns import InternalDnsService
from kornode.services.render_transaction import rendered_configuration
from kornode.services.server import ServerService
from kornode.services.sessions import SessionService

ClientDnsSignature = tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], bool]


def client_dns_signature(config: AppConfig) -> ClientDnsSignature:
    """What a connected client sees from DNS; a change means reconnect."""
    return (
        tuple(config.client_dns_servers()),
        tuple(config.server.search_domains),
        tuple(config.internal_dns.forward_domains),
        config.dns_tunnel_active(),
    )


def apply_dns_configuration(
    config: AppConfig,
    background_tasks: BackgroundTasks,
    *,
    reconnect_clients: bool,
    config_path: Path | None = None,
    env_file: Path | None = None,
) -> list[CommandResult]:
    """Apply current disk state when a source is supplied by an unlocked caller.

    Without a source, the caller owns the in-memory candidate and serialization;
    this preserves intentional initialization/transaction overrides.
    """
    if config_path is not None:
        with rendered_configuration(config_path, env_file=env_file) as (current, _):
            return _apply_dns_runtime(
                current, background_tasks, reconnect_clients=reconnect_clients
            )
    from kornode.services.config import ConfigService

    ConfigService().write_rendered_files(config)
    return _apply_dns_runtime(config, background_tasks, reconnect_clients=reconnect_clients)


def _apply_dns_runtime(
    config: AppConfig, background_tasks: BackgroundTasks, *, reconnect_clients: bool
) -> list[CommandResult]:
    results: list[CommandResult] = []
    server = ServerService(config)
    if config.dns_tunnel_active():
        InternalDnsService(config).ensure_listen_address()
        results.append(server.process_action("restart", "dnsmasq"))
    else:
        results.append(server.process_action("stop", "dnsmasq"))
    if reconnect_clients:
        reload_result = server.reload()
        results.append(reload_result)
        if reload_result.ok:
            sessions = SessionService(config)
            usernames = tuple(dict.fromkeys(item.username for item in sessions.list_sessions()))
            if usernames:
                background_tasks.add_task(_disconnect_dns_clients, config, usernames)
    return results


def _disconnect_dns_clients(config: AppConfig, usernames: tuple[str, ...]) -> None:
    sessions = SessionService(config)
    for username in usernames:
        sessions.kick(username)
