from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

import typer
import yaml

from kornode.config.defaults import DEFAULT_CONFIG
from kornode.config.env import combined_environment, env_overrides_from_mapping
from kornode.config.loader import (
    DEFAULT_CONFIG_PATH,
    deep_merge,
    load_config,
    load_yaml_file,
    resolve_secret_refs,
)
from kornode.config.models import AppConfig, GroupPolicyConfig, OidcProviderConfig
from kornode.services.cert_pin import fetch_server_pin
from kornode.services.certificates import CertificateService
from kornode.services.command import CommandResult
from kornode.services.config import ConfigService
from kornode.services.diagnostics import DiagnosticsService
from kornode.services.files import FileManager
from kornode.services.groups import GroupConfigService
from kornode.services.host_dns import HostDnsService
from kornode.services.internal_dns import InternalDnsService
from kornode.services.logs import LogRotationService, LogService
from kornode.services.nftables import NftablesService
from kornode.services.otp import OtpService
from kornode.services.password_hash import hash_password
from kornode.services.routing import RoutingService
from kornode.services.secrets import collect_config_secrets, mask_text
from kornode.services.server import ServerService
from kornode.services.server_certificates import ServerCertificateService
from kornode.services.sessions import SessionService
from kornode.services.upstream import UpstreamService
from kornode.services.users import UserConfig, UserService

app = typer.Typer(no_args_is_help=True, help="Korvus Node management")
config_app = typer.Typer(help="Validate and render configuration")
server_app = typer.Typer(help="Manage Korvus Node runtime processes")
server_process_app = typer.Typer(help="Manage supervisor-managed Korvus Node processes")
server_cert_app = typer.Typer(help="Manage Korvus Node TLS certificates")
server_ca_app = typer.Typer(help="Manage Korvus Node certificate authority")
user_app = typer.Typer(help="Manage VPN users")
user_cert_app = typer.Typer(help="Manage user certificates")
user_p12_app = typer.Typer(help="Export user PKCS#12 bundles")
user_otp_app = typer.Typer(help="Manage user OTP")
sessions_app = typer.Typer(help="Inspect and disconnect sessions")
upstream_app = typer.Typer(help="Manage upstream OpenConnect profiles")
routes_app = typer.Typer(help="Manage split routes")
domains_app = typer.Typer(help="Manage split domains")
internal_dns_app = typer.Typer(help="Manage the Internal DNS server and its blocklist")
identity_app = typer.Typer(help="Manage identity providers and group policies")
identity_oidc_app = typer.Typer(help="Manage OIDC connector settings")
identity_group_app = typer.Typer(help="Manage VPN group policies")
identity_group_config_app = typer.Typer(help="Manage ocserv config-per-group files")
nft_app = typer.Typer(help="Manage project-owned nftables state")
host_dns_app = typer.Typer(help="Point the host's resolver at the built-in dnsmasq")
web_app = typer.Typer(help="Manage Web GUI security")

STATE: dict[str, Path | None] = {"config_path": None, "env_file": None}


@app.callback()
def main(
    config: Path = typer.Option(
        DEFAULT_CONFIG_PATH,
        "--config",
        "-c",
        envvar="KORNODE_CONFIG",
        help="YAML configuration path.",
    ),
    env_file: Path | None = typer.Option(
        None,
        "--env-file",
        envvar="KORNODE_ENV_FILE",
        help=".env file to load before process environment overrides.",
    ),
) -> None:
    STATE["config_path"] = config
    STATE["env_file"] = env_file


def get_config(cli_overrides: dict[str, Any] | None = None) -> AppConfig:
    return load_config(
        STATE.get("config_path") or DEFAULT_CONFIG_PATH,
        env_file=STATE.get("env_file"),
        cli_overrides=cli_overrides,
    )


def echo_result(result: CommandResult) -> None:
    if result.dry_run:
        typer.echo(f"dry-run: {' '.join(result.argv)}")
    if result.stdout:
        typer.echo(result.stdout.rstrip())
    if result.stderr:
        typer.echo(result.stderr.rstrip(), err=True)
    if result.returncode != 0:
        raise typer.Exit(result.returncode)


@config_app.command("validate")
def config_validate() -> None:
    config = get_config()
    typer.echo(json.dumps(config.model_dump_safe(), indent=2, sort_keys=True))


@config_app.command("render")
def config_render(
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Render to stdout without writing files.",
    ),
) -> None:
    config = get_config()
    service = ConfigService()
    secrets = collect_config_secrets(config)
    if dry_run:
        for rendered in service.render_files(config):
            typer.echo(f"--- {rendered.path}")
            typer.echo(mask_text(rendered.content, secrets).rstrip())
        return
    for path in service.write_rendered_files(config):
        typer.echo(str(path))


@config_app.command("diff")
def config_diff() -> None:
    diff = ConfigService().diff_rendered_files(get_config())
    typer.echo(diff or "No changes.")


def save_config_patch(patch: dict[str, Any], *, write_rendered: bool = True) -> AppConfig:
    path = STATE.get("config_path") or DEFAULT_CONFIG_PATH
    old_data = load_yaml_file(path)
    merged = deep_merge(old_data, patch)
    _validate_config_data(merged, path)
    FileManager().atomic_write_text(path, yaml.safe_dump(merged, sort_keys=False), mode=0o600)
    config = get_config()
    if write_rendered:
        ConfigService().write_rendered_files(config)
    return config


def _validate_config_data(data: dict[str, Any], path: Path) -> AppConfig:
    environment = combined_environment(path, STATE.get("env_file"), None)
    env_overrides = env_overrides_from_mapping(environment)
    merged = deep_merge(DEFAULT_CONFIG, env_overrides)
    merged = deep_merge(merged, data)
    merged = resolve_secret_refs(merged, environment)
    return AppConfig.model_validate(merged)


@server_app.command("start")
def server_start(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show supervisor command only."),
) -> None:
    echo_result(ServerService(get_config()).start(dry_run=dry_run))


@server_app.command("stop")
def server_stop(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show supervisor command only."),
) -> None:
    echo_result(ServerService(get_config()).stop(dry_run=dry_run))


@server_app.command("reload")
def server_reload(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show supervisor signal command only."),
) -> None:
    echo_result(ServerService(get_config()).reload(dry_run=dry_run))


@server_app.command("restart")
def server_restart(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show supervisor restart command only."),
) -> None:
    echo_result(ServerService(get_config()).restart(dry_run=dry_run))


@server_app.command("status")
def server_status() -> None:
    echo_result(ServerService(get_config()).status())


@server_process_app.command("list")
def server_process_list() -> None:
    for process in ServerService(get_config()).processes():
        typer.echo(f"{process.name}\t{process.state}\t{process.description}")


@server_process_app.command("start")
def server_process_start(
    process: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(ServerService(get_config()).process_action("start", process, dry_run=dry_run))


@server_process_app.command("stop")
def server_process_stop(
    process: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(ServerService(get_config()).process_action("stop", process, dry_run=dry_run))


@server_process_app.command("restart")
def server_process_restart(
    process: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(ServerService(get_config()).process_action("restart", process, dry_run=dry_run))


@server_process_app.command("status")
def server_process_status(
    process: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(ServerService(get_config()).process_action("status", process, dry_run=dry_run))


@server_cert_app.command("status")
def server_cert_status() -> None:
    typer.echo(
        json.dumps(ServerCertificateService(get_config()).status(), indent=2, sort_keys=True)
    )


@server_cert_app.command("pin")
def server_cert_pin() -> None:
    """Print the pin other openconnect clients use to trust this server."""
    typer.echo(json.dumps(ServerCertificateService(get_config()).server_pin(), indent=2))


@server_cert_app.command("external")
def server_cert_external(
    server_cert: Path = typer.Option(
        ...,
        "--server-cert",
        help="PEM fullchain/server certificate.",
    ),
    server_key: Path = typer.Option(..., "--server-key", help="PEM private key."),
    ca_cert: Path = typer.Option(..., "--ca-cert", help="PEM CA/chain certificate."),
) -> None:
    paths = ServerCertificateService(get_config()).save_external_material(
        server_cert=server_cert.read_bytes(),
        server_key=server_key.read_bytes(),
        ca_cert=ca_cert.read_bytes(),
    )
    typer.echo(json.dumps({key: str(value) for key, value in paths.__dict__.items()}, indent=2))


@server_cert_app.command("letsencrypt-issue")
def server_cert_letsencrypt_issue(
    email: str = typer.Option(..., "--email", help="Let's Encrypt account email."),
    domain: list[str] = typer.Option(..., "--domain", "-d", help="Certificate domain."),
    staging: bool = typer.Option(False, "--staging", help="Use Let's Encrypt staging CA."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(
        ServerCertificateService(get_config()).issue_letsencrypt(
            email=email,
            domains=domain,
            staging=staging,
            dry_run=dry_run,
        )
    )


@server_cert_app.command("letsencrypt-renew")
def server_cert_letsencrypt_renew(
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(ServerCertificateService(get_config()).renew_letsencrypt(dry_run=dry_run))


@server_ca_app.command("regenerate")
def server_ca_regenerate(
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    for result in CertificateService(get_config()).regenerate_ca(dry_run=dry_run):
        echo_result(result)


@server_ca_app.command("upload")
def server_ca_upload(
    ca_cert: Path = typer.Option(..., "--ca-cert", help="PEM CA certificate."),
    ca_key: Path = typer.Option(..., "--ca-key", help="PEM CA private key."),
) -> None:
    echo_result(
        CertificateService(get_config()).save_ca_material(
            ca_cert=ca_cert.read_bytes(),
            ca_key=ca_key.read_bytes(),
        )
    )


@server_ca_app.command("revoke-pem")
def server_ca_revoke_pem(
    file: Path = typer.Option(..., "--file", "-f", help="PEM user certificate to revoke."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(
        CertificateService(get_config()).revoke_certificate_pem(
            file.read_bytes(),
            dry_run=dry_run,
        )
    )


@server_ca_app.command("revoke-b64")
def server_ca_revoke_b64(
    certificate_b64: str = typer.Argument(...),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(
        CertificateService(get_config()).revoke_certificate_pem(
            base64.b64decode(certificate_b64, validate=True),
            dry_run=dry_run,
        )
    )


@server_ca_app.command("revoked")
def server_ca_revoked() -> None:
    typer.echo(
        json.dumps(
            CertificateService(get_config()).list_revoked_certificates(),
            indent=2,
            sort_keys=True,
        )
    )


@user_app.command("list")
def user_list() -> None:
    users = UserService(get_config()).list_users()
    for user in users:
        status = "disabled" if user.disabled else "enabled"
        groups = ",".join(user.groups or []) or "-"
        typer.echo(f"{user.username}\t{status}\t{groups}")


@user_app.command("create")
def user_create(
    username: str,
    password: str = typer.Option(
        ...,
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Password; prompted by default and never echoed.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(UserService(get_config()).create_user(username, password, dry_run=dry_run))


@user_app.command("delete")
def user_delete(
    username: str,
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not prompt for confirmation."),
) -> None:
    if not yes and not typer.confirm(f"Delete user {username}?"):
        raise typer.Exit(1)
    changed = UserService(get_config()).delete_user(username)
    typer.echo("deleted" if changed else "not found")


@user_app.command("enable")
def user_enable(
    username: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(UserService(get_config()).enable_user(username, dry_run=dry_run))


@user_app.command("disable")
def user_disable(
    username: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(UserService(get_config()).disable_user(username, dry_run=dry_run))


@user_app.command("passwd")
def user_passwd(
    username: str,
    password: str = typer.Option(
        ...,
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="New password; prompted by default and never echoed.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(UserService(get_config()).change_password(username, password, dry_run=dry_run))


@user_app.command("groups")
def user_groups_set(
    username: str,
    group: list[str] = typer.Option([], "--group", "-g", help="Group name; repeatable."),
    clear: bool = typer.Option(False, "--clear", help="Remove all group memberships."),
) -> None:
    groups = [] if clear else group
    echo_result(UserService(get_config()).set_user_groups(username, groups))


@user_cert_app.command("create")
def user_cert_create(
    username: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    results = CertificateService(get_config()).create_user_certificate(username, dry_run=dry_run)
    for result in results:
        echo_result(result)


@user_cert_app.command("revoke")
def user_cert_revoke(
    username: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(CertificateService(get_config()).revoke_user_certificate(username, dry_run=dry_run))


@user_p12_app.command("create")
def user_p12_create(
    username: str,
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        prompt=False,
        hide_input=True,
        help="Optional P12 passphrase; never echoed.",
    ),
    apple_compatible: bool = typer.Option(False, "--apple-compatible"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(
        CertificateService(get_config()).create_p12(
            username,
            passphrase,
            apple_compatible=apple_compatible,
            dry_run=dry_run,
        )
    )


@user_app.command("revoke")
def user_revoke(
    username: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(CertificateService(get_config()).revoke_user_certificate(username, dry_run=dry_run))


@user_otp_app.command("enable")
def user_otp_enable(username: str) -> None:
    OtpService(get_config()).enable(username)
    typer.echo(f"OTP enabled for {username}. Use `korctl user otp show-qr {username}` to enroll.")


@user_otp_app.command("disable")
def user_otp_disable(username: str) -> None:
    changed = OtpService(get_config()).disable(username)
    typer.echo("disabled" if changed else "not enabled")


@user_otp_app.command("show-qr")
def user_otp_show_qr(username: str) -> None:
    echo_result(OtpService(get_config()).qr_ansi(username))


@sessions_app.command("list")
def sessions_list() -> None:
    sessions = SessionService(get_config()).list_sessions()
    for session in sessions:
        typer.echo(
            "\t".join(
                [
                    session.username,
                    session.vpn_ip or "-",
                    session.real_ip or "-",
                    session.device or "-",
                    session.rx or "-",
                    session.tx or "-",
                ]
            )
        )


@sessions_app.command("kick")
def sessions_kick(
    username: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(SessionService(get_config()).kick(username, dry_run=dry_run))


@upstream_app.command("status")
def upstream_status() -> None:
    status = UpstreamService(get_config()).status()
    typer.echo(json.dumps(status.__dict__, indent=2, sort_keys=True))


@upstream_app.command("fetch-pin")
def upstream_fetch_pin(
    server: str,
    port: int = typer.Option(443, "--port", min=1, max=65535),
) -> None:
    """Show the pin of the certificate an upstream server presents (not verified)."""
    typer.echo(json.dumps(fetch_server_pin(server, port).as_dict(), indent=2))


@upstream_app.command("list")
def upstream_list() -> None:
    for profile in UpstreamService(get_config()).list_profiles():
        typer.echo(profile.name)


@upstream_app.command("switch")
def upstream_switch(profile: str) -> None:
    UpstreamService(get_config()).switch_profile(profile)
    typer.echo(f"active profile set to {profile}")


@upstream_app.command("enable")
def upstream_enable_profile(profile: str) -> None:
    """Let the watchdog keep `profile` dialed (UpstreamProfileConfig.enabled)."""
    _set_profile_enabled(profile, True)


@upstream_app.command("disable")
def upstream_disable_profile(profile: str) -> None:
    """Stop the watchdog from dialing `profile`; disconnects it if it's up."""
    _set_profile_enabled(profile, False)


def _set_profile_enabled(name: str, enabled: bool) -> None:
    config = get_config()
    if not any(item.name == name for item in config.upstream.profiles):
        typer.echo(f"unknown upstream profile: {name}", err=True)
        raise typer.Exit(1)
    profiles = [
        {**item.model_dump(mode="json"), "enabled": enabled}
        if item.name == name
        else item.model_dump(mode="json")
        for item in config.upstream.profiles
    ]
    save_config_patch({"upstream": {"profiles": profiles}})
    typer.echo(f"profile '{name}' {'enabled' if enabled else 'disabled'}")


@upstream_app.command("connect")
def upstream_connect(
    profile: str = typer.Argument(None, help="Profile to connect (default: active)."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(UpstreamService(get_config()).connect(profile or None, dry_run=dry_run))


@upstream_app.command("disconnect")
def upstream_disconnect(
    profile: str = typer.Argument(None, help="Profile to disconnect (default: active)."),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    echo_result(UpstreamService(get_config()).disconnect(profile or None, dry_run=dry_run))


@upstream_app.command("hook")
def upstream_hook(
    reason: str = typer.Argument(help="vpnc-script event: connect/reconnect/disconnect/..."),
) -> None:
    """Internal: called by vpnc-script-kornode on tunnel events.

    Stores the routes/split-DNS domains the upstream server pushed in the
    handshake (openconnect's CISCO_SPLIT_INC_*/CISCO_SPLIT_DNS environment)
    for the profile owning $TUNDEV. Never fails: it runs inside
    openconnect's own connect sequence.
    """
    try:
        profile = UpstreamService(get_config()).record_vpnc_event(reason)
    except Exception as exc:  # noqa: BLE001 - must never break the tunnel
        typer.echo(f"upstream hook failed: {exc}", err=True)
        return
    if profile is not None:
        typer.echo(f"stored server-pushed routing for profile '{profile.name}'")


@upstream_app.command("server-routes")
def upstream_server_routes(
    profile: str = typer.Argument(None, help="Profile (default: all)."),
) -> None:
    """Show the routes/split-DNS domains each upstream server pushed."""
    service = UpstreamService(get_config())
    payload = {
        item.name: service.server_routing_status(item)
        for item in service.list_profiles()
        if profile is None or item.name == profile
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@upstream_app.command("sync")
def upstream_sync(
    profile: str = typer.Argument(..., help="Profile with sync_url to refresh now."),
) -> None:
    """Pull a profile's routes/split-DNS from its upstream panel and apply them."""
    config = get_config()
    service = UpstreamService(config)
    target = next((item for item in config.upstream.profiles if item.name == profile), None)
    if target is None:
        typer.echo(f"unknown upstream profile: {profile}", err=True)
        raise typer.Exit(1)
    synced = service.sync_server_routes(target)
    if synced.sync_error:
        typer.echo(f"sync failed: {synced.sync_error}", err=True)
        raise typer.Exit(1)
    for result in service.apply_server_routing_if_changed():
        echo_result(result)
    typer.echo(
        f"{len(synced.routes)} routes, {len(synced.domains)} split-DNS domains "
        f"(version {synced.version or '-'})"
    )


@upstream_app.command("watch")
def upstream_watch(
    once: bool = typer.Option(
        False, "--once", help="Run a single check-and-recover tick, then exit."
    ),
) -> None:
    """Supervisor entrypoint: monitor the active upstream connection and
    reconnect (failing over to the next profile if enabled) after
    upstream.check_threshold consecutive unhealthy ticks. Also brings every
    profile's connection state in line with its own `enabled` flag on each
    tick -- unconditional on upstream.failover, since staying connected and
    being eligible for automatic switching are separate concerns (see
    UpstreamService.enforce_profile_enablement).

    Reloads config on every tick, so settings changes take effect without
    restarting the watchdog.
    """
    consecutive_failures = 0
    # Monotonic deadline: health-check failures before this time don't count
    # (see check_settle_seconds). A tunnel that recover() just brought up
    # needs a moment for routing/DPD to settle -- without this, one failed
    # probe seconds after a successful reconnect would immediately start a
    # new consecutive_failures streak and could trigger another recover()
    # before the last one ever had a chance to prove itself, live-locking
    # into a connect/disconnect/reconnect loop every check_interval tick.
    settled_until = 0.0
    # Tracks whether *this watchdog process* has ever seen a healthy
    # connection. Gates upstream.connect_on_boot: while off and this is
    # still False, the watchdog only observes -- it never dials on its own
    # -- until an admin connects manually (from the panel/CLI) at least
    # once. From then on it behaves exactly as if connect_on_boot were on,
    # since "on boot" no longer applies once a connection has existed.
    ever_connected = False
    while True:
        config = get_config()
        service = UpstreamService(config)
        if config.upstream.enabled:
            selected = service.selected_profile()
            if selected is not None:
                if service.is_healthy():
                    consecutive_failures = 0
                    ever_connected = True
                    # The kernel drops the fwmark table's route whenever the
                    # tunnel device bounces; heal it while the tunnel is up.
                    service.ensure_policy_routing()
                elif selected.kind == "external_interface":
                    # No dial/redial possible for an externally-managed
                    # interface -- status()/the GUI already surfaces the
                    # down link; never attempt recover() for it.
                    consecutive_failures = 0
                elif not config.upstream.connect_on_boot and not ever_connected:
                    consecutive_failures = 0
                elif time.monotonic() < settled_until:
                    pass
                else:
                    consecutive_failures += 1
                    if consecutive_failures >= config.upstream.check_threshold:
                        if service.recover():
                            settled_until = time.monotonic() + config.upstream.check_settle_seconds
                            ever_connected = True
                        consecutive_failures = 0
            else:
                consecutive_failures = 0
            # Outside the "is there an active profile" branch above on
            # purpose: disabling the currently active profile makes
            # selected_profile() return None, and that profile (now just
            # another disabled one) still needs to be torn down.
            service.enforce_profile_enablement()
            # Server-pushed routing: pick up lists stored by the vpnc-script
            # hook after openconnect's own internal reconnects, and poll
            # sync_url profiles. Never allowed to kill the watchdog.
            try:
                service.refresh_server_routes()
            except Exception as exc:  # noqa: BLE001
                typer.echo(f"server-pushed routing refresh failed: {exc}", err=True)
        else:
            consecutive_failures = 0
        if once:
            return
        time.sleep(config.upstream.check_interval)


@host_dns_app.command("status")
def host_dns_status() -> None:
    typer.echo(json.dumps(HostDnsService(get_config()).status(), indent=2, sort_keys=True))


@host_dns_app.command("apply")
def host_dns_apply() -> None:
    """Point (or stop pointing) the host resolver at dnsmasq per routing.host_dns."""
    typer.echo(HostDnsService(get_config()).apply().detail)


@host_dns_app.command("restore")
def host_dns_restore() -> None:
    """Put the host's original resolv.conf back."""
    typer.echo(HostDnsService(get_config()).restore().detail)


@host_dns_app.command("guard")
def host_dns_guard(
    interval: int = typer.Option(30, "--interval", min=5),
) -> None:
    """Supervisor entrypoint: keep routing.host_dns asserted, restore on stop.

    Re-reads the config every cycle (so toggling routing.host_dns in the
    panel applies without restarting anything) and re-asserts the host
    resolv.conf when NetworkManager/DHCP rewrote it. On SIGTERM (container
    shutdown) it puts the host's original resolv.conf back: the host must
    not keep pointing at a dnsmasq that is about to stop.
    """
    import signal

    stopping = False

    def _stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    last_detail = ""
    while not stopping:
        try:
            result = HostDnsService(get_config()).apply()
            if result.changed or result.detail != last_detail:
                typer.echo(result.detail)
                last_detail = result.detail
        except Exception as exc:  # noqa: BLE001 - keep guarding
            typer.echo(f"host DNS check failed: {exc}", err=True)
        deadline = time.monotonic() + interval
        while not stopping and time.monotonic() < deadline:
            time.sleep(0.5)
    typer.echo(HostDnsService(get_config()).restore().detail)


@routes_app.command("list")
def routes_list() -> None:
    for route in RoutingService(get_config()).list_routes():
        typer.echo(route)


@routes_app.command("add")
def routes_add(route: str) -> None:
    RoutingService(get_config()).add_route(route)
    typer.echo(f"added {route}")


@routes_app.command("delete")
def routes_delete(route: str) -> None:
    RoutingService(get_config()).delete_route(route)
    typer.echo(f"deleted {route}")


@routes_app.command("reload")
def routes_reload(
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    for result in NftablesService(get_config()).apply(dry_run=dry_run):
        echo_result(result)


@domains_app.command("list")
def domains_list() -> None:
    for domain in RoutingService(get_config()).list_domains():
        typer.echo(domain)


@domains_app.command("add")
def domains_add(domain: str) -> None:
    RoutingService(get_config()).add_domain(domain)
    typer.echo(f"added {domain}")


@domains_app.command("delete")
def domains_delete(domain: str) -> None:
    RoutingService(get_config()).delete_domain(domain)
    typer.echo(f"deleted {domain}")


@domains_app.command("reload")
def domains_reload(
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    config = get_config()
    ConfigService().write_rendered_files(config)
    for result in NftablesService(config).apply(dry_run=dry_run):
        echo_result(result)


@internal_dns_app.command("status")
def internal_dns_status() -> None:
    status = InternalDnsService(get_config()).status()
    typer.echo(json.dumps(status, indent=2, sort_keys=True))


@internal_dns_app.command("blocklist")
def internal_dns_blocklist(
    limit: int = typer.Option(0, "--limit", help="Print at most N domains (0 = all)."),
) -> None:
    merged = InternalDnsService(get_config()).merged_blocklist()
    for domain in merged[:limit] if limit > 0 else merged:
        typer.echo(domain)


@internal_dns_app.command("settings")
def internal_dns_settings(
    enabled: bool = typer.Option(..., "--enabled/--disabled"),
    blocklist_file: list[str] = typer.Option(
        [],
        "--blocklist-file",
        help="Local text file with blocked domains; repeatable. Replaces the whole "
        "list when given (pass --blocklist-file '' once to clear it).",
    ),
    blocklist_url: list[str] = typer.Option(
        [],
        "--blocklist-url",
        help="HTTP(S) URL of a hosts/domain blocklist; repeatable. Replaces the "
        "whole list when given (pass --blocklist-url '' once to clear it).",
    ),
) -> None:
    patch: dict[str, Any] = {"enabled": enabled}
    if blocklist_file:
        patch["blocklist_files"] = [item for item in blocklist_file if item]
    if blocklist_url:
        patch["blocklist_urls"] = [item for item in blocklist_url if item]
    config = save_config_patch({"internal_dns": patch})
    typer.echo(json.dumps(InternalDnsService(config).status(), indent=2, sort_keys=True))


@internal_dns_app.command("ensure-listen")
def internal_dns_ensure_listen(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show the ip command only."),
) -> None:
    """Assign the dnsmasq listen IP to the loopback interface (idempotent)."""
    echo_result(InternalDnsService(get_config()).ensure_listen_address(dry_run=dry_run))


@internal_dns_app.command("run")
def internal_dns_run() -> None:
    """Supervisor entrypoint: ensure the listen IP exists, then exec dnsmasq."""
    config = get_config()
    if not config.dns_tunnel_active():
        typer.echo("internal DNS and split DNS are disabled; nothing to run", err=True)
        raise typer.Exit(1)
    service = InternalDnsService(config)
    result = service.ensure_listen_address()
    if not result.ok:
        # dnsmasq will report the bind failure itself; surface the ip error early.
        typer.echo(f"warning: {' '.join(result.argv)}: {result.stderr.strip()}", err=True)
    argv = service.dnsmasq_argv()
    os.execv(argv[0], argv)


@internal_dns_app.command("refresh")
def internal_dns_refresh(
    url: str = typer.Option(
        ...,
        "--url",
        help="Which configured internal_dns.blocklist_urls entry to refresh.",
    ),
    preview: bool = typer.Option(
        False,
        "--preview",
        help="Download and validate the URL blocklist without applying it.",
    ),
) -> None:
    config = get_config()
    result = InternalDnsService(config).refresh_url_blocklist(url, preview=preview)
    if result.saved and config.internal_dns.blocklist_enabled:
        ConfigService().write_rendered_files(config)
    typer.echo(
        json.dumps(
            {
                "url": result.url,
                "total_lines": result.total_lines,
                "valid": result.valid,
                "skipped": result.skipped,
                "sample": result.sample,
                "saved": result.saved,
            },
            indent=2,
            sort_keys=True,
        )
    )


@identity_app.command("status")
def identity_status() -> None:
    config = get_config()
    payload = {
        "oidc": config.auth.oidc.model_dump(
            mode="json",
        ),
        "providers": [
            provider.model_dump(mode="json", exclude={"client_secret"})
            for provider in config.identity.oidc_providers
        ],
        "groups": [group.model_dump(mode="json") for group in config.identity.group_policies],
        "config_per_group_dir": str(config.identity.config_per_group_dir),
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@identity_oidc_app.command("settings")
def identity_oidc_settings(
    enabled: bool = typer.Option(..., "--enabled/--disabled"),
    connector: str = typer.Option("pam", "--connector", help="pam or radius."),
    pam_service: str = typer.Option("ocserv", "--pam-service"),
    radius_config: Path = typer.Option(
        Path("/etc/radiusclient/radiusclient.conf"),
        "--radius-config",
    ),
) -> None:
    patch = {
        "enabled": enabled,
        "connector": connector,
        "pam": {"service": pam_service},
        "radius": {"config_file": str(radius_config), "groupconfig": True},
    }
    config = save_config_patch({"auth": {"oidc": patch}})
    typer.echo(json.dumps(config.auth.oidc.model_dump(mode="json"), indent=2, sort_keys=True))


@identity_oidc_app.command("provider-set")
def identity_oidc_provider_set(
    name: str,
    issuer_url: str = typer.Option(..., "--issuer-url"),
    client_id: str = typer.Option(..., "--client-id"),
    client_secret: str | None = typer.Option(
        None,
        "--client-secret",
        hide_input=True,
        help="OIDC client secret; prefer ${SECRET:...} in YAML for production.",
    ),
    scope: list[str] = typer.Option(["openid", "profile", "email"], "--scope"),
    username_claim: str = typer.Option("preferred_username", "--username-claim"),
    groups_claim: str = typer.Option("groups", "--groups-claim"),
    allowed_group: list[str] = typer.Option([], "--allowed-group"),
) -> None:
    config = get_config()
    provider = OidcProviderConfig.model_validate(
        {
            "name": name,
            "issuer_url": issuer_url,
            "client_id": client_id,
            "client_secret": client_secret,
            "scopes": scope,
            "username_claim": username_claim,
            "groups_claim": groups_claim,
            "allowed_groups": allowed_group,
        }
    )
    providers = [item for item in config.identity.oidc_providers if item.name != provider.name]
    providers.append(provider)
    updated = save_config_patch(
        {
            "identity": {
                "oidc_providers": [item.model_dump(mode="json") for item in providers],
            }
        }
    )
    safe = [
        item.model_dump(mode="json", exclude={"client_secret"})
        for item in updated.identity.oidc_providers
    ]
    typer.echo(json.dumps(safe, indent=2, sort_keys=True))


@identity_group_app.command("set")
def identity_group_set(
    file: Path = typer.Option(..., "--file", "-f", help="YAML or JSON group policy file."),
) -> None:
    config = get_config()
    loaded = yaml.safe_load(file.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("group policy file must contain a mapping")
    group = GroupPolicyConfig.model_validate(loaded)
    groups = [item for item in config.identity.group_policies if item.name != group.name]
    groups.append(group)
    updated = save_config_patch(
        {
            "identity": {
                "group_policies": [item.model_dump(mode="json") for item in groups],
            }
        }
    )
    typer.echo(
        json.dumps(
            [item.model_dump(mode="json") for item in updated.identity.group_policies],
            indent=2,
            sort_keys=True,
        )
    )


@identity_group_app.command("delete")
def identity_group_delete(name: str) -> None:
    config = get_config()
    groups = [item for item in config.identity.group_policies if item.name != name]
    updated = save_config_patch(
        {
            "identity": {
                "group_policies": [item.model_dump(mode="json") for item in groups],
            }
        }
    )
    typer.echo(
        json.dumps(
            [item.model_dump(mode="json") for item in updated.identity.group_policies],
            indent=2,
            sort_keys=True,
        )
    )


@identity_group_config_app.command("list")
def identity_group_config_list() -> None:
    for group in GroupConfigService(get_config()).list_groups():
        typer.echo(f"{group.name}\t{'configured' if group.config_exists else 'empty'}")


@identity_group_config_app.command("show")
def identity_group_config_show(name: str) -> None:
    config = GroupConfigService(get_config()).read_group_config(name)
    typer.echo(json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True))


@identity_group_config_app.command("save")
def identity_group_config_save(
    name: str,
    file: Path = typer.Option(..., "--file", "-f", help="YAML or JSON UserConfig-style file."),
) -> None:
    loaded = yaml.safe_load(file.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("group config file must contain a mapping")
    echo_result(
        GroupConfigService(get_config()).save_group_config(
            name,
            UserConfig.model_validate(loaded),
        )
    )


@identity_group_config_app.command("delete")
def identity_group_config_delete(name: str) -> None:
    deleted = GroupConfigService(get_config()).delete_group_config(name)
    typer.echo("deleted" if deleted else "not found")


@nft_app.command("apply")
def nft_apply(
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    config = get_config()
    secrets = collect_config_secrets(config)
    for result in NftablesService(config).apply(dry_run=dry_run):
        if result.stdout:
            typer.echo(mask_text(result.stdout.rstrip(), secrets))
        else:
            echo_result(result)


@nft_app.command("show")
def nft_show() -> None:
    echo_result(NftablesService(get_config()).show())


@nft_app.command("cleanup")
def nft_cleanup(
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    for result in NftablesService(get_config()).cleanup(dry_run=dry_run):
        echo_result(result)


@app.command("diagnose")
def diagnose(
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    for name, result in DiagnosticsService(get_config()).run(dry_run=dry_run).items():
        typer.echo(f"## {name}")
        echo_result(result)


@app.command("logs")
def logs(
    name: str = typer.Argument("api.log"),
    lines: int = typer.Option(100, "--lines", "-n"),
) -> None:
    typer.echo(LogService(get_config()).tail(name=name, lines=lines))


@app.command("logs-rotate")
def logs_rotate(
    force: bool = typer.Option(
        False,
        "--force",
        help="Rotate every non-empty log now, ignoring size/age thresholds.",
    ),
) -> None:
    """Rotate logs per system.log_rotation; no-op while rotation is disabled."""
    rotated = LogRotationService(get_config()).rotate(force=force)
    if rotated:
        typer.echo("rotated: " + ", ".join(rotated))


@web_app.command("hash-password")
def web_hash_password() -> None:
    password = typer.prompt("Admin password", hide_input=True, confirmation_prompt=True)
    typer.echo(hash_password(password))


user_app.add_typer(user_cert_app, name="cert")
user_app.add_typer(user_p12_app, name="p12")
user_app.add_typer(user_otp_app, name="otp")
server_app.add_typer(server_process_app, name="process")
identity_app.add_typer(identity_oidc_app, name="oidc")
identity_app.add_typer(identity_group_app, name="group")
identity_group_app.add_typer(identity_group_config_app, name="config")
server_cert_app.add_typer(server_ca_app, name="ca")

app.add_typer(config_app, name="config")
app.add_typer(server_app, name="server")
app.add_typer(server_cert_app, name="certificates")
app.add_typer(user_app, name="user")
app.add_typer(sessions_app, name="sessions")
app.add_typer(identity_app, name="identity")
app.add_typer(upstream_app, name="upstream")
app.add_typer(routes_app, name="routes")
app.add_typer(domains_app, name="domains")
app.add_typer(internal_dns_app, name="internal-dns")
app.add_typer(nft_app, name="nft")
app.add_typer(host_dns_app, name="host-dns")
app.add_typer(web_app, name="web")


if __name__ == "__main__":
    app()
