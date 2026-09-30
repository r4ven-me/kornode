from __future__ import annotations

import base64
import contextlib
import dataclasses
import fcntl
import ipaddress
import json
import os
import re
import signal
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from kornode.config.models import AppConfig, UpstreamProfileConfig
from kornode.services.cert_pin import fetch_server_pin
from kornode.services.command import CommandError, CommandResult, CommandRunner
from kornode.services.files import FileManager
from kornode.services.nftables import NftablesService
from kornode.services.policy_routing import PolicyRoutingService
from kornode.services.upstream_pushed import (
    PushedRouting,
    PushedRoutingStore,
    parse_sync_payload,
    parse_vpnc_environment,
)

RESOLV_CONF = Path("/etc/resolv.conf")
VPNC_MARKER = "#@VPNC_GENERATED@"
DISCONNECT_GRACE_SECONDS = 5
# openconnect's --background parent exits 0 the moment it forks into the
# background, before the daemon finishes binding the tun device -- a
# failure past that point (e.g. the tun interface name already being in
# use) kills the daemon within well under a second with no way for the
# parent to report it. See _verify_backgrounded.
BACKGROUND_GRACE_SECONDS = 2
SYNC_TIMEOUT_SECONDS = 20
SYNC_MAX_BYTES = 1024 * 1024
SYNC_USER_AGENT = "kornode-client-sync/1.0"
VPNC_CONNECT_REASONS = {"connect", "reconnect"}


@dataclass(frozen=True)
class UpstreamStatus:
    enabled: bool
    active_profile: str | None
    interface: str
    connected: bool
    local_ip: str | None = None
    remote: str | None = None
    connections: list[dict[str, object]] = field(default_factory=list)


class UpstreamService:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
        nftables: NftablesService | None = None,
        policy_routing: PolicyRoutingService | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.nftables = nftables or NftablesService(config, runner=self.runner)
        self.policy_routing = policy_routing or PolicyRoutingService(config, runner=self.runner)
        self.pushed = PushedRoutingStore(config, self.files)
        self.active_profile_file = config.system.generated_dir / "active-upstream"
        self.log_file = config.system.log_dir / "upstream.log"
        self._lock_path = config.system.generated_dir / ".upstream.lock"
        self._lock_fd: int | None = None
        self._lock_depth = 0

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize every operation that mutates nftables/policy-routing/
        active-profile state, across processes.

        `korctl upstream watch` (the watchdog) runs as its own long-lived
        process calling ensure_policy_routing()/enforce_profile_enablement()/
        recover() on a timer, fully independent of the FastAPI worker
        process handling switch_profile()/connect()/disconnect() via the
        admin API or CLI. Without a lock, a manual switch_profile() (a full
        nftables reload + policy-route apply) can interleave with a
        concurrent watchdog tick reading a now-stale selected_profile() and
        re-asserting a route to the OLD interface right after the switch --
        misrouting marked traffic until the next tick.

        fcntl.flock on a fixed file serializes this across processes.
        Reentrant *within one instance* via a depth counter and one
        persistent fd, so a method that calls another locking method on
        `self` (e.g. enforce_profile_enablement() calling self.connect())
        doesn't self-deadlock -- re-flocking the SAME fd is a no-op, but two
        independently-opened fds from the same process are treated as
        unrelated locks by flock(2) and would deadlock against each other.
        """
        if self._lock_depth == 0:
            if self._lock_fd is None:
                self.files.ensure_dir(self._lock_path.parent)
                self._lock_fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        self._lock_depth += 1
        try:
            yield
        finally:
            self._lock_depth -= 1
            if self._lock_depth == 0 and self._lock_fd is not None:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def list_profiles(self) -> list[UpstreamProfileConfig]:
        return self.config.upstream.profiles

    def _named_target_routing(
        self,
    ) -> list[tuple[UpstreamProfileConfig, PolicyRoutingService]]:
        """Every profile with its own routes/domains assigned, paired with a
        PolicyRoutingService for its auto-derived fwmark/table (see
        RoutingService.list_targets()). Independent of which profile is
        active/selected -- a named target's traffic always follows its own
        assigned profile. Empty when upstream is disabled: named targets
        don't exist at all then, same as the rendered nftables rules."""
        if not self.config.upstream.enabled:
            return []
        from kornode.services.routing import RoutingService

        targets_by_name = {
            target.name: target
            for target in RoutingService(self.config).list_targets(
                default_interface=self.config.routing.main_interface
            )
            if target.name != "default"
        }
        result: list[tuple[UpstreamProfileConfig, PolicyRoutingService]] = []
        for profile in self.config.upstream.profiles:
            target = targets_by_name.get(profile.name)
            if target is None:
                continue
            result.append(
                (
                    profile,
                    PolicyRoutingService(
                        self.config,
                        runner=self.runner,
                        fwmark=target.fwmark,
                        table_id=target.table_id,
                    ),
                )
            )
        return result

    def selected_profile(self) -> UpstreamProfileConfig | None:
        """The runtime-switched active profile (active_profile_file), or
        the config's default if nothing was switched at runtime.

        A disabled profile is never returned, even if it's still the
        on-disk marker (e.g. it was switched to, then disabled later) --
        see UpstreamConfig.selected_profile for why falling through
        doesn't auto-promote a replacement.
        """
        profiles = {profile.name: profile for profile in self.config.upstream.profiles}
        for line in self.files.read_lines(self.active_profile_file):
            name = line.strip()
            if name and name in profiles:
                profile = profiles[name]
                return profile if profile.enabled else None
        return self.config.upstream.selected_profile()

    def _profile_by_name(self, name: str) -> UpstreamProfileConfig:
        for profile in self.config.upstream.profiles:
            if profile.name == name:
                return profile
        raise ValueError(f"unknown upstream profile: {name}")

    def profile_interface(self, profile: UpstreamProfileConfig) -> str:
        return self.config.upstream.profile_interface(profile)

    def active_interface(self) -> str:
        selected = self.selected_profile()
        if selected is None:
            return self.config.upstream.interface
        return self.profile_interface(selected)

    def status(self) -> UpstreamStatus:
        selected = self.selected_profile()
        connections: list[dict[str, object]] = []
        active_connected = False
        active_local: str | None = None
        active_remote: str | None = None
        for profile in self.config.upstream.profiles:
            interface = self.profile_interface(profile)
            connected = self._profile_connected(profile)
            local_ip = self._interface_address(interface) if connected else None
            remote = self._remote_address(profile) if connected else None
            connected_since, connected_for_seconds = self._connection_age(profile)
            connections.append(
                {
                    "profile": profile.name,
                    "interface": interface,
                    "connected": connected,
                    "local_ip": local_ip,
                    "remote": remote,
                    "connected_since": connected_since,
                    "connected_for_seconds": connected_for_seconds,
                    "server_routing": self.server_routing_status(profile),
                }
            )
            if selected and profile.name == selected.name:
                active_connected = connected
                active_local = local_ip
                active_remote = remote
        return UpstreamStatus(
            enabled=self.config.upstream.enabled,
            active_profile=selected.name if selected else None,
            interface=self.active_interface(),
            connected=active_connected,
            local_ip=active_local,
            remote=active_remote,
            connections=connections,
        )

    def _pid_file(self, profile: UpstreamProfileConfig) -> Path:
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", profile.name)
        return self.config.system.generated_dir / f"upstream-{safe_name}.pid"

    def _read_pid(self, profile: UpstreamProfileConfig) -> int | None:
        try:
            content = self._pid_file(profile).read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return int(content) if content.isdigit() else None

    @staticmethod
    def _is_running(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            pass
        # Guard against pid-number recycling: a stale pid file (e.g. left
        # behind by a container restart, which resets the pid namespace)
        # must not make an unrelated long-lived process that inherited the
        # number look like our connection forever.
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return True  # /proc entry unreadable -- keep the kill(0) answer
        return b"openconnect" in cmdline

    def _profile_connected(self, profile: UpstreamProfileConfig) -> bool:
        if profile.kind == "external_interface":
            return self._interface_link_up(self.profile_interface(profile))
        pid = self._read_pid(profile)
        return pid is not None and self._is_running(pid)

    def _interface_link_up(self, interface: str) -> bool:
        """Whether a pre-existing interface (kind='external_interface')
        currently exists and reports link-up, via `ip -j link show`.

        This is read-only observation -- kornode never brings this
        interface up/down itself -- the external_interface analogue of
        _profile_connected()'s pid-liveness check above.
        """
        result = self.runner.run(
            ["ip", "-j", "link", "show", "dev", interface],
            timeout=5,
            check=False,
        )
        if not result.ok:
            return False
        try:
            entries = json.loads(result.stdout)
        except json.JSONDecodeError:
            return False
        for entry in entries if isinstance(entries, list) else []:
            if entry.get("operstate") == "UP" or "LOWER_UP" in entry.get("flags", []):
                return True
        return False

    def _connection_age(self, profile: UpstreamProfileConfig) -> tuple[str | None, int | None]:
        """Return the current OpenConnect process start time and age.

        A reconnect that replaces the OpenConnect process resets both values,
        making reconnects visible in the panel without maintaining separate
        mutable state. Runtime environments without readable procfs simply
        report no timing information. Meaningless for an external_interface
        profile -- there's no kornode-owned process to time.
        """
        if profile.kind == "external_interface":
            return None, None
        pid = self._read_pid(profile)
        if pid is None or not self._is_running(pid):
            return None, None
        try:
            stat_fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
            start_ticks = int(stat_fields[21])
            clock_ticks = int(os.sysconf("SC_CLK_TCK"))
            system_uptime = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
        except (OSError, ValueError, IndexError):
            return None, None
        age = max(0, int(system_uptime - (start_ticks / clock_ticks)))
        started_at = datetime.fromtimestamp(time.time() - age, tz=UTC).isoformat()
        return started_at, age

    def _interface_address(self, interface: str) -> str | None:
        result = self.runner.run(
            ["ip", "-j", "addr", "show", "dev", interface],
            timeout=5,
            check=False,
        )
        if not result.ok:
            return None
        try:
            entries = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        for entry in entries if isinstance(entries, list) else []:
            for addr in entry.get("addr_info", []):
                if addr.get("family") == "inet" and addr.get("local"):
                    return str(addr["local"])
        return None

    def _remote_address(self, profile: UpstreamProfileConfig) -> str | None:
        """Public IP this profile's openconnect is actually talking to.

        Read from the process's own established socket (ss, matched by the
        pid we already track) rather than the configured server name: the
        panel already shows server:port in the profiles table, and after
        DNS round-robin or a redirect the live endpoint may differ from it
        anyway.
        """
        pid = self._read_pid(profile)
        if pid is None:
            return None
        result = self.runner.run(["ss", "-H", "-tnp"], timeout=5, check=False)
        if not result.ok:
            return None
        for line in result.stdout.splitlines():
            if f"pid={pid}," not in line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                # Peer column is "ip:port" (or "[v6]:port"); the port is
                # already visible in the profiles table, keep the IP only.
                return parts[4].rsplit(":", 1)[0].strip("[]")
        return None

    def switch_profile(self, name: str) -> None:
        """Make `name` the active profile and re-point the redirection
        rules (nftables oifname + policy-route device) at its tunnel.

        The connection itself is untouched -- with several profiles
        connected simultaneously this is what makes failover a rule flip
        rather than a reconnect.
        """
        profile = self._profile_by_name(name)
        with self._locked():
            self.files.atomic_write_text(self.active_profile_file, f"{name}\n", mode=0o600)
            interface = self.profile_interface(profile)
            self.nftables.apply(outbound_interface=interface)
            if self._profile_connected(profile):
                self.policy_routing.apply(interface)

    def _profile_secrets_dir(self, profile: UpstreamProfileConfig) -> Path:
        return self.config.system.secrets_dir / "upstream" / profile.name

    def _materialize_cert(self, profile: UpstreamProfileConfig) -> tuple[Path | None, Path | None]:
        """Resolve on-disk cert/key paths, decoding any base64-provided content.

        cert_file/key_file (a path already on this host) and
        cert_file_base64/key_file_base64 (uploaded or pasted content) are
        mutually exclusive per field (enforced by UpstreamProfileConfig);
        base64 content is decoded into the profile's own secrets
        subdirectory right before connecting.
        """
        cert_path = profile.cert_file
        key_path = profile.key_file
        if profile.cert_file_base64 or profile.key_file_base64:
            self.files.ensure_dir(self._profile_secrets_dir(profile), mode=0o700)
        if profile.cert_file_base64:
            cert_path = self._profile_secrets_dir(profile) / "cert"
            self.files.atomic_write_bytes(cert_path, base64.b64decode(profile.cert_file_base64))
        if profile.key_file_base64:
            key_path = self._profile_secrets_dir(profile) / "key"
            self.files.atomic_write_bytes(key_path, base64.b64decode(profile.key_file_base64))
        return cert_path, key_path

    def openconnect_argv(
        self, profile: UpstreamProfileConfig, *, accepted_pin: str | None = None
    ) -> list[str]:
        """argv for dialing `profile`.

        `accepted_pin` is the pin of whatever certificate the server just
        presented, used for trusted_cert profiles without an explicit
        server_cert_pin (see _accepted_server_pin()).
        """
        server = f"{profile.server}:{profile.port}"
        if profile.camouflage_secret:
            server = f"{server}/?{profile.camouflage_secret}"
        argv = [
            "openconnect",
            "--interface",
            self.profile_interface(profile),
            "--protocol=anyconnect",
            "--non-inter",
            "--background",
            f"--pid-file={self._pid_file(profile)}",
        ]
        # The fwmark policy routing always owns tunnel egress now (no more
        # hands-off "direct" mode); the distribution vpnc-script would
        # additionally apply whatever the upstream pushes (default route,
        # split routes, resolv.conf) to this namespace -- on
        # network_mode: host that hijacks the host itself. Use the minimal
        # interface-only script instead.
        argv.append(f"--script={self._ensure_vpnc_script()}")
        # openconnect dropped --no-cert-check; a certificate that isn't
        # CA-trusted can only be accepted by pinning it.
        pin = profile.server_cert_pin or accepted_pin
        if pin:
            argv.extend(["--servercert", pin])
        # Username/password also apply to certificate profiles: an upstream
        # ocserv with several `auth =` lines (e.g. certificate + plain)
        # requires all of them, so it asks for a password after accepting
        # the client certificate.
        if profile.auth_type == "password" or profile.password:
            argv.append("--passwd-on-stdin")
        if profile.username:
            argv.extend(["--user", profile.username])
        if profile.auth_type in {"cert", "p12"}:
            cert_path, key_path = self._materialize_cert(profile)
            if cert_path:
                argv.extend(["--certificate", str(cert_path)])
                if key_path:
                    argv.extend(["--sslkey", str(key_path)])
                if profile.cert_pass:
                    # Through a 0600 --config file, never --key-password=
                    # on the command line, which every local user could read
                    # from the process list for the tunnel's whole lifetime.
                    argv.append(f"--config={self._materialize_key_password(profile)}")
        argv.append(server)
        return argv

    def _materialize_key_password(self, profile: UpstreamProfileConfig) -> Path:
        path = self._profile_secrets_dir(profile) / "openconnect.conf"
        self.files.ensure_dir(path.parent, mode=0o700)
        self.files.atomic_write_text(path, f"key-password={profile.cert_pass}\n", mode=0o600)
        return path

    def _accepted_server_pin(
        self, profile: UpstreamProfileConfig, *, dry_run: bool
    ) -> str | None:
        """Pin for a trusted_cert ("no cert check") profile. RUNTIME: network.

        Accepts whatever certificate the server presents right now, which is
        what --no-cert-check used to do -- still no protection against a
        man-in-the-middle. An explicit server_cert_pin always wins.
        """
        if not profile.trusted_cert or profile.server_cert_pin:
            return None
        if dry_run:
            return "pin-sha256:<fetched-from-server-at-connect>"
        # Only ever called for kind="openconnect" (connect() branches into
        # _activate_external_interface() before reaching this), where
        # `server` is validator-required (UpstreamProfileConfig.
        # validate_kind_fields) -- narrows the type for mypy.
        assert profile.server is not None
        try:
            pin = fetch_server_pin(profile.server, int(profile.port)).pin
        except (OSError, ValueError) as exc:
            raise CommandError(
                CommandResult(
                    argv=("openconnect", profile.server),
                    returncode=1,
                    stdout="",
                    stderr=(
                        f"could not read the server certificate of "
                        f"{profile.server}:{profile.port} to accept it: {exc}"
                    ),
                )
            ) from exc
        previous = self._read_accepted_pin(profile)
        if previous and previous != pin:
            self._append_log(
                f"WARNING profile '{profile.name}': the server now presents a different "
                f"key ({previous} -> {pin}); accepted automatically because the "
                "certificate check is disabled. Expected after a key rotation on the "
                "upstream; otherwise it may be a man-in-the-middle."
            )
        elif previous is None:
            self._append_log(
                f"profile '{profile.name}': certificate check disabled, accepting the "
                f"certificate the server presented ({pin}); set server_cert_pin to it "
                "to stop trusting whatever the server presents"
            )
        self.files.atomic_write_text(self._accepted_pin_file(profile), f"{pin}\n")
        return pin

    def _accepted_pin_file(self, profile: UpstreamProfileConfig) -> Path:
        # Last pin accepted for a trusted_cert profile, to notice key changes.
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", profile.name)
        return self.config.system.generated_dir / f"upstream-{safe_name}.accepted-pin"

    def _read_accepted_pin(self, profile: UpstreamProfileConfig) -> str | None:
        try:
            return self._accepted_pin_file(profile).read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def _ensure_vpnc_script(self) -> Path:
        """Install the interface-only vpnc-script into generated_dir.

        Copied from the shipped template on every connect so an image
        update propagates without manual steps; must be executable for
        openconnect to run it.
        """
        from kornode.renderers.base import default_template_dir

        source = default_template_dir() / "vpnc-script-kornode"
        target = self.config.system.generated_dir / "vpnc-script-kornode"
        self.files.ensure_dir(target.parent)
        self.files.atomic_write_text(target, source.read_text(encoding="utf-8"), mode=0o755)
        return target

    def _repair_stale_resolv_conf(self) -> None:
        """Clear a leftover vpnc-script marker from a previously killed connect.

        vpnc-script only backs up /etc/resolv.conf when it does NOT already
        carry this marker (`grep ... || cp ... "$RESOLV_CONF_BACKUP"`); if an
        earlier attempt was killed (e.g. our own connect timeout) before it
        could run its disconnect cleanup and restore the file, the marker is
        left behind. Every later connect then sees the marker, skips its own
        backup, and immediately fails trying to read a backup file that (from
        that run's point of view) was never created:
        "cannot open .../resolv.conf-backup.<pid>: No such file". There is no
        way to recover the true pre-VPN content at this point; stripping the
        marker just lets the next connect start clean instead of failing
        forever.
        """
        try:
            content = RESOLV_CONF.read_text(encoding="utf-8")
        except OSError:
            return
        lines = content.splitlines()
        if not lines or not lines[0].startswith(VPNC_MARKER):
            return
        remaining = [
            line
            for line in lines[1:]
            if not line.startswith("# and will be overwritten by vpnc")
            and not line.startswith("# as long as the above mark is intact")
        ]
        self.files.atomic_write_text(
            RESOLV_CONF, "\n".join(remaining) + ("\n" if remaining else ""), mode=0o644
        )

    def _append_log(self, line: str) -> None:
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(line if line.endswith("\n") else f"{line}\n")
        except OSError:
            pass

    def connect(self, name: str | None = None, *, dry_run: bool = False) -> CommandResult:
        """Dial one profile's connection (the active one when name is None).

        Standby profiles connect without touching routing: their tunnels
        just sit ready so a later switch/failover is instant.
        """
        profile = self._profile_by_name(name) if name else self.selected_profile()
        if profile is None:
            raise ValueError("no upstream profile configured")
        if profile.kind == "external_interface":
            return self._activate_external_interface(profile, dry_run=dry_run)
        with self._locked():
            if not dry_run and self._profile_connected(profile):
                # Idempotent, mirroring disconnect's "not connected" no-op:
                # the watchdog auto-connects in the background, so a manual
                # Connect click can legitimately race an already-established
                # tunnel -- that's a state to report, not an error to scare
                # with.
                return CommandResult(
                    argv=("openconnect", "<already-running>"),
                    returncode=0,
                    stdout=f"profile '{profile.name}' is already connected",
                    stderr="",
                )
            selected = self.selected_profile()
            is_active = selected is not None and selected.name == profile.name
            if not dry_run:
                self._repair_stale_resolv_conf()
                # Load the split/full-mode kill-switch rules before dialing,
                # so marked traffic is blocked from the very first moment
                # rather than briefly leaking out unencrypted while
                # connecting. Rules always point at the ACTIVE profile's
                # interface, even when dialing a standby.
                self.nftables.apply(outbound_interface=self.active_interface())
            accepted_pin = self._accepted_server_pin(profile, dry_run=dry_run)
            result = self.runner.run(
                self.openconnect_argv(profile, accepted_pin=accepted_pin),
                input_text=f"{profile.password}\n" if profile.password else None,
                timeout=60,
                graceful_timeout=5,
                dry_run=dry_run,
                output_file=self.log_file,
                extra_secrets=[profile.password or "", profile.cert_pass or "", profile.port],
            )
            if not dry_run:
                self._verify_backgrounded(profile, result)
            if not dry_run and is_active:
                # A failed connect already raised CommandError above, so
                # reaching here means the tunnel is up and the interface
                # actually exists -- only now can a route via it be
                # installed.
                self.policy_routing.apply(self.profile_interface(profile))
            if not dry_run:
                # A connected profile that's also a named target gets its
                # own table pointed at its own interface, regardless of
                # whether it's the active one -- its assigned traffic
                # doesn't care which profile is "active".
                for target_profile, routing in self._named_target_routing():
                    if target_profile.name == profile.name:
                        routing.apply(self.profile_interface(profile))
                # The vpnc-script hook has already stored whatever routes/
                # split-DNS domains the server pushed in this handshake
                # (openconnect runs it before backgrounding); apply them now
                # rather than on the watchdog's next tick.
                self.apply_server_routing_if_changed()
            return result

    def _verify_backgrounded(self, profile: UpstreamProfileConfig, result: CommandResult) -> None:
        """Confirm the daemonized openconnect is still alive after --background.

        The --background parent exits 0 as soon as it forks into the
        background -- BEFORE the daemon finishes binding the tun device.
        A failure past that point (e.g. "Failed to bind local tun device
        (TUNSETIFF): Device or resource busy", one real-world cause: the
        interface name is still held by another still-negotiating attempt
        for the same profile) kills the daemon within well under a second,
        with no way for the already-exited parent to report it -- runner.run
        returns a clean success. Without this check, connect() would look
        successful, recover() would log a false "reconnected", and the
        watchdog's next few health-check ticks would find the process gone
        and retry the same doomed dial forever, each cycle logging a
        misleading success followed by silence instead of a visible error.
        """
        deadline = time.monotonic() + BACKGROUND_GRACE_SECONDS
        while not self._profile_connected(profile) and time.monotonic() < deadline:
            time.sleep(0.2)
        if self._profile_connected(profile):
            return
        raise CommandError(
            CommandResult(
                argv=result.argv,
                returncode=1,
                stdout=result.stdout,
                stderr=(
                    f"{result.stderr}\nopenconnect backgrounded but the process was "
                    f"gone moments later; see {self.log_file} for the actual failure "
                    "(e.g. the tun interface name already in use)"
                ).strip(),
            )
        )

    def _activate_external_interface(
        self, profile: UpstreamProfileConfig, *, dry_run: bool
    ) -> CommandResult:
        """'Connect' for an externally-managed interface (kind=
        'external_interface'): apply the same nftables/policy-routing
        kornode applies to a dialed profile, without ever touching the
        interface itself -- there's nothing to dial, kornode doesn't own
        its lifecycle.
        """
        interface = self.profile_interface(profile)
        argv = ("ip", "link", "show", "dev", interface)
        if dry_run:
            return CommandResult(argv=argv, returncode=0, stdout="", stderr="", dry_run=True)
        with self._locked():
            selected = self.selected_profile()
            is_active = selected is not None and selected.name == profile.name
            self.nftables.apply(outbound_interface=self.active_interface())
            if is_active and self._interface_link_up(interface):
                self.policy_routing.apply(interface)
            for target_profile, routing in self._named_target_routing():
                if target_profile.name == profile.name and self._interface_link_up(interface):
                    routing.apply(interface)
            return CommandResult(
                argv=argv,
                returncode=0,
                stdout=(
                    f"profile '{profile.name}' uses externally-managed interface "
                    f"'{interface}'; routing applied, no connection dialed"
                ),
                stderr="",
            )

    def connect_active(self, *, dry_run: bool = False) -> CommandResult:
        return self.connect(dry_run=dry_run)

    def _deactivate_external_interface(
        self, profile: UpstreamProfileConfig, *, dry_run: bool
    ) -> CommandResult:
        """'Disconnect' for an externally-managed interface: undo whatever
        routing was applied, without any process signaling -- kornode never
        owns this interface's lifecycle.
        """
        interface = self.profile_interface(profile)
        argv = ("ip", "link", "show", "dev", interface)
        if dry_run:
            return CommandResult(argv=argv, returncode=0, stdout="", stderr="", dry_run=True)
        with self._locked():
            selected = self.selected_profile()
            if selected is not None and selected.name == profile.name:
                self.policy_routing.cleanup()
            for target_profile, routing in self._named_target_routing():
                if target_profile.name == profile.name:
                    routing.cleanup()
            return CommandResult(
                argv=argv,
                returncode=0,
                stdout="routing deactivated (interface untouched)",
                stderr="",
            )

    def disconnect(self, name: str | None = None, *, dry_run: bool = False) -> CommandResult:
        """Tear down one profile's backgrounded openconnect (active when
        name is None).

        openconnect's --pid-file records the PID of the daemonized process;
        SIGTERM there runs its normal cleanup (vpnc-script disconnect,
        restoring /etc/resolv.conf) before it exits and removes its own
        pid-file. A grace period is given before SIGKILL, same reasoning as
        CommandRunner's graceful_timeout: an unconditional kill would leave
        resolv.conf in the same half-modified state this service otherwise
        repairs on the next connect.
        """
        profile = self._profile_by_name(name) if name else self.selected_profile()
        if profile is not None and profile.kind == "external_interface":
            return self._deactivate_external_interface(profile, dry_run=dry_run)
        with self._locked():
            pid = self._read_pid(profile) if profile is not None else None
            if profile is None or pid is None or not self._is_running(pid):
                return CommandResult(
                    argv=("kill", "-TERM", "<upstream-pid>"),
                    returncode=0,
                    stdout="not connected",
                    stderr="",
                    dry_run=dry_run,
                )
            argv = ("kill", "-TERM", str(pid))
            if dry_run:
                return CommandResult(argv=argv, returncode=0, stdout="", stderr="", dry_run=True)
            self._append_log(f"--- disconnect '{profile.name}' requested (pid {pid}) ---")
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + DISCONNECT_GRACE_SECONDS
            while time.monotonic() < deadline and self._is_running(pid):
                time.sleep(0.2)
            if self._is_running(pid):
                self._append_log(
                    f"pid {pid} did not exit within {DISCONNECT_GRACE_SECONDS}s, sending SIGKILL"
                )
                os.kill(pid, signal.SIGKILL)
            selected = self.selected_profile()
            if selected is not None and selected.name == profile.name:
                # Only the active profile's tunnel carries the policy route;
                # dropping a standby connection must not touch routing.
                self.policy_routing.cleanup()
            for target_profile, routing in self._named_target_routing():
                if target_profile.name == profile.name:
                    routing.cleanup()
            self._append_log(f"'{profile.name}' disconnected")
            return CommandResult(argv=argv, returncode=0, stdout="disconnected", stderr="")

    def healthcheck(self, *, dry_run: bool = False) -> CommandResult | None:
        profile = self.selected_profile()
        if profile is None or not profile.check_host:
            return None
        # -I <tunnel>: the check must prove the TUNNEL works, not the host's
        # uplink. Without it a check_host that also answers via the normal
        # route (e.g. 1.1.1.1) keeps reporting healthy forever while the
        # tunnel is actually dead, so the watchdog never recovers.
        #
        # -c 3: a single packet is a coin flip on any link with real-world
        # loss, especially seconds after a fresh reconnect while ARP/routing
        # is still settling -- ping still exits 0 the instant one reply
        # comes back, so this only ever adds latency on an already-unhealthy
        # tunnel, never on a healthy one.
        return self.runner.run(
            [
                "ping",
                "-I",
                self.profile_interface(profile),
                "-c",
                "3",
                "-i",
                "0.3",
                "-W",
                "2",
                profile.check_host,
            ],
            timeout=8,
            check=False,
            dry_run=dry_run,
        )

    def is_healthy(self) -> bool:
        """Whether the active connection currently looks good: the
        backgrounded process is alive and, if a check_host is configured,
        it still answers."""
        profile = self.selected_profile()
        if profile is None or not self._profile_connected(profile):
            return False
        result = self.healthcheck()
        return result is None or result.ok

    def ensure_policy_routing(self) -> list[CommandResult]:
        """Re-assert the fwmark rule/route for the active connected profile,
        and for every connected named-target profile.

        Run by the watchdog on every healthy tick: the kernel purges every
        route referencing the tunnel device whenever it bounces (openconnect
        reconnects internally without going through this service), leaving a
        'connected' upstream whose fwmark table is empty -- marked traffic
        then dies in the kill-switch until something re-installs the route.
        """
        with self._locked():
            results: list[CommandResult] = []
            profile = self.selected_profile()
            if profile is not None and self._profile_connected(profile):
                results.extend(self.policy_routing.ensure(self.profile_interface(profile)))
            for target_profile, routing in self._named_target_routing():
                if self._profile_connected(target_profile):
                    results.extend(routing.ensure(self.profile_interface(target_profile)))
            return results

    def enforce_profile_enablement(self) -> list[CommandResult]:
        """Bring every profile's connection up to date with its own
        `enabled` flag, besides the active one (which the watchdog's
        health-check/recover cycle already owns):

        - enabled and down -> dial it, keeping it warm.
        - disabled and up -> tear it down.

        Deliberately unconditional on upstream.failover: staying connected
        and being eligible for automatic switching are separate concerns.
        With failover on, keeping standbys warm is what makes recover()
        switch instantly instead of paying for a fresh handshake
        mid-outage; with failover off, it just keeps them ready (e.g. for
        a manual switch later) without ever making them active --
        switch_profile() is never called here. A disabled profile is never
        connected regardless of failover, including the profile that used
        to be active: selected_profile() already stops treating a disabled
        profile as active, so it naturally falls out of "active" here too
        and gets torn down like any other disabled profile.
        """
        with self._locked():
            selected = self.selected_profile()
            active_name = selected.name if selected else None
            results: list[CommandResult] = []
            for profile in self.config.upstream.profiles:
                connected = self._profile_connected(profile)
                if not profile.enabled:
                    # An external_interface profile's "connected" reading is
                    # link state, not "routing applied" -- link-down doesn't
                    # mean routing was already torn down, so disconnect()
                    # (idempotent) always runs for this kind regardless.
                    if connected or profile.kind == "external_interface":
                        results.append(self.disconnect(profile.name))
                    continue
                if profile.name == active_name:
                    continue
                if profile.kind == "openconnect" and connected:
                    continue
                # external_interface profiles fall through here every tick
                # regardless of `connected` (link state): connect() ->
                # _activate_external_interface() only (re)applies routing,
                # cheap and idempotent, and is the only way routing gets
                # (re)applied after e.g. a kornode restart where the link
                # was already up before kornode started observing it.
                try:
                    results.append(self.connect(profile.name))
                except (ValueError, CommandError):
                    self._append_log(f"standby connect to '{profile.name}' failed")
            return results

    def recover(self) -> bool:
        """Restore upstream connectivity after health-check failures.

        The active profile is retried first (reconnect). With
        upstream.failover enabled and several profiles configured, the
        next profiles in list order (wrapping around) are tried after
        that -- and a standby whose tunnel is already up is adopted by
        just switching the redirection rules to it, no dialing.
        """
        with self._locked():
            profiles = self.config.upstream.profiles
            if not profiles:
                return False
            # Only ever consider enabled profiles here: selected_profile()
            # already refuses to report a disabled profile as active (see
            # its docstring), so falling back to profiles[0] without the
            # same filter could pick a disabled one right back up --
            # connect() doesn't itself check `enabled`, so it would dial
            # successfully, and the next enforce_profile_enablement() tick
            # would immediately tear it back down again, live-locking
            # recover() against its own watchdog.
            names = [profile.name for profile in profiles if profile.enabled]
            if not names:
                self._append_log("no enabled upstream profile to recover")
                return False
            active = self.selected_profile()
            # Track separately from current_name: when there's no genuinely
            # active profile (active is None -- e.g. the one on record was
            # disabled), current_name falls back to names[0] as a search
            # starting point only. That fallback was never actually granted
            # the redirection rules, so it must still go through
            # switch_profile() below like any other failover target --
            # treating it as "already active" purely because its name
            # matches the fallback would leave a connected-but-not-
            # redirected tunnel.
            already_active = active is not None
            current_name = active.name if active else names[0]
            if self.config.upstream.failover and len(names) > 1:
                start = names.index(current_name) if current_name in names else 0
                order = [names[(start + offset) % len(names)] for offset in range(len(names))]
            else:
                order = [current_name]

            for name in order:
                profile = self._profile_by_name(name)
                if profile.kind == "external_interface":
                    # Nothing to redial for an externally-managed interface
                    # -- it can only ever be a failover SOURCE (the watchdog
                    # never calls recover() while one is selected and
                    # healthy-or-not, see upstream_watch()), never a target.
                    continue
                is_current_and_active = name == current_name and already_active
                if is_current_and_active:
                    # The active connection is the one that failed its
                    # checks: a live-but-unhealthy process must be torn down
                    # before redialing, and a dead one leaves nothing to
                    # keep.
                    if self._profile_connected(profile):
                        self.disconnect(name)
                    try:
                        self.connect(name)
                    except (ValueError, CommandError):
                        self._append_log(f"reconnect attempt to '{name}' failed")
                        continue
                elif not self._profile_connected(profile):
                    try:
                        self.connect(name)
                    except (ValueError, CommandError):
                        self._append_log(f"failover connect to '{name}' failed")
                        continue
                if is_current_and_active:
                    self._append_log(f"reconnected to '{name}'")
                else:
                    self.switch_profile(name)
                    self._append_log(f"failed over to '{name}' (redirection rules switched)")
                return True
            self._append_log("all reconnect attempts failed")
            return False

    # --- server-pushed routing (accept_server_routes / sync_url) ---------

    def profile_for_interface(self, interface: str) -> UpstreamProfileConfig | None:
        for profile in self.config.upstream.profiles:
            if self.profile_interface(profile) == interface:
                return profile
        return None

    def record_vpnc_event(
        self, reason: str, environ: dict[str, str] | None = None
    ) -> UpstreamProfileConfig | None:
        """Store what the server pushed in a connect/reconnect handshake.

        Called by `korctl upstream hook` from the vpnc-script, i.e. inside
        openconnect's own connect sequence -- while connect() may still hold
        the upstream lock in another process. So this only writes the
        profile's pushed-routing file and takes no lock; applying it is
        apply_server_routing_if_changed()'s job (connect() right after the
        dial, or the watchdog's next tick after an internal reconnect).
        """
        env = dict(os.environ if environ is None else environ)
        if reason not in VPNC_CONNECT_REASONS:
            return None
        profile = self.profile_for_interface(env.get("TUNDEV", ""))
        if profile is None:
            return None
        self.pushed.save_handshake(profile, parse_vpnc_environment(env))
        return profile

    def server_routing_status(self, profile: UpstreamProfileConfig) -> dict[str, object]:
        pushed = self.pushed.load(profile)
        return {
            "accept": profile.accept_server_routes,
            "active": profile.accept_server_routes and profile.route_host_enabled,
            "routes": pushed.routes,
            "domains": pushed.domains,
            "dns": pushed.dns,
            "source": pushed.source,
            "version": pushed.version,
            "updated_at": pushed.updated_at,
            "synced_at": pushed.synced_at,
            "sync_error": pushed.sync_error,
            "warnings": self._server_routing_warnings(profile, pushed),
        }

    def _server_routing_warnings(
        self, profile: UpstreamProfileConfig, pushed: PushedRouting
    ) -> list[str]:
        warnings: list[str] = []
        if profile.accept_server_routes and not profile.route_host_enabled:
            warnings.append(
                "accept_server_routes has no effect until host routing "
                "(route_host_enabled) is on for this profile"
            )
        # Everything inside server.ipv4_network is exempt from host marking
        # (nftables output chain) and the internal DNS address sits on the
        # loopback -- an upstream using the same subnet (both default to
        # 10.10.10.0/24) would be unreachable through the tunnel.
        own_network = ipaddress.ip_network(self.config.server.ipv4_network, strict=False)
        overlapping = [
            item
            for item in [*pushed.routes, *pushed.dns]
            if _overlaps(item, own_network)
        ]
        if overlapping:
            warnings.append(
                "the upstream pushes addresses inside this server's own "
                f"server.ipv4_network ({own_network}): {', '.join(overlapping)}; they "
                "can't be reached through the tunnel -- change server.ipv4_network "
                "(and internal_dns.listen) to a subnet the upstream doesn't use"
            )
        return warnings

    def apply_server_routing_if_changed(self, *, force: bool = False) -> list[CommandResult]:
        """Re-render/re-apply nftables and dnsmasq when any profile's
        effective server-pushed lists changed since the last apply.

        Cheap when nothing changed (one fingerprint comparison), so the
        watchdog runs it on every tick.
        """
        fingerprint = self.pushed.fingerprint()
        if not force and fingerprint == self.pushed.applied_fingerprint():
            return []
        from kornode.renderers.dnsmasq import DnsmasqConfigRenderer
        from kornode.services.internal_dns import InternalDnsService
        from kornode.services.server import ServerService

        with self._locked():
            # nftables.apply() renders its own file; only dnsmasq.conf needs
            # an explicit re-render here (the rest of the generated config
            # doesn't depend on pushed lists).
            results = self.nftables.apply(outbound_interface=self.active_interface())
            if results and not results[0].ok:
                self._append_log("applying server-pushed routes failed: nftables reload error")
                return results
            if self.config.dns_tunnel_active():
                renderer = DnsmasqConfigRenderer()
                self.files.atomic_write_text(
                    renderer.target_path(self.config), renderer.render(self.config)
                )
                try:
                    results.append(InternalDnsService(self.config).ensure_listen_address())
                    results.append(ServerService(self.config).process_action("restart", "dnsmasq"))
                except Exception as exc:  # noqa: BLE001 - supervisor may be absent
                    self._append_log(f"could not restart dnsmasq for pushed domains: {exc}")
            self.pushed.mark_applied(fingerprint)
            self._append_log(f"applied server-pushed routes/domains ({fingerprint})")
            return results

    def sync_server_routes(self, profile: UpstreamProfileConfig) -> PushedRouting:
        """Pull `profile`'s current routes/split-DNS from the upstream panel.

        RUNTIME: network. The request goes out through the profile's own
        tunnel (curl --interface binds the socket to the device), so it
        carries the tunnel address the upstream's /api/client/routing uses
        to identify us. Stores the result; apply_server_routing_if_changed()
        does the rest.
        """
        if not profile.sync_url:
            raise ValueError(f"profile {profile.name!r} has no sync_url")
        previous = self.pushed.load(profile)
        now = int(time.time())
        argv = [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            str(SYNC_TIMEOUT_SECONDS),
            "--max-filesize",
            str(SYNC_MAX_BYTES),
            "--interface",
            self.profile_interface(profile),
            "--user-agent",
            SYNC_USER_AGENT,
            "--header",
            "Accept: application/json",
        ]
        if not profile.sync_verify_tls:
            argv.append("--insecure")
        argv.append(f"{profile.sync_url}/api/client/routing")
        result = self.runner.run(argv, timeout=SYNC_TIMEOUT_SECONDS + 5, check=False)
        try:
            if not result.ok:
                raise ValueError(result.stderr.strip() or f"curl exited {result.returncode}")
            routes, domains, version = parse_sync_payload(json.loads(result.stdout or "null"))
        except ValueError as exc:
            failed = dataclasses.replace(previous, synced_at=now, sync_error=str(exc)[:500])
            self.pushed.save(profile, failed)
            return failed
        updated = dataclasses.replace(
            previous,
            routes=routes,
            domains=domains,
            source="sync",
            version=version,
            interface=self.profile_interface(profile),
            updated_at=now if version != previous.version else previous.updated_at,
            synced_at=now,
            sync_error="",
        )
        self.pushed.save(profile, updated)
        return updated

    def refresh_server_routes(self, *, now: float | None = None) -> list[CommandResult]:
        """Watchdog tick: sync every connected profile whose sync_interval
        elapsed, then apply whatever changed (handshake or sync)."""
        current = time.time() if now is None else now
        for profile in self.config.upstream.profiles:
            if not (
                profile.enabled
                and profile.accept_server_routes
                and profile.route_host_enabled
                and profile.sync_url
            ):
                continue
            if not self._profile_connected(profile):
                continue
            if current - self.pushed.load(profile).synced_at < profile.sync_interval:
                continue
            synced = self.sync_server_routes(profile)
            if synced.sync_error:
                self._append_log(f"routing sync for '{profile.name}' failed: {synced.sync_error}")
        return self.apply_server_routing_if_changed()


def _overlaps(item: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        return ipaddress.ip_network(item, strict=False).overlaps(network)
    except (ValueError, TypeError):
        return False
