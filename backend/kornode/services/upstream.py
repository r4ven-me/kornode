from __future__ import annotations

import base64
import contextlib
import fcntl
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
from kornode.services.command import CommandError, CommandResult, CommandRunner
from kornode.services.files import FileManager
from kornode.services.net import NetApplyError, NetService
from kornode.services.netinputs import active_profile_file, carrier_state_dir, selected_profile
from kornode.tunnels import vpnc_script_source
from kornode.tunnels.argv import DialSpec
from kornode.tunnels.argv import config_lines as tunnel_config_lines
from kornode.tunnels.argv import openconnect_argv as build_openconnect_argv
from kornode.tunnels.carrier import resolve_carrier_addresses
from kornode.tunnels.pin import fetch_server_pin

RESOLV_CONF = Path("/etc/resolv.conf")
VPNC_MARKER = "#@VPNC_GENERATED@"
DISCONNECT_GRACE_SECONDS = 5
# openconnect's --background parent exits 0 the moment it forks into the
# background, before the daemon finishes binding the tun device -- a
# failure past that point (e.g. the tun interface name already being in
# use) kills the daemon within well under a second with no way for the
# parent to report it. See _verify_backgrounded.
BACKGROUND_GRACE_SECONDS = 5
SYNC_TIMEOUT_SECONDS = 20
SYNC_MAX_BYTES = 1024 * 1024
SYNC_USER_AGENT = "kornode-client-sync/1.0"
VPNC_CONNECT_REASONS = {"connect", "reconnect"}
# What a watchdog tick survives: a failed dial, an unknown profile, or a
# reconciler pass that did not converge (retried on the next tick).
_RECOVERABLE = (ValueError, CommandError, NetApplyError)


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
        net: NetService | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.net = net or NetService(config, runner=self.runner)
        self.active_profile_file = active_profile_file(config)
        self.log_file = config.system.log_dir / "upstream.log"
        self._lock_path = config.system.generated_dir / ".upstream.lock"
        self._lock_fd: int | None = None
        self._lock_depth = 0

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize every operation that mutates the reconciler's inputs
        (active profile, carrier addresses, tunnels), across processes.

        `korctl upstream watch` (the watchdog) runs as its own long-lived
        process calling enforce_profile_enablement()/
        recover() on a timer, fully independent of the FastAPI worker
        process handling switch_profile()/connect()/disconnect() via the
        admin API or CLI. Without a lock, a manual switch_profile() (marker
        write + reconciler pass) can interleave with a concurrent watchdog
        tick reading a now-stale selected_profile() and acting on the OLD
        profile right after the switch.

        fcntl.flock on a fixed file serializes this across processes.
        Reentrant *within one instance* via a depth counter and one fd for
        the outermost operation, so a method that calls another locking
        method on `self` (e.g. enforce_profile_enablement() calling
        self.connect()) doesn't self-deadlock. The fd is closed when that
        outermost operation finishes: the watchdog creates a fresh service
        every tick, so keeping it open would leak one descriptor per tick.
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
                lock_fd = self._lock_fd
                self._lock_fd = None
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)

    def list_profiles(self) -> list[UpstreamProfileConfig]:
        return self.config.upstream.profiles

    def selected_profile(self) -> UpstreamProfileConfig | None:
        """The runtime-switched active profile (active_profile_file), or
        the config's default if nothing was switched at runtime."""
        return selected_profile(self.config, self.files)

    def _profile_by_name(self, name: str) -> UpstreamProfileConfig:
        for profile in self.config.upstream.profiles:
            if profile.name == name:
                return profile
        raise ValueError(f"unknown upstream profile: {name}")

    def profile_interface(self, profile: UpstreamProfileConfig) -> str:
        return self.config.upstream.profile_interface(profile)

    def _carrier_exclusion_state_path(self, profile: UpstreamProfileConfig) -> Path:
        return carrier_state_dir(self.config) / f"{profile.name}.addrs"

    def _resolve_carrier_addresses(self, profile: UpstreamProfileConfig) -> list[str]:
        """The literal IPv4 address(es) this profile's carrier connection
        actually dials, so they can be excluded from policy routing (see
        install_carrier_exclusion). A literal IP in `server` is returned
        as-is; a hostname is resolved via DNS on every call, since it may
        change between connects. Resolution failure yields an empty list
        rather than raising -- callers must tolerate "nothing to exclude
        yet", not block a connection attempt on a DNS hiccup.
        """
        return resolve_carrier_addresses(profile.server)

    def install_carrier_exclusion(
        self, profile: UpstreamProfileConfig, *, dry_run: bool = False
    ) -> list[str]:
        """Record the addresses this profile's own carrier connection dials,
        so the reconciler keeps them out of its policy table: without this,
        a host rule `via: upstream:<p>` can route openconnect's (or the cert-pin
        probe's) TCP session to the server back into a tunnel, looping or
        mis-routing the carrier connection (root cause 7).

        Resolves `profile.server` fresh every call; a no-longer-current
        address disappears from the file and so from the kernel on the next
        pass. Must be followed by a reconciler pass before dialing, not
        after -- the rule has to exist before the carrier's own handshake.
        """
        current = self._resolve_carrier_addresses(profile)
        if not dry_run:
            state_path = self._carrier_exclusion_state_path(profile)
            if current:
                self.files.write_unique_lines(state_path, current)
            else:
                state_path.unlink(missing_ok=True)
        return current

    def remove_carrier_exclusion(
        self, profile: UpstreamProfileConfig, *, dry_run: bool = False
    ) -> None:
        if not dry_run:
            self._carrier_exclusion_state_path(profile).unlink(missing_ok=True)

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

    def _interface_exists(self, interface: str) -> bool:
        """Whether the tunnel device has been created yet.

        TUN devices commonly report ``operstate UNKNOWN`` even while usable,
        so connection bootstrap must check existence rather than link state.
        """
        result = self.runner.run(
            ["ip", "link", "show", "dev", interface],
            timeout=5,
            check=False,
        )
        return result.ok

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
        """Make `name` the active profile and let the reconciler re-point
        the redirection (nft + policy routes) at its tunnel.

        The connection itself is untouched -- with several profiles
        connected simultaneously this is what makes failover a rule flip
        rather than a reconnect.
        """
        self._profile_by_name(name)  # reject unknown names before writing the marker
        with self._locked():
            self.files.atomic_write_text(self.active_profile_file, f"{name}\n", mode=0o600)
            self.net.converge()

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
        cert_path: Path | None = None
        key_path: Path | None = None
        if profile.auth_type in {"cert", "p12"}:
            cert_path, key_path = self._materialize_cert(profile)
        assert profile.server is not None  # validator-required for kind="openconnect"
        spec = DialSpec(
            server=profile.server,
            port=profile.port,
            interface=self.profile_interface(profile),
            pid_file=self._pid_file(profile),
            script=self._ensure_vpnc_script(),
            auth_type=profile.auth_type,
            username=profile.username,
            password=profile.password,
            server_cert_pin=profile.server_cert_pin,
            cert_path=cert_path,
            key_path=key_path,
            cert_pass=profile.cert_pass,
            camouflage_secret=profile.camouflage_secret,
        )
        lines = tunnel_config_lines(spec)
        config_path = self._materialize_openconnect_conf(profile, lines) if lines else None
        return build_openconnect_argv(spec, accepted_pin=accepted_pin, config_path=config_path)

    def _materialize_openconnect_conf(
        self, profile: UpstreamProfileConfig, lines: list[str]
    ) -> Path:
        path = self._profile_secrets_dir(profile) / "openconnect.conf"
        self.files.ensure_dir(path.parent, mode=0o700)
        self.files.atomic_write_text(path, "\n".join(lines) + "\n", mode=0o600)
        return path

    def _accepted_server_pin(self, profile: UpstreamProfileConfig, *, dry_run: bool) -> str | None:
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
        source = vpnc_script_source()
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
        timestamp = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file.open("a", encoding="utf-8") as handle:
                message = line.rstrip("\n")
                handle.write(f"[{timestamp}] {message}\n")
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
            # Must happen before any TCP to the server -- including the
            # cert-pin probe below -- and before the reconciler pass right
            # after, which reads the recorded carrier addresses to exempt
            # them from marking (D-20: the carrier is never marked).
            self.install_carrier_exclusion(profile, dry_run=dry_run)
            if not dry_run:
                self._repair_stale_resolv_conf()
                # Converge before dialing, so the kill-switch is in place and
                # marked traffic is blocked from the very first moment rather
                # than briefly leaking out unencrypted while connecting. A
                # failed pass aborts the connect (fail closed).
                self.net.converge()
            accepted_pin = self._accepted_server_pin(profile, dry_run=dry_run)
            result = self.runner.run(
                self.openconnect_argv(profile, accepted_pin=accepted_pin),
                input_text=f"{profile.password}\n" if profile.password else None,
                timeout=60,
                graceful_timeout=5,
                dry_run=dry_run,
                output_file=self.log_file,
                extra_secrets=[
                    profile.password or "",
                    profile.cert_pass or "",
                    profile.camouflage_secret or "",
                    profile.port,
                ],
            )
            if not dry_run:
                self._verify_backgrounded(profile, result)
            if not dry_run:
                # A failed connect already raised CommandError above, so the
                # tunnel is up and its interface exists: one more pass
                # installs the routes via it (active exit and named targets
                # alike -- the reconciler derives them all).
                self.net.converge()
            return result

    def _verify_backgrounded(self, profile: UpstreamProfileConfig, result: CommandResult) -> None:
        """Wait until both the daemon and its tunnel interface are ready.

        OpenConnect's ``--background`` parent exits before the daemon has
        finished creating the TUN device. Converging as soon as only the PID
        appears races that setup: the reconciler cannot install a route via
        a device that does not exist yet, and the watchdog can then enter a
        reconnect loop because its health probe runs without that route.
        """
        interface = self.profile_interface(profile)
        deadline = time.monotonic() + BACKGROUND_GRACE_SECONDS
        process_seen = False
        while time.monotonic() < deadline:
            process_seen = self._profile_connected(profile)
            if process_seen and self._interface_exists(interface):
                return
            time.sleep(0.2)

        if process_seen:
            detail = (
                f"tunnel interface '{interface}' did not appear within {BACKGROUND_GRACE_SECONDS}s"
            )
        else:
            detail = (
                "openconnect backgrounded but the process was gone moments later; "
                "the tunnel interface may already be in use"
            )
        raise CommandError(
            CommandResult(
                argv=result.argv,
                returncode=1,
                stdout=result.stdout,
                stderr=f"{result.stderr}\n{detail}; see {self.log_file} for details".strip(),
            )
        )

    def _activate_external_interface(
        self, profile: UpstreamProfileConfig, *, dry_run: bool
    ) -> CommandResult:
        """'Connect' for an externally-managed interface (kind=
        'external_interface'): converge the same routing a dialed profile
        gets, without ever touching the interface itself -- there's nothing
        to dial, kornode doesn't own its lifecycle.
        """
        interface = self.profile_interface(profile)
        argv = ("ip", "link", "show", "dev", interface)
        if dry_run:
            return CommandResult(argv=argv, returncode=0, stdout="", stderr="", dry_run=True)
        with self._locked():
            self.net.converge()
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
        """'Disconnect' for an externally-managed interface: converge the
        routing (the profile is disabled or being dropped), without any
        process signaling -- kornode never owns this interface's lifecycle.
        """
        interface = self.profile_interface(profile)
        argv = ("ip", "link", "show", "dev", interface)
        if dry_run:
            return CommandResult(argv=argv, returncode=0, stdout="", stderr="", dry_run=True)
        with self._locked():
            self.net.converge()
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
                if profile is not None and not dry_run:
                    # The process died on its own: its carrier exemption must
                    # not outlive it.
                    state_path = self._carrier_exclusion_state_path(profile)
                    if state_path.exists():
                        self.remove_carrier_exclusion(profile)
                        self.net.converge()
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
            self.remove_carrier_exclusion(profile)
            # The tunnel is gone: the reconciler drops its routes and keeps
            # the kill-switch for whatever was assigned to it.
            self.net.converge()
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

    def health_status(self) -> tuple[bool, str]:
        """Return health and a safe diagnostic reason for watchdog logs.

        The reason deliberately excludes the probe target and command output:
        either may contain deployment details that should not be copied into
        routine logs.
        """
        profile = self.selected_profile()
        if profile is None:
            return False, "no active upstream profile"
        if not self._profile_connected(profile):
            return False, "connection process or interface is down"
        result = self.healthcheck()
        if result is not None and not result.ok:
            return False, f"tunnel probe failed with exit status {result.returncode}"
        return True, "healthy"

    def log_healthcheck_failure(
        self,
        *,
        reason: str,
        streak: int,
        threshold: int,
        state: str,
    ) -> None:
        """Record one failed watchdog check without logging probe secrets."""
        self._append_log(
            f"healthcheck failed: {reason}; streak={streak}/{threshold}; state={state}"
        )

    def is_healthy(self) -> bool:
        """Whether the active connection currently looks good."""
        healthy, _reason = self.health_status()
        return healthy

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
                        try:
                            results.append(self.disconnect(profile.name))
                        except NetApplyError as exc:
                            self._append_log(f"disconnect of '{profile.name}': {exc}")
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
                except _RECOVERABLE:
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
                    try:
                        if self._profile_connected(profile):
                            self.disconnect(name)
                        self.connect(name)
                    except _RECOVERABLE:
                        self._append_log(f"reconnect attempt to '{name}' failed")
                        continue
                elif not self._profile_connected(profile):
                    try:
                        self.connect(name)
                    except _RECOVERABLE:
                        self._append_log(f"failover connect to '{name}' failed")
                        continue
                if is_current_and_active:
                    self._append_log(f"reconnected to '{name}'")
                else:
                    try:
                        self.switch_profile(name)
                    except NetApplyError as exc:
                        self._append_log(f"failover switch to '{name}' failed: {exc}")
                        continue
                    self._append_log(f"failed over to '{name}' (redirection rules switched)")
                return True
            self._append_log("all reconnect attempts failed")
            return False
