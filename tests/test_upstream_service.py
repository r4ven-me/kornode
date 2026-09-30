from __future__ import annotations

import base64
import fcntl
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kornode.config.models import AppConfig, UpstreamProfileConfig
from kornode.services import upstream as upstream_module
from kornode.services.command import CommandError, CommandResult
from kornode.services.upstream import UpstreamService


class FakeRunner:
    """tmp_path is optional: only tests exercising a connect() that must
    look genuinely alive afterward (_verify_backgrounded polls the pid
    file, see upstream.py) need it -- pass it whenever the test calls
    connect()/connect_active() outside dry_run and expects success, and
    call close() in a finally block to clean up the spawned fake process."""

    def __init__(self, tmp_path: Path | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.tmp_path = tmp_path
        self.processes: list[subprocess.Popen[bytes]] = []

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        self.calls.append({"argv": argv, **kwargs})
        if argv[0] == "openconnect" and self.tmp_path is not None:
            _write_fake_openconnect_pid(argv, self.processes, self.tmp_path)
        # Simulate a plain (non-Docker-managed) host for
        # NftablesService._ensure_docker_forward_compat()'s existence check,
        # so it's a no-op and doesn't add extra "nft" calls these tests
        # don't otherwise expect.
        if tuple(argv[:5]) == ("nft", "list", "chain", "ip", "filter"):
            return CommandResult(
                argv=tuple(argv), returncode=1, stdout="", stderr="No such file or directory"
            )
        return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")

    def call_for(self, program: str) -> dict[str, Any]:
        return next(call for call in self.calls if call["argv"][0] == program)

    def close(self) -> None:
        for process in self.processes:
            process.terminate()
        for process in self.processes:
            process.wait(timeout=5)


def _write_pid(service: UpstreamService, pid: int | str) -> None:
    profile = service.selected_profile()
    assert profile is not None
    path = service._pid_file(profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid))


def _spawn_fake_openconnect(tmp_path: Path) -> subprocess.Popen[bytes]:
    """A live process whose /proc/<pid>/cmdline says "openconnect".

    _is_running() verifies the command line to defend against pid-number
    recycling, so tests can no longer pass an arbitrary live pid (e.g.
    os.getpid(), which reads as python) as a fake connection.
    """
    ready_file = tmp_path / f"fake-oc-ready-{time.monotonic_ns()}"
    script = (
        "import signal, sys, time\n"
        "signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))\n"
        f"open({str(ready_file)!r}, 'w').close()\n"
        "time.sleep(30)\n"
    )
    process = subprocess.Popen(
        ["bash", "-c", 'exec -a openconnect "$0" -c "$1"', sys.executable, script]
    )
    deadline = time.monotonic() + 5
    while not ready_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    return process


def _write_fake_openconnect_pid(
    argv: list[str],
    processes: list[subprocess.Popen[bytes]],
    tmp_path: Path,
) -> None:
    """Simulate a real openconnect --background daemon staying alive: spawn
    a fake process with an "openconnect" cmdline and write its pid to
    whatever --pid-file= the call requested, so _verify_backgrounded's
    post-connect liveness poll (see upstream.py) finds a live connection
    the same way it would for a genuinely successful dial."""
    pid_file = next((arg.split("=", 1)[1] for arg in argv if arg.startswith("--pid-file=")), None)
    if pid_file is None:
        return
    process = _spawn_fake_openconnect(tmp_path)
    processes.append(process)
    Path(pid_file).parent.mkdir(parents=True, exist_ok=True)
    Path(pid_file).write_text(str(process.pid))


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
                "log_dir": tmp_path / "logs",
            }
        }
    )


def _upstream_config(tmp_path: Path, **upstream: object) -> dict[str, object]:
    return {
        "system": {
            "data_dir": tmp_path / "data",
            "generated_dir": tmp_path / "generated",
            "secrets_dir": tmp_path / "secrets",
        },
        "routing": {"fwmark": "0x0c01", "table_id": 1201},
        "upstream": {"enabled": True, **upstream},
    }


def test_upstream_profile_name_allows_a_leading_digit(tmp_path: Path) -> None:
    # Regression test: the name validator used to require the first
    # character to be a letter (mirroring OidcProviderConfig/
    # GroupPolicyConfig's own pattern at the time), which had nothing to do
    # with the actual path-traversal concern it exists for -- "4laddin" is
    # just as safe a path segment as "aladdin".
    config = AppConfig.model_validate(
        _upstream_config(
            tmp_path,
            profiles=[
                {
                    "name": "4laddin",
                    "server": "vpn.example.com",
                    "auth_type": "password",
                    "username": "user",
                }
            ],
        )
    )

    assert config.upstream.profiles[0].name == "4laddin"


def test_upstream_profile_name_rejects_path_traversal_characters(tmp_path: Path) -> None:
    # Regression test: profile.name is used unsanitized as a path segment in
    # _profile_secrets_dir() (secrets_dir / "upstream" / profile.name), which
    # receives attacker-controllable base64 cert/key material via the admin
    # API -- an unvalidated "../" would be a path-traversal / arbitrary file
    # write.
    with pytest.raises(ValidationError, match="short identifier"):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[
                    {
                        "name": "../evil",
                        "server": "vpn.example.com",
                        "auth_type": "password",
                        "username": "user",
                    }
                ],
            )
        )


def test_upstream_profile_host_routes_and_domains_are_validated(tmp_path: Path) -> None:
    # host_routes/host_domains reuse the same _validate_cidr/_validate_domain
    # helpers as routes/domains -- a malformed entry must be rejected the
    # same way.
    with pytest.raises(ValidationError):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[
                    {
                        "name": "finance",
                        "server": "vpn.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "route_host_enabled": True,
                        "host_routes": ["not-a-cidr"],
                    }
                ],
            )
        )


def test_upstream_profile_route_clients_enabled_defaults_true(tmp_path: Path) -> None:
    # Compatibility default: existing configs that already populate
    # routes/domains without ever having heard of route_clients_enabled must
    # keep behaving as before (routes/domains active) after upgrading.
    config = AppConfig.model_validate(
        _upstream_config(
            tmp_path,
            profiles=[
                {
                    "name": "finance",
                    "server": "vpn.example.com",
                    "auth_type": "password",
                    "username": "user",
                    "routes": ["10.50.0.0/16"],
                }
            ],
        )
    )

    assert config.upstream.profiles[0].route_clients_enabled is True
    assert config.upstream.profiles[0].route_host_enabled is False


def test_upstream_profiles_with_colliding_safe_names_are_rejected(tmp_path: Path) -> None:
    # "My-VPN" and "my_vpn" both normalize to the same nftables set name
    # (RoutingService.list_targets()'s profile_safe_name()), which would
    # break the whole ruleset load.
    with pytest.raises(ValidationError, match="normalized"):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[
                    {
                        "name": "My-VPN",
                        "server": "a.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "interface": "oc-a",
                        "routes": ["10.1.0.0/16"],
                    },
                    {
                        "name": "my_vpn",
                        "server": "b.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "interface": "oc-b",
                        "routes": ["10.2.0.0/16"],
                    },
                ],
            )
        )


def test_upstream_profiles_with_colliding_routing_offsets_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="routing_offset"):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[
                    {
                        "name": "a",
                        "server": "a.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "interface": "oc-a",
                        "routing_offset": 5,
                    },
                    {
                        "name": "b",
                        "server": "b.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "interface": "oc-b",
                        "routing_offset": 5,
                    },
                ],
            )
        )


def test_routing_fwmark_zero_is_rejected(tmp_path: Path) -> None:
    # fwmark 0 is an unmarked packet's implicit mark -- using it would make
    # the forward kill-switch's "oifname != <tunnel> drop" rule match
    # virtually all forwarded traffic, not just what kornode marked.
    with pytest.raises(ValidationError, match="must not be 0"):
        AppConfig.model_validate(
            {
                "system": {
                    "data_dir": tmp_path / "data",
                    "generated_dir": tmp_path / "generated",
                    "secrets_dir": tmp_path / "secrets",
                },
                "routing": {"fwmark": "0x0"},
            }
        )


@pytest.mark.parametrize("table_id", [253, 254, 255])
def test_routing_table_id_rejects_kernel_reserved_values(tmp_path: Path, table_id: int) -> None:
    with pytest.raises(ValidationError, match="reserved"):
        AppConfig.model_validate(
            {
                "system": {
                    "data_dir": tmp_path / "data",
                    "generated_dir": tmp_path / "generated",
                    "secrets_dir": tmp_path / "secrets",
                },
                "routing": {"table_id": table_id},
            }
        )


def test_derived_per_profile_table_id_rejects_kernel_reserved_values(tmp_path: Path) -> None:
    # routing.table_id (252) + this profile's offset (1, the only profile)
    # lands on 253, a kernel-reserved table -- must be rejected even though
    # the top-level table_id itself is fine on its own.
    with pytest.raises(ValidationError, match="reserved"):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[
                    {
                        "name": "a",
                        "server": "a.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "interface": "oc-a",
                        "routes": ["10.1.0.0/16"],
                    },
                ],
            )
            | {"routing": {"fwmark": "0x0c01", "table_id": 252}}
        )


def test_openconnect_argv_always_uses_minimal_vpnc_script(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            },
            "routing": {"mode": "split"},
        }
    )
    profile = UpstreamProfileConfig(
        name="primary", server="vpn.example.com", auth_type="password", username="user"
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    script_args = [arg for arg in argv if arg.startswith("--script=")]
    assert len(script_args) == 1
    script = Path(script_args[0].split("=", 1)[1])
    assert script.exists()
    assert os.access(script, os.X_OK)
    content = script.read_text(encoding="utf-8")
    # The whole point: never delegate to the distribution vpnc-script,
    # which would apply upstream-pushed routes/DNS to the namespace.
    assert "/usr/share/vpnc-scripts" not in content
    assert "ip link set" in content


def test_openconnect_argv_appends_camouflage_secret_to_target(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        port="443",
        auth_type="password",
        username="user",
        camouflage_secret="s3cret",
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    assert argv[-1] == "vpn.example.com:443/?s3cret"


def test_openconnect_argv_omits_camouflage_suffix_when_unset(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary", server="vpn.example.com", port="443", auth_type="password", username="user"
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    assert argv[-1] == "vpn.example.com:443"


def test_openconnect_argv_uses_cert_file_path_directly(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="cert",
        cert_file="/etc/kornode/upstream.crt",
        key_file="/etc/kornode/upstream.key",
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    assert "--certificate" in argv
    assert argv[argv.index("--certificate") + 1] == "/etc/kornode/upstream.crt"
    assert argv[argv.index("--sslkey") + 1] == "/etc/kornode/upstream.key"


def test_openconnect_argv_materializes_base64_cert_and_key(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="cert",
        cert_file_base64=base64.b64encode(b"cert-bytes").decode(),
        key_file_base64=base64.b64encode(b"key-bytes").decode(),
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    cert_path = Path(argv[argv.index("--certificate") + 1])
    key_path = Path(argv[argv.index("--sslkey") + 1])
    assert cert_path.read_bytes() == b"cert-bytes"
    assert key_path.read_bytes() == b"key-bytes"
    assert cert_path.parent == tmp_path / "secrets" / "upstream" / "primary"


def test_openconnect_argv_materializes_base64_p12_without_key(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="p12",
        cert_file_base64=base64.b64encode(b"p12-bytes").decode(),
        cert_pass="hunter2",
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    cert_path = Path(argv[argv.index("--certificate") + 1])
    assert cert_path.read_bytes() == b"p12-bytes"
    assert "--sslkey" not in argv
    assert _key_password_from_config(argv) == "hunter2"


def test_openconnect_argv_passes_cert_pass_as_key_password(tmp_path: Path) -> None:
    # Regression test: cert_pass was stored and masked in logs but never
    # actually handed to openconnect, so it always fell back to prompting
    # interactively for the PKCS#12/key passphrase and failed under
    # --non-inter ("User input required in non-interactive mode").
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="cert",
        cert_file="/etc/kornode/upstream.crt",
        key_file="/etc/kornode/upstream.key",
        cert_pass="hunter2",
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    assert _key_password_from_config(argv) == "hunter2"


def test_openconnect_argv_keeps_key_password_out_of_the_process_list(tmp_path: Path) -> None:
    # --key-password=PASS would sit in /proc/<pid>/cmdline (`ps aux`) for the
    # tunnel's whole lifetime; it goes through a 0600 --config file instead.
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="cert",
        cert_file="/etc/kornode/upstream.crt",
        cert_pass="hunter2",
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    assert not any("hunter2" in arg for arg in argv)
    config_path = Path(next(arg for arg in argv if arg.startswith("--config=")).split("=", 1)[1])
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert config_path.parent == tmp_path / "secrets" / "upstream" / "primary"


def test_openconnect_argv_omits_key_password_when_unset(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="cert",
        cert_file="/etc/kornode/upstream.crt",
        key_file="/etc/kornode/upstream.key",
    )

    argv = UpstreamService(config).openconnect_argv(profile)

    assert not any(arg.startswith(("--key-password", "--config")) for arg in argv)


def _key_password_from_config(argv: list[str]) -> str | None:
    for arg in argv:
        if arg.startswith("--config="):
            content = Path(arg.split("=", 1)[1]).read_text(encoding="utf-8")
            for line in content.splitlines():
                if line.startswith("key-password="):
                    return line.split("=", 1)[1]
    return None


def test_openconnect_argv_daemonizes_with_pid_file(tmp_path: Path) -> None:
    # Regression test: openconnect stays in the foreground holding the tunnel
    # open for as long as the connection lives, so without --background a
    # *successful* connection never returns on its own -- our own code would
    # then wait out its timeout and report a working connection as a failure.
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="cert",
        cert_file="/etc/kornode/upstream.crt",
        key_file="/etc/kornode/upstream.key",
    )
    service = UpstreamService(config)

    argv = service.openconnect_argv(profile)

    assert "--background" in argv
    assert f"--pid-file={service._pid_file(profile)}" in argv


def test_cert_file_and_cert_file_base64_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not both"):
        UpstreamProfileConfig(
            name="primary",
            server="vpn.example.com",
            auth_type="cert",
            cert_file="/etc/kornode/upstream.crt",
            cert_file_base64=base64.b64encode(b"cert-bytes").decode(),
        )


def test_cert_file_base64_must_be_valid_base64() -> None:
    with pytest.raises(ValueError, match="valid base64"):
        UpstreamProfileConfig(
            name="primary",
            server="vpn.example.com",
            auth_type="cert",
            cert_file_base64="not-valid-base64!!!",
        )


def test_cert_file_base64_accepts_standard_multiline_wrapping(tmp_path: Path) -> None:
    # Regression test: `base64 file.p12` (and most other base64 tools) wrap
    # output at 64/76 characters per line. base64.b64decode(..., validate=True)
    # rejects the embedded newlines outright, so pasting standard base64
    # output -- rather than a single unwrapped line -- always failed.
    encoded = base64.b64encode(b"p12-bytes" * 20).decode()
    wrapped = "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))

    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="p12",
        cert_file_base64=wrapped,
    )

    assert profile.cert_file_base64 == encoded

    config = _config(tmp_path)
    argv = UpstreamService(config).openconnect_argv(profile)
    cert_path = Path(argv[argv.index("--certificate") + 1])
    assert cert_path.read_bytes() == b"p12-bytes" * 20


def _profile(name: str = "primary", server: str = "vpn.example.com") -> UpstreamProfileConfig:
    return UpstreamProfileConfig(
        name=name, server=server, auth_type="password", username="user"
    )


def test_connect_active_repairs_stale_resolv_conf_and_uses_graceful_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text(
        "#@VPNC_GENERATED@ -- this file is generated, do not edit\n"
        "# and will be overwritten by vpnc\n"
        "# as long as the above mark is intact\n"
        "nameserver 10.0.0.1\n"
    )
    monkeypatch.setattr(upstream_module, "RESOLV_CONF", resolv_conf)

    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    runner = FakeRunner(tmp_path)
    service = UpstreamService(config, runner=runner)
    try:
        service.connect_active()
    finally:
        runner.close()

    assert resolv_conf.read_text() == "nameserver 10.0.0.1\n"
    openconnect_call = runner.call_for("openconnect")
    assert openconnect_call["graceful_timeout"] == 5
    assert openconnect_call["output_file"] == service.log_file


def test_connect_active_leaves_healthy_resolv_conf_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text("nameserver 10.0.0.1\n")
    monkeypatch.setattr(upstream_module, "RESOLV_CONF", resolv_conf)

    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    runner = FakeRunner(tmp_path)
    service = UpstreamService(config, runner=runner)
    try:
        service.connect_active()
    finally:
        runner.close()

    assert resolv_conf.read_text() == "nameserver 10.0.0.1\n"


def test_connect_active_does_not_repair_resolv_conf_on_dry_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv_conf = tmp_path / "resolv.conf"
    stale_content = "#@VPNC_GENERATED@ -- generated, do not edit\nnameserver 10.0.0.1\n"
    resolv_conf.write_text(stale_content)
    monkeypatch.setattr(upstream_module, "RESOLV_CONF", resolv_conf)

    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    runner = FakeRunner()
    service = UpstreamService(config, runner=runner)

    service.connect_active(dry_run=True)

    assert resolv_conf.read_text() == stale_content


def test_repair_stale_resolv_conf_noop_when_marker_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text("nameserver 10.0.0.1\n")
    monkeypatch.setattr(upstream_module, "RESOLV_CONF", resolv_conf)

    UpstreamService(_config(tmp_path))._repair_stale_resolv_conf()

    assert resolv_conf.read_text() == "nameserver 10.0.0.1\n"


def test_repair_stale_resolv_conf_noop_when_file_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upstream_module, "RESOLV_CONF", tmp_path / "does-not-exist")

    UpstreamService(_config(tmp_path))._repair_stale_resolv_conf()


def test_status_reports_connected_when_pid_file_has_live_process(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    service = UpstreamService(config)
    process = _spawn_fake_openconnect(tmp_path)
    try:
        _write_pid(service, process.pid)

        assert service.status().connected is True
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_live_pid_of_a_different_program_does_not_count_as_connected(
    tmp_path: Path,
) -> None:
    # Regression test: container restarts reset the pid namespace, so a
    # stale pid file can point at an unrelated long-lived process (ocserv
    # worker, dnsmasq...). Without checking /proc/<pid>/cmdline that made
    # the profile look permanently connected -- Connect refused to run
    # while the status genuinely was "down".
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    service = UpstreamService(config)
    _write_pid(service, os.getpid())  # alive, but it's python, not openconnect

    assert service.status().connected is False


def test_status_reports_not_connected_when_pid_file_stale(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    service = UpstreamService(config)
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    _write_pid(service, process.pid)

    assert service.status().connected is False


def test_status_reports_not_connected_when_no_pid_file(tmp_path: Path) -> None:
    assert UpstreamService(_config(tmp_path)).status().connected is False


def test_connect_raises_when_backgrounded_process_dies_immediately(tmp_path: Path) -> None:
    """Regression test: openconnect's --background parent exits 0 the
    moment it forks into the background -- BEFORE the daemon finishes
    binding the tun device. If that later fails (e.g. "Failed to bind
    local tun device (TUNSETIFF): Device or resource busy"), the daemon
    dies within well under a second with no way for the already-exited
    parent to report it, so runner.run() alone sees a clean success.
    Without _verify_backgrounded, connect() would return that false
    success too."""
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    # No tmp_path passed -- FakeRunner reports the openconnect call as a
    # plain success without leaving a live process behind, exactly like a
    # daemon that backgrounded and then immediately died.
    service = UpstreamService(config, runner=FakeRunner())

    with pytest.raises(CommandError) as exc_info:
        service.connect_active()
    assert "gone moments later" in exc_info.value.result.stderr


def test_recover_reports_failure_instead_of_a_false_success_when_background_dies(
    tmp_path: Path,
) -> None:
    """The false "reconnected" this fixes wasn't just a cosmetic log line:
    recover() short-circuits (returns True) on the first apparent success,
    so a lying connect() meant the watchdog's own loop (see
    cli.py::upstream_watch) would keep resetting consecutive_failures to 0
    and never actually recover -- an invisible, endless retry loop on a
    connection that was never really up."""
    config = _config(tmp_path)
    config.upstream.failover = False
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    service = UpstreamService(config, runner=FakeRunner())

    assert service.recover() is False


def test_connect_active_is_a_noop_when_already_connected(tmp_path: Path) -> None:
    # Idempotency: the watchdog auto-connects in the background, so a manual
    # Connect can race an already-established tunnel; that must not error
    # and must not dial a second openconnect.
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    runner = FakeRunner()
    service = UpstreamService(config, runner=runner)
    process = _spawn_fake_openconnect(tmp_path)
    try:
        _write_pid(service, process.pid)

        result = service.connect_active()

        assert result.returncode == 0
        assert "already connected" in result.stdout
        assert not any(call["argv"][0] == "openconnect" for call in runner.calls)
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_disconnect_noop_when_not_connected(tmp_path: Path) -> None:
    result = UpstreamService(_config(tmp_path)).disconnect()

    assert result.returncode == 0
    assert result.stdout == "not connected"


def test_disconnect_terminates_process_gracefully(tmp_path: Path) -> None:
    process = _spawn_fake_openconnect(tmp_path)
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    service = UpstreamService(config, runner=FakeRunner())
    _write_pid(service, process.pid)

    result = service.disconnect()

    assert result.stdout == "disconnected"
    assert process.wait(timeout=2) == 0


def test_disconnect_dry_run_does_not_kill_process(tmp_path: Path) -> None:
    process = _spawn_fake_openconnect(tmp_path)
    try:
        config = _config(tmp_path)
        config.upstream.profiles.append(_profile())
        config.upstream.active_profile = "primary"
        service = UpstreamService(config)
        _write_pid(service, process.pid)

        result = service.disconnect(dry_run=True)

        assert result.dry_run is True
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_connect_active_applies_nftables_before_dialing_when_mode_not_direct(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    assert config.routing.mode == "full"
    runner = FakeRunner(tmp_path)
    service = UpstreamService(config, runner=runner)
    try:
        service.connect_active()
    finally:
        runner.close()

    programs = [call["argv"][0] for call in runner.calls]
    # One `nft -j list table ...` readiness probe (the live table's schema
    # doesn't match yet on this first apply, see NftablesService._apply_ruleset)
    # that decides a full recreate is needed, one atomic `nft -f` load
    # (folding the old table delete/redefine sequence into one transaction,
    # see templates/nftables.nft.j2), plus one `nft list chain ...` existence
    # check for the Docker DOCKER-USER compat shim (a no-op here since
    # FakeRunner reports it absent).
    assert programs.count("nft") == 3
    assert programs.index("nft") < programs.index("openconnect")


def test_connect_active_applies_policy_routing_after_successful_connect(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    runner = FakeRunner(tmp_path)
    service = UpstreamService(config, runner=runner)
    try:
        service.connect_active()
    finally:
        runner.close()

    ip_calls = [call["argv"] for call in runner.calls if call["argv"][0] == "ip"]
    assert ["ip", "route", "replace", "default", "dev", "oc-middle0", "table", "1201"] in ip_calls


def test_disconnect_cleans_up_policy_routing(tmp_path: Path) -> None:
    process = _spawn_fake_openconnect(tmp_path)
    runner = FakeRunner()
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    service = UpstreamService(config, runner=runner)
    _write_pid(service, process.pid)

    service.disconnect()
    process.wait(timeout=2)

    ip_calls = [call["argv"] for call in runner.calls if call["argv"][0] == "ip"]
    assert ["ip", "route", "flush", "table", "1201"] in ip_calls


def test_connect_applies_policy_routing_for_a_named_target_even_when_not_active(
    tmp_path: Path,
) -> None:
    # A profile with its own routes/domains gets its own table pointed at
    # its own interface as soon as it connects, regardless of which profile
    # is "active" -- its assigned traffic doesn't depend on that.
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(
        UpstreamProfileConfig(
            name="finance",
            server="finance.example.com",
            auth_type="password",
            username="user",
            interface="oc-finance",
            routes=["10.50.0.0/16"],
        )
    )
    config.upstream.enabled = True
    config.upstream.active_profile = "primary"
    runner = FakeRunner(tmp_path)
    service = UpstreamService(config, runner=runner)
    try:
        service.connect("finance")
    finally:
        runner.close()

    ip_calls = [call["argv"] for call in runner.calls if call["argv"][0] == "ip"]
    # finance is the 2nd configured profile (primary is 1st) -- its routing
    # offset is derived from that fixed position (2), not from a count of
    # profiles with routes, so table_id = 1201 + 2 = 1203.
    assert ["ip", "route", "replace", "default", "dev", "oc-finance", "table", "1203"] in ip_calls


def test_disconnect_cleans_up_named_target_policy_routing(tmp_path: Path) -> None:
    process = _spawn_fake_openconnect(tmp_path)
    runner = FakeRunner()
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(
        UpstreamProfileConfig(
            name="finance",
            server="finance.example.com",
            auth_type="password",
            username="user",
            interface="oc-finance",
            routes=["10.50.0.0/16"],
        )
    )
    config.upstream.enabled = True
    config.upstream.active_profile = "primary"
    service = UpstreamService(config, runner=runner)
    finance_profile = config.upstream.profiles[1]
    path = service._pid_file(finance_profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(process.pid))

    service.disconnect("finance")
    process.wait(timeout=2)

    ip_calls = [call["argv"] for call in runner.calls if call["argv"][0] == "ip"]
    # See the analogous comment in the connect() test above re: offset 2.
    assert ["ip", "route", "flush", "table", "1203"] in ip_calls


def test_ensure_policy_routing_covers_connected_named_targets(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(
        UpstreamProfileConfig(
            name="finance",
            server="finance.example.com",
            auth_type="password",
            username="user",
            interface="oc-finance",
            routes=["10.50.0.0/16"],
        )
    )
    config.upstream.enabled = True
    # No active_profile at all -- the default target is inactive, but the
    # named target must still be maintained on its own.
    runner = FakeRunner()
    service = UpstreamService(config, runner=runner)
    finance_profile = config.upstream.profiles[1]
    process = _spawn_fake_openconnect(tmp_path)
    try:
        path = service._pid_file(finance_profile)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(process.pid))

        service.ensure_policy_routing()
    finally:
        process.terminate()
        process.wait(timeout=5)

    ip_calls = [call["argv"] for call in runner.calls if call["argv"][0] == "ip"]
    assert any(
        call[:6] == ["ip", "route", "replace", "default", "dev", "oc-finance"] for call in ip_calls
    )


def test_is_healthy_false_when_not_connected(tmp_path: Path) -> None:
    assert UpstreamService(_config(tmp_path)).is_healthy() is False


def test_is_healthy_true_when_connected_without_check_host(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile())
    config.upstream.active_profile = "primary"
    service = UpstreamService(config)
    process = _spawn_fake_openconnect(tmp_path)
    try:
        _write_pid(service, process.pid)

        assert service.is_healthy() is True
    finally:
        process.terminate()
        process.wait(timeout=5)


class PingRunner:
    def __init__(self, *, ping_ok: bool) -> None:
        self.ping_ok = ping_ok

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        del kwargs
        if argv[0] == "ping":
            return CommandResult(
                argv=tuple(argv), returncode=0 if self.ping_ok else 1, stdout="", stderr=""
            )
        return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")


def test_healthcheck_pings_through_the_tunnel_interface(tmp_path: Path) -> None:
    # Regression test: a plain ping reaches a public check_host (1.1.1.1)
    # via the uplink even when the tunnel is dead, so the watchdog reported
    # healthy forever and never recovered.
    config = _config(tmp_path)
    config.upstream.profiles.append(
        UpstreamProfileConfig(
            name="primary",
            server="vpn.example.com",
            auth_type="password",
            username="user",
            check_host="1.1.1.1",
        )
    )
    config.upstream.active_profile = "primary"
    runner = FakeRunner()
    service = UpstreamService(config, runner=runner)

    service.healthcheck()

    ping = runner.call_for("ping")["argv"]
    assert ping[:3] == ["ping", "-I", "oc-middle0"]
    assert ping[-1] == "1.1.1.1"


def test_is_healthy_true_when_check_host_ping_succeeds(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(
        UpstreamProfileConfig(
            name="primary",
            server="vpn.example.com",
            auth_type="password",
            username="user",
            check_host="10.0.0.1",
        )
    )
    config.upstream.active_profile = "primary"
    service = UpstreamService(config, runner=PingRunner(ping_ok=True))
    process = _spawn_fake_openconnect(tmp_path)
    try:
        _write_pid(service, process.pid)

        assert service.is_healthy() is True
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_is_healthy_false_when_check_host_ping_fails(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(
        UpstreamProfileConfig(
            name="primary",
            server="vpn.example.com",
            auth_type="password",
            username="user",
            check_host="10.0.0.1",
        )
    )
    config.upstream.active_profile = "primary"
    service = UpstreamService(config, runner=PingRunner(ping_ok=False))
    process = _spawn_fake_openconnect(tmp_path)
    try:
        _write_pid(service, process.pid)

        assert service.is_healthy() is False
    finally:
        process.terminate()
        process.wait(timeout=5)


class ScriptedConnectRunner:
    """Fakes connect_active()'s underlying runner: openconnect calls whose
    server host is in fail_servers raise CommandError (as a real failed
    connect attempt would under check=True); everything else -- including
    the nftables/ip plumbing connect_active()/disconnect() also trigger --
    succeeds, and (for openconnect specifically) leaves a genuinely live
    fake process behind so _verify_backgrounded's post-connect liveness
    poll (see upstream.py) finds the connection still up, same as a real
    successful dial. Call close() in a finally block to clean these up."""

    def __init__(self, fail_servers: set[str], tmp_path: Path) -> None:
        self.fail_servers = fail_servers
        self.tmp_path = tmp_path
        self.calls: list[list[str]] = []
        self.processes: list[subprocess.Popen[bytes]] = []

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        del kwargs
        self.calls.append(list(argv))
        if argv[0] == "openconnect":
            host = argv[-1].split(":")[0]
            if host in self.fail_servers:
                result = CommandResult(
                    argv=tuple(argv), returncode=1, stdout="", stderr="auth failed"
                )
                raise CommandError(result)
            _write_fake_openconnect_pid(argv, self.processes, self.tmp_path)
        return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")

    def close(self) -> None:
        for process in self.processes:
            process.terminate()
        for process in self.processes:
            process.wait(timeout=5)


def test_recover_retries_same_profile_when_failover_disabled(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.failover = False
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers=set(), tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)
    try:
        assert service.recover() is True
    finally:
        runner.close()
    assert service.selected_profile() is not None
    assert service.selected_profile().name == "primary"


def test_recover_fails_over_to_next_profile_when_enabled(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.failover = True
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers={"vpn.example.com"}, tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        assert service.recover() is True
    finally:
        runner.close()
    assert service.selected_profile() is not None
    assert service.selected_profile().name == "backup"


def test_recover_does_not_fail_over_when_disabled(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.failover = False
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers={"vpn.example.com"}, tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        assert service.recover() is False
    finally:
        runner.close()
    assert service.selected_profile() is not None
    assert service.selected_profile().name == "primary"


def test_recover_wraps_around_the_profile_cycle(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.failover = True
    config.upstream.profiles.append(_profile("a", server="a.example.com"))
    config.upstream.profiles.append(_profile("b", server="b.example.com"))
    config.upstream.profiles.append(_profile("c", server="c.example.com"))
    config.upstream.active_profile = "c"
    runner = ScriptedConnectRunner(
        fail_servers={"c.example.com", "a.example.com"}, tmp_path=tmp_path
    )
    service = UpstreamService(config, runner=runner)

    try:
        assert service.recover() is True
    finally:
        runner.close()
    assert service.selected_profile() is not None
    assert service.selected_profile().name == "b"


def test_recover_returns_false_when_no_profiles_configured(tmp_path: Path) -> None:
    assert UpstreamService(_config(tmp_path)).recover() is False


def test_recover_never_dials_a_disabled_fallback_profile(tmp_path: Path) -> None:
    # Regression test: with the configured active_profile disabled,
    # selected_profile() correctly reports None (it never auto-promotes a
    # replacement) -- but recover()'s old fallback to profiles[0] didn't
    # check `enabled` either, so it could redial that same disabled profile.
    # connect() itself doesn't gate on `enabled`, so the dial would succeed,
    # and the very next enforce_profile_enablement() tick would immediately
    # tear it back down -- live-locking the watchdog against itself.
    config = _config(tmp_path)
    config.upstream.failover = True
    primary = _profile("primary")
    primary.enabled = False
    config.upstream.profiles.append(primary)
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    assert UpstreamService(config).selected_profile() is None

    runner = ScriptedConnectRunner(fail_servers=set(), tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)
    try:
        assert service.recover() is True
    finally:
        runner.close()

    assert service.selected_profile() is not None
    assert service.selected_profile().name == "backup"
    dialed_hosts = {
        call[-1].split(":")[0] for call in runner.calls if call[0] == "openconnect"
    }
    assert "vpn.example.com" not in dialed_hosts


def test_recover_returns_false_when_every_profile_is_disabled(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = _profile("primary")
    profile.enabled = False
    config.upstream.profiles.append(profile)

    assert UpstreamService(config).recover() is False


def test_enforce_profile_enablement_dials_disconnected_standbys(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.failover = False
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers=set(), tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        results = service.enforce_profile_enablement()
        assert len(results) == 1
        connections = {
            entry["profile"]: entry["connected"] for entry in service.status().connections
        }
        assert connections["backup"] is True
        # Never switched: the active profile is untouched even though the
        # standby is now connected too.
        assert service.selected_profile() is not None
        assert service.selected_profile().name == "primary"
    finally:
        runner.close()


def test_enforce_profile_enablement_skips_already_connected_standby(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers=set(), tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        service.connect("backup")
        results = service.enforce_profile_enablement()
    finally:
        runner.close()

    assert results == []


def test_enforce_profile_enablement_logs_and_continues_on_failure(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers={"backup.example.com"}, tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        results = service.enforce_profile_enablement()
    finally:
        runner.close()

    assert results == []
    log = (config.system.log_dir / "upstream.log").read_text(encoding="utf-8")
    assert "standby connect to 'backup' failed" in log


def test_enforce_profile_enablement_never_dials_a_disabled_standby(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    backup = _profile("backup", server="backup.example.com")
    backup.enabled = False
    config.upstream.profiles.append(backup)
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers=set(), tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        results = service.enforce_profile_enablement()
    finally:
        runner.close()

    assert results == []


def test_enforce_profile_enablement_disconnects_a_standby_that_became_disabled(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers=set(), tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        service.connect("backup")
        config.upstream.profiles[1].enabled = False

        results = service.enforce_profile_enablement()

        assert len(results) == 1
        connections = {
            entry["profile"]: entry["connected"] for entry in service.status().connections
        }
        assert connections["backup"] is False
    finally:
        runner.close()


def test_enforce_profile_enablement_disconnects_the_active_profile_once_disabled(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers=set(), tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        service.connect_active()
        config.upstream.profiles[0].enabled = False

        # Disabling drops selected_profile() entirely -- no auto-promotion
        # of a replacement -- yet the (now merely disabled) profile still
        # needs tearing down.
        assert service.selected_profile() is None
        results = service.enforce_profile_enablement()

        assert len(results) == 1
        assert service.status().connected is False
    finally:
        runner.close()


def test_selected_profile_skips_disabled_active_profile_config_default(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    profile = _profile("primary")
    profile.enabled = False
    config.upstream.profiles.append(profile)

    assert config.upstream.selected_profile() is None
    assert UpstreamService(config).selected_profile() is None


def test_profile_interface_first_profile_keeps_global_interface(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.interface = "oc-bl4ck0"
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    service = UpstreamService(config)

    assert service.profile_interface(config.upstream.profiles[0]) == "oc-bl4ck0"
    assert service.profile_interface(config.upstream.profiles[1]) == "oc-up1"


def test_profile_interface_explicit_value_wins(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = UpstreamProfileConfig(
        name="backup",
        server="backup.example.com",
        auth_type="password",
        username="user",
        interface="oc-custom7",
    )
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(profile)

    assert UpstreamService(config).profile_interface(profile) == "oc-custom7"


def test_duplicate_effective_interfaces_are_rejected() -> None:
    with pytest.raises(ValueError, match="distinct interfaces"):
        AppConfig.model_validate(
            {
                "upstream": {
                    "interface": "oc-x0",
                    "profiles": [
                        {
                            "name": "a",
                            "server": "a.example.com",
                            "auth_type": "password",
                            "username": "u",
                            "interface": "oc-x0",
                        },
                        {
                            "name": "b",
                            "server": "b.example.com",
                            "auth_type": "password",
                            "username": "u",
                            "interface": "oc-x0",
                        },
                    ],
                }
            }
        )


def test_connect_standby_profile_does_not_touch_policy_routing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = FakeRunner(tmp_path)
    service = UpstreamService(config, runner=runner)
    try:
        service.connect("backup")
    finally:
        runner.close()

    openconnect_call = runner.call_for("openconnect")
    assert "oc-up1" in openconnect_call["argv"]
    assert not any(
        call["argv"][:3] == ["ip", "route", "replace"] for call in runner.calls
    )


def test_switch_profile_repoints_rules_without_reconnecting(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(
        UpstreamProfileConfig(
            name="backup",
            server="backup.example.com",
            auth_type="password",
            username="user",
            interface="oc-backup0",
        )
    )
    config.upstream.active_profile = "primary"
    runner = FakeRunner()
    service = UpstreamService(config, runner=runner)
    process = _spawn_fake_openconnect(tmp_path)
    backup_pid = service._pid_file(config.upstream.profiles[1])
    backup_pid.parent.mkdir(parents=True, exist_ok=True)
    backup_pid.write_text(str(process.pid))

    service.switch_profile("backup")
    process.terminate()

    assert not any(call["argv"][0] == "openconnect" for call in runner.calls)
    assert any(call["argv"][0] == "nft" for call in runner.calls)
    ip_calls = [call["argv"] for call in runner.calls if call["argv"][0] == "ip"]
    assert [
        "ip", "route", "replace", "default", "dev", "oc-backup0", "table", "1201",
    ] in ip_calls
    assert service.selected_profile() is not None
    assert service.selected_profile().name == "backup"


def test_recover_adopts_already_connected_standby_without_dialing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.failover = True
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    runner = ScriptedConnectRunner(fail_servers={"vpn.example.com"}, tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)
    process = _spawn_fake_openconnect(tmp_path)
    backup_pid = service._pid_file(config.upstream.profiles[1])
    backup_pid.parent.mkdir(parents=True, exist_ok=True)
    backup_pid.write_text(str(process.pid))

    assert service.recover() is True
    process.terminate()
    assert service.selected_profile() is not None
    assert service.selected_profile().name == "backup"
    dialed = [call for call in runner.calls if call[0] == "openconnect"]
    # Only the failed retry of "primary" dialed; "backup" was adopted as-is.
    assert all("backup.example.com" not in call[-1] for call in dialed)


def test_status_reports_per_connection_details(tmp_path: Path) -> None:
    process = _spawn_fake_openconnect(tmp_path)
    pid = process.pid

    class AddrRunner:
        def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
            del kwargs
            if argv[:4] == ["ip", "-j", "addr", "show"]:
                payload = '[{"addr_info": [{"family": "inet", "local": "10.66.0.2"}]}]'
                return CommandResult(argv=tuple(argv), returncode=0, stdout=payload, stderr="")
            if argv[0] == "ss":
                line = (
                    "ESTAB 0 0 192.168.1.5:44444 203.0.113.77:39852 "
                    f'users:(("openconnect",pid={pid},fd=5))'
                )
                return CommandResult(argv=tuple(argv), returncode=0, stdout=line, stderr="")
            return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")

    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "primary"
    service = UpstreamService(config, runner=AddrRunner())
    _write_pid(service, pid)

    status = service.status()
    process.terminate()

    assert status.connected is True
    assert status.local_ip == "10.66.0.2"
    # Exit-node IP from the process's own socket, not the configured
    # server:port (already shown in the profiles table).
    assert status.remote == "203.0.113.77"
    assert status.connections[0]["connected"] is True
    assert status.connections[0]["interface"] == "oc-middle0"
    assert isinstance(status.connections[0]["connected_since"], str)
    assert isinstance(status.connections[0]["connected_for_seconds"], int)
    assert status.connections[0]["connected_for_seconds"] >= 0
    assert status.connections[1]["connected"] is False
    assert status.connections[1]["local_ip"] is None
    assert status.connections[1]["connected_since"] is None
    assert status.connections[1]["connected_for_seconds"] is None


def test_upstream_lock_serializes_across_service_instances(tmp_path: Path) -> None:
    # Regression test: switch_profile()/connect()/disconnect() etc. used to
    # have no lock at all, so a manual API call could interleave with a
    # concurrent watchdog tick (a separate process, each with its own
    # UpstreamService instance) reading stale state and re-asserting a route
    # to the wrong interface. Two independently constructed instances here
    # stand in for "two processes" -- flock() genuinely treats separately
    # opened file descriptors as unrelated, even from the same PID, so this
    # exercises the real cross-process mechanism, not just a Python-level
    # lock that would only ever help within one process anyway.
    config = _config(tmp_path)
    service_a = UpstreamService(config)
    service_b = UpstreamService(config)

    with service_a._locked():
        lock_path = service_b._lock_path
        service_b.files.ensure_dir(lock_path.parent)
        probe_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(probe_fd)


def test_upstream_lock_is_reentrant_within_one_instance(tmp_path: Path) -> None:
    # Regression test: enforce_profile_enablement()/recover() call
    # self.connect()/self.disconnect()/self.switch_profile() internally --
    # all of which also acquire the same lock. Re-locking the SAME fd must
    # not deadlock (unlike two independently opened fds, see the test
    # above).
    config = _config(tmp_path)
    service = UpstreamService(config)

    with service._locked(), service._locked():
        pass
    assert service._lock_depth == 0


def test_watchdog_respects_connect_on_boot_until_first_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """connect_on_boot=False must not dial on its own the first time the
    watchdog (cli.py::upstream_watch) sees the profile down, but once ANY
    connection has succeeded (however that happened -- an admin connecting
    manually counts), normal health-check-triggered reconnection resumes
    regardless of this flag."""
    from kornode import cli

    config = AppConfig.model_validate(
        _upstream_config(
            tmp_path,
            connect_on_boot=False,
            check_interval=1,
            check_threshold=1,
            active_profile="primary",
            profiles=[
                {
                    "name": "primary",
                    "server": "vpn.example.com",
                    "auth_type": "password",
                    "username": "user",
                }
            ],
        )
    )
    monkeypatch.setattr(cli, "get_config", lambda: config)

    # down, down (still gated by connect_on_boot), up (a manual connect from
    # the panel), down again (must now trigger recover() since a connection
    # has existed since this watchdog process started).
    healthy_sequence = iter([False, False, True, False])
    recover_calls: list[None] = []
    monkeypatch.setattr(
        UpstreamService, "is_healthy", lambda self: next(healthy_sequence)
    )
    monkeypatch.setattr(
        UpstreamService,
        "recover",
        lambda self: recover_calls.append(None) or True,
    )
    monkeypatch.setattr(UpstreamService, "ensure_policy_routing", lambda self: [])
    monkeypatch.setattr(UpstreamService, "enforce_profile_enablement", lambda self: [])

    class _StopLoop(Exception):
        pass

    tick_count = 0

    def _fake_sleep(_seconds: float) -> None:
        nonlocal tick_count
        tick_count += 1
        if tick_count >= 4:
            raise _StopLoop

    monkeypatch.setattr(cli.time, "sleep", _fake_sleep)

    with pytest.raises(_StopLoop):
        cli.upstream_watch(once=False)

    assert len(recover_calls) == 1


def _service(tmp_path: Path) -> UpstreamService:
    return UpstreamService(_config(tmp_path))


def test_openconnect_argv_never_uses_removed_no_cert_check(tmp_path: Path) -> None:
    # openconnect removed --no-cert-check; passing it makes every connect fail.
    profile = _profile().model_copy(update={"trusted_cert": True})

    argv = _service(tmp_path).openconnect_argv(profile, accepted_pin="pin-sha256:AAAA")

    assert "--no-cert-check" not in argv
    assert argv[argv.index("--servercert") + 1] == "pin-sha256:AAAA"


def test_explicit_server_cert_pin_wins_over_accepted_pin(tmp_path: Path) -> None:
    profile = _profile().model_copy(
        update={"trusted_cert": True, "server_cert_pin": "pin-sha256:PINNED"}
    )

    argv = _service(tmp_path).openconnect_argv(profile, accepted_pin="pin-sha256:OTHER")

    assert argv[argv.index("--servercert") + 1] == "pin-sha256:PINNED"
    assert argv.count("--servercert") == 1


def test_trusted_cert_accepts_the_certificate_the_server_presents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kornode.services.cert_pin import CertificatePin

    fetched: list[tuple[str, int]] = []

    def fake_fetch(host: str, port: int) -> CertificatePin:
        fetched.append((host, port))
        return CertificatePin(pin="pin-sha256:FETCHED", sha256="sha256:00")

    monkeypatch.setattr(upstream_module, "fetch_server_pin", fake_fetch)
    profile = _profile().model_copy(update={"trusted_cert": True, "port": "8443"})

    pin = _service(tmp_path)._accepted_server_pin(profile, dry_run=False)

    assert pin == "pin-sha256:FETCHED"
    assert fetched == [("vpn.example.com", 8443)]


def test_accepted_pin_is_not_fetched_without_trusted_cert_or_with_a_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_fetch(host: str, port: int) -> None:
        raise AssertionError("must not touch the network")

    monkeypatch.setattr(upstream_module, "fetch_server_pin", fail_fetch)
    service = _service(tmp_path)

    assert service._accepted_server_pin(_profile(), dry_run=False) is None
    pinned = _profile().model_copy(
        update={"trusted_cert": True, "server_cert_pin": "pin-sha256:X"}
    )
    assert service._accepted_server_pin(pinned, dry_run=False) is None
    trusted = _profile().model_copy(update={"trusted_cert": True})
    assert service._accepted_server_pin(trusted, dry_run=True) is not None


def test_unreachable_server_certificate_is_a_command_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(host: str, port: int) -> None:
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(upstream_module, "fetch_server_pin", refuse)
    profile = _profile().model_copy(update={"trusted_cert": True})

    with pytest.raises(CommandError) as excinfo:
        _service(tmp_path)._accepted_server_pin(profile, dry_run=False)

    assert "connection refused" in excinfo.value.result.stderr


def test_trusted_cert_follows_a_changed_server_key_and_logs_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kornode.services.cert_pin import CertificatePin

    presented = ["pin-sha256:FIRST"]
    monkeypatch.setattr(
        upstream_module,
        "fetch_server_pin",
        lambda host, port: CertificatePin(pin=presented[0], sha256="sha256:00"),
    )
    service = _service(tmp_path)
    profile = _profile().model_copy(update={"trusted_cert": True})

    assert service._accepted_server_pin(profile, dry_run=False) == "pin-sha256:FIRST"
    assert service._accepted_server_pin(profile, dry_run=False) == "pin-sha256:FIRST"
    presented[0] = "pin-sha256:SECOND"
    assert service._accepted_server_pin(profile, dry_run=False) == "pin-sha256:SECOND"

    log = service.log_file.read_text(encoding="utf-8")
    assert log.count("certificate check disabled") == 1
    assert "pin-sha256:FIRST -> pin-sha256:SECOND" in log


def test_certificate_profile_also_sends_username_and_password_when_set(tmp_path: Path) -> None:
    # An upstream ocserv with `auth = "certificate"` and `auth = "plain[...]"`
    # requires both, so after the client certificate it asks for a password.
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="p12",
        cert_file="/etc/kornode/upstream.p12",
        username="yarchik-net",
        password="secret",
    )

    argv = _service(tmp_path).openconnect_argv(profile)

    assert argv[argv.index("--user") + 1] == "yarchik-net"
    assert "--passwd-on-stdin" in argv
    assert argv[argv.index("--certificate") + 1] == "/etc/kornode/upstream.p12"


def test_certificate_profile_without_password_does_not_read_stdin(tmp_path: Path) -> None:
    profile = UpstreamProfileConfig(
        name="primary",
        server="vpn.example.com",
        auth_type="p12",
        cert_file="/etc/kornode/upstream.p12",
    )

    argv = _service(tmp_path).openconnect_argv(profile)

    assert "--passwd-on-stdin" not in argv
    assert "--user" not in argv


# --- kind="external_interface" (pre-existing device, e.g. WireGuard) ------


def test_upstream_profile_kind_defaults_to_openconnect(tmp_path: Path) -> None:
    # Back-compat: a config predating the `kind` field parses unchanged.
    config = AppConfig.model_validate(
        _upstream_config(
            tmp_path,
            profiles=[
                {
                    "name": "finance",
                    "server": "vpn.example.com",
                    "auth_type": "password",
                    "username": "user",
                }
            ],
        )
    )
    assert config.upstream.profiles[0].kind == "openconnect"


def test_external_interface_profile_requires_interface(tmp_path: Path) -> None:
    # kornode can't invent a device name for an interface it doesn't own --
    # unlike an openconnect profile, there's no oc-up<N> fallback here.
    with pytest.raises(ValidationError, match="requires 'interface'"):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[{"name": "wg", "kind": "external_interface"}],
            )
        )


def test_external_interface_profile_does_not_require_server_or_auth(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        _upstream_config(
            tmp_path,
            profiles=[{"name": "wg", "kind": "external_interface", "interface": "wg0"}],
        )
    )
    profile = config.upstream.profiles[0]
    assert profile.server is None
    assert profile.interface == "wg0"


def test_external_interface_profile_forbids_accept_server_routes(tmp_path: Path) -> None:
    # No vpnc-script handshake exists for a plain externally-managed
    # interface, so there's nothing to receive pushed routes/domains from.
    with pytest.raises(ValidationError, match="require kind='openconnect'"):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[
                    {
                        "name": "wg",
                        "kind": "external_interface",
                        "interface": "wg0",
                        "route_host_enabled": True,
                        "accept_server_routes": True,
                    }
                ],
            )
        )


def test_external_interface_profile_forbids_sync_url(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="require kind='openconnect'"):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[
                    {
                        "name": "wg",
                        "kind": "external_interface",
                        "interface": "wg0",
                        "sync_url": "https://10.10.10.1:8443",
                    }
                ],
            )
        )


def test_openconnect_profile_still_requires_server(tmp_path: Path) -> None:
    # Regression guard: gating validate_kind_fields's existing body behind
    # `kind == "openconnect"` must not have loosened it.
    with pytest.raises(ValidationError, match="requires server"):
        AppConfig.model_validate(
            _upstream_config(
                tmp_path,
                profiles=[{"name": "finance", "auth_type": "password", "username": "user"}],
            )
        )


class LinkStateRunner:
    """Fakes `ip -j link show dev <interface>`'s report of an externally-
    managed interface's link state. Everything else (nftables/ip rule/ip
    route calls) succeeds like FakeRunner, and no openconnect process is
    ever spawned -- kornode never dials one for this kind."""

    def __init__(self, link_up: dict[str, bool]) -> None:
        self.link_up = link_up
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        del kwargs
        self.calls.append(list(argv))
        if argv[:3] == ["ip", "-j", "link"]:
            interface = argv[-1]
            up = self.link_up.get(interface, False)
            payload = f'[{{"operstate": "{"UP" if up else "DOWN"}", "flags": []}}]'
            return CommandResult(argv=tuple(argv), returncode=0, stdout=payload, stderr="")
        if tuple(argv[:5]) == ("nft", "list", "chain", "ip", "filter"):
            return CommandResult(
                argv=tuple(argv), returncode=1, stdout="", stderr="No such file or directory"
            )
        return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")


def _external_profile(
    name: str = "wg", interface: str = "wg0", **overrides: object
) -> UpstreamProfileConfig:
    return UpstreamProfileConfig(
        name=name, kind="external_interface", interface=interface, **overrides
    )


def test_external_interface_profile_connected_reflects_link_up(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_external_profile())
    config.upstream.active_profile = "wg"
    service = UpstreamService(config, runner=LinkStateRunner({"wg0": True}))

    assert service.status().connected is True
    assert service.status().connections[0]["connected"] is True


def test_external_interface_profile_not_connected_when_link_down(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_external_profile())
    config.upstream.active_profile = "wg"
    service = UpstreamService(config, runner=LinkStateRunner({"wg0": False}))

    assert service.status().connected is False


def test_connection_age_and_remote_address_are_none_for_external_interface(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_external_profile())
    config.upstream.active_profile = "wg"
    service = UpstreamService(config, runner=LinkStateRunner({"wg0": True}))

    status = service.status()
    assert status.connections[0]["connected_since"] is None
    assert status.connections[0]["connected_for_seconds"] is None
    assert status.remote is None


def test_connect_on_external_interface_applies_routing_without_dialing(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_external_profile())
    config.upstream.active_profile = "wg"
    runner = LinkStateRunner({"wg0": True})
    service = UpstreamService(config, runner=runner)

    result = service.connect_active()

    assert result.returncode == 0
    assert "no connection dialed" in result.stdout
    assert all(call[0] != "openconnect" for call in runner.calls)
    ip_calls = [call for call in runner.calls if call[0] == "ip" and call[1] != "-j"]
    assert ["ip", "route", "replace", "default", "dev", "wg0", "table", "1201"] in ip_calls


def test_connect_on_external_interface_skips_routing_when_link_down(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_external_profile())
    config.upstream.active_profile = "wg"
    runner = LinkStateRunner({"wg0": False})
    service = UpstreamService(config, runner=runner)

    service.connect_active()

    ip_calls = [call for call in runner.calls if call[0] == "ip" and call[1] != "-j"]
    assert not any(call[:3] == ["ip", "route", "replace"] for call in ip_calls)


def test_disconnect_on_external_interface_does_not_signal_any_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    config.upstream.profiles.append(_external_profile())
    config.upstream.active_profile = "wg"
    runner = LinkStateRunner({"wg0": True})
    service = UpstreamService(config, runner=runner)

    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))

    result = service.disconnect()

    assert result.returncode == 0
    assert killed == []
    ip_calls = [call for call in runner.calls if call[0] == "ip" and call[1] != "-j"]
    assert ["ip", "route", "flush", "table", "1201"] in ip_calls


def test_enforce_profile_enablement_reapplies_routing_for_enabled_external_interface(
    tmp_path: Path,
) -> None:
    # Unlike an openconnect standby (skipped once its pid is alive),
    # `connected` for external_interface means link-up, not "routing
    # applied" -- this must keep (idempotently) re-applying every tick
    # regardless of link state, since enforce_profile_enablement() never
    # touches the currently-active profile either way.
    config = _config(tmp_path)
    config.upstream.profiles.append(_profile("primary"))
    config.upstream.profiles.append(_external_profile("wg", interface="wg0"))
    config.upstream.active_profile = "primary"
    runner = LinkStateRunner({"wg0": True})
    service = UpstreamService(config, runner=runner)

    results = service.enforce_profile_enablement()

    assert len(results) == 1
    assert all(call[0] != "openconnect" for call in runner.calls)


def test_enforce_profile_enablement_tears_down_disabled_external_interface(
    tmp_path: Path,
) -> None:
    # A standby (never-active) disabled external_interface profile has no
    # top-level policy route to clean up (same as an openconnect standby,
    # see disconnect()'s "only the active profile's tunnel carries the
    # policy route" comment) -- the point here is that disconnect() is
    # still (idempotently) invoked every tick regardless of link state,
    # unlike an openconnect standby which is only torn down when its pid
    # is observed alive.
    config = _config(tmp_path)
    profile = _external_profile()
    profile.enabled = False
    config.upstream.profiles.append(profile)
    runner = LinkStateRunner({"wg0": True})
    service = UpstreamService(config, runner=runner)

    results = service.enforce_profile_enablement()

    assert len(results) == 1
    assert results[0].stdout == "routing deactivated (interface untouched)"


def test_recover_never_selects_external_interface_as_a_failover_target(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.upstream.failover = True
    config.upstream.profiles.append(_external_profile("wg", interface="wg0"))
    config.upstream.profiles.append(_profile("backup", server="backup.example.com"))
    config.upstream.active_profile = "wg"
    runner = ScriptedConnectRunner(fail_servers=set(), tmp_path=tmp_path)
    service = UpstreamService(config, runner=runner)

    try:
        assert service.recover() is True
    finally:
        runner.close()

    assert service.selected_profile() is not None
    assert service.selected_profile().name == "backup"
