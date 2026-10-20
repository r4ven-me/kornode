from __future__ import annotations

from pathlib import Path

from kornode.tunnels.argv import DialSpec, config_lines, openconnect_argv
from kornode.tunnels.carrier import resolve_carrier_addresses


def _spec(**kw: object) -> DialSpec:
    base: dict[str, object] = {
        "server": "hub.example",
        "port": 443,
        "interface": "oc-hub0",
        "pid_file": Path("/run/oc.pid"),
        "script": Path("/x/vpnc"),
    }
    base.update(kw)
    return DialSpec(**base)  # type: ignore[arg-type]


def test_fabric_argv_pins_forces_tcp_and_keeps_secrets_out() -> None:
    spec = _spec(
        auth_type="cert",
        cert_path=Path("/t/cert.pem"),
        key_path=Path("/t/key.pem"),
        server_cert_pin="pin-sha256:AAA",
        transport="tcp",
        pfs=True,
        camouflage_secret="s3cret",
        cert_pass="kp",
    )
    argv = openconnect_argv(spec, config_path=Path("/t/oc.conf"))
    assert "--no-dtls" in argv and "--pfs" in argv
    assert argv[argv.index("--servercert") + 1] == "pin-sha256:AAA"
    assert "--passwd-on-stdin" not in argv
    assert argv[-1] == "--config=/t/oc.conf"  # camouflage: no positional server
    assert "s3cret" not in " ".join(argv) and "kp" not in argv
    assert config_lines(spec) == ["server=hub.example:443/?s3cret", "key-password=kp"]


def test_password_profile_takes_stdin_and_positional_server() -> None:
    argv = openconnect_argv(_spec(username="u", password="p"), accepted_pin="pin-sha256:B")
    assert "--passwd-on-stdin" in argv and argv[argv.index("--user") + 1] == "u"
    assert argv[argv.index("--servercert") + 1] == "pin-sha256:B"
    assert argv[-1] == "hub.example:443"


def test_carrier_literal_and_empty() -> None:
    assert resolve_carrier_addresses("203.0.113.5") == ["203.0.113.5"]
    assert resolve_carrier_addresses(None) == []
