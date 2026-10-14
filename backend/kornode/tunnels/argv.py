from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class DialSpec:
    """Everything openconnect needs to dial one tunnel."""

    server: str
    port: int | str
    interface: str
    pid_file: Path
    script: Path | None = None  # None: the distribution vpnc-script (enroll session only)
    auth_type: Literal["password", "cert", "p12"] = "password"
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    server_cert_pin: str | None = None
    cert_path: Path | None = None
    key_path: Path | None = None
    cert_pass: str | None = field(default=None, repr=False)
    camouflage_secret: str | None = field(default=None, repr=False)
    transport: Literal["tcp", "auto"] = "auto"
    pfs: bool = False


def config_lines(spec: DialSpec) -> list[str]:
    """Secret-bearing lines for the 0600 ``--config`` file.

    Everything secret stays out of argv: /proc/<pid>/cmdline is readable by
    every local user for the tunnel's whole lifetime. The camouflage secret
    is part of the server URL, so it moves into ``server=`` in that file.
    """
    lines: list[str] = []
    if spec.camouflage_secret:
        lines.append(f"server={spec.server}:{spec.port}/?{spec.camouflage_secret}")
    if spec.auth_type in {"cert", "p12"} and spec.cert_path and spec.cert_pass:
        lines.append(f"key-password={spec.cert_pass}")
    return lines


def openconnect_argv(
    spec: DialSpec, *, accepted_pin: str | None = None, config_path: Path | None = None
) -> list[str]:
    """argv for dialing ``spec``; ``config_path`` is the file for config_lines()."""
    argv = [
        "openconnect",
        "--interface",
        spec.interface,
        "--protocol=anyconnect",
        "--non-inter",
        "--background",
        f"--pid-file={spec.pid_file}",
    ]
    if spec.script is not None:
        # Interface-only script: the distribution vpnc-script would apply the
        # server's pushed routes/resolv.conf to this namespace.
        argv.append(f"--script={spec.script}")
    # openconnect dropped --no-cert-check: an untrusted certificate can only
    # be accepted by pinning it.
    pin = spec.server_cert_pin or accepted_pin
    if pin:
        argv.extend(["--servercert", pin])
    if spec.pfs:
        argv.append("--pfs")
    if spec.transport == "tcp":
        argv.append("--no-dtls")
    # Username/password also apply to certificate profiles: an upstream ocserv
    # with several `auth =` lines asks for a password after the certificate.
    if spec.auth_type == "password" or spec.password:
        argv.append("--passwd-on-stdin")
    if spec.username:
        argv.extend(["--user", spec.username])
    if spec.auth_type in {"cert", "p12"} and spec.cert_path:
        argv.extend(["--certificate", str(spec.cert_path)])
        if spec.key_path:
            argv.extend(["--sslkey", str(spec.key_path)])
    if config_path is not None:
        argv.append(f"--config={config_path}")
    if not spec.camouflage_secret:
        argv.append(f"{spec.server}:{spec.port}")
    return argv
