"""Decide whether an ocserv.conf change can be applied with SIGHUP.

ocserv re-reads most of its configuration on SIGHUP, but not everything:
the authentication methods (``auth =``), the listening sockets and the
tun device are fixed when the main process starts. Changing them and only
sending SIGHUP leaves the running server enforcing the *old* settings, e.g.
still asking for a password after password auth was switched off. Those
changes need a full restart, which disconnects the active VPN sessions.
"""

from __future__ import annotations

# Directives the running ocserv does not pick up on SIGHUP.
RESTART_ONLY_DIRECTIVES = frozenset(
    {
        "auth",
        "enable-auth",
        "acct",
        "cert-user-oid",
        "cert-group-oid",
        "tcp-port",
        "udp-port",
        "listen-host",
        "udp-listen-host",
        "listen-proxy-proto",
        "device",
        "run-as-user",
        "run-as-group",
        "socket-file",
        "occtl-socket-file",
        "use-occtl",
        "isolate-workers",
        "pid-file",
    }
)


def restart_only_settings(ocserv_conf: str) -> list[tuple[str, str]]:
    """The restart-only ``key = value`` pairs of an ocserv.conf, in file order."""
    settings: list[tuple[str, str]] = []
    for raw_line in ocserv_conf.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in RESTART_ONLY_DIRECTIVES:
            settings.append((key, value.strip()))
    return settings


def restart_required(previous: str, current: str) -> bool:
    return restart_only_settings(previous) != restart_only_settings(current)
