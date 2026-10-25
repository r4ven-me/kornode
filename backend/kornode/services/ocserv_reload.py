"""Decide whether an ocserv.conf change can be applied with SIGHUP.

ocserv re-reads most of its configuration on SIGHUP, but not everything:
the authentication methods (``auth =``), the listening sockets and the
tun device are fixed when the main process starts. Changing them and only
sending SIGHUP leaves the running server enforcing the *old* settings, e.g.
still asking for a password after password auth was switched off. Those
changes need a full restart, which disconnects the active VPN sessions.

Certificate files are snapshotted by *path* when ocserv starts. SIGHUP re-reads
new content at the same path (renewal), but a reload that points at a new path
fails with ``cannot find snapshot for file`` (ocserv 1.5). Switching from the
self-signed certificate to an external or Let's Encrypt one, or adding,
removing or renaming a ``[vhost:...]`` section, therefore needs a restart too.
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
        "server-cert",
        "server-key",
        "ca-cert",
        "crl",
        "dh-params",
        "ocsp-response",
    }
)


def restart_only_settings(ocserv_conf: str) -> list[tuple[str, str]]:
    """The restart-only ``key = value`` pairs of an ocserv.conf, in file order.

    Section headers such as ``[vhost:name]`` are included as ``("[section]",
    name)``, so a vhost's own certificate paths are compared per section.
    """
    settings: list[tuple[str, str]] = []
    for raw_line in ocserv_conf.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            settings.append(("[section]", line[1:-1].strip()))
            continue
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in RESTART_ONLY_DIRECTIVES:
            settings.append((key, value.strip()))
    return settings


def restart_required(previous: str, current: str) -> bool:
    return restart_only_settings(previous) != restart_only_settings(current)
