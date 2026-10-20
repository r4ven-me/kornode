"""Raw openconnect peers and test PKI for ocserv scenarios in netlab.

Unlike kornode_nodes.connect_node_upstream these peers bypass kornode on the
client side: they log in with a password or a certificate, record what ocserv
pushed and can add routes the hub never pushed (to probe restrictions).
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from tests.netlab.kornode_nodes import _kill_openconnect, _wait_until
from tests.netlab.lab import Namespace

LISTENER = textwrap.dedent(
    """
    import selectors, socket, sys
    sel = selectors.DefaultSelector()
    for item in sys.argv[1:]:
        host, port = item.rsplit(":", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        s.listen(16)
        sel.register(s, selectors.EVENT_READ)
    while True:
        for key, _ in sel.select():
            conn, _ = key.fileobj.accept()
            conn.close()
    """
)

# Minimal vpnc-script: address, pushed routes (default when none), and
# KN_EXTRA_ROUTES to emulate a client that adds routes the hub never pushed.
VPNC_SCRIPT = textwrap.dedent(
    """\
    #!/bin/sh
    env | sort > "$KN_ENV_DUMP.$reason"
    [ "$reason" = connect ] || exit 0
    ip link set dev "$TUNDEV" up mtu "${INTERNAL_IP4_MTU:-1400}"
    ip addr add "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV"
    n="${CISCO_SPLIT_INC:-0}"
    [ "$n" -eq 0 ] && ip route add default dev "$TUNDEV"
    i=0
    while [ "$i" -lt "$n" ]; do
        eval a="\\$CISCO_SPLIT_INC_${i}_ADDR"
        eval m="\\$CISCO_SPLIT_INC_${i}_MASKLEN"
        ip route add "$a/$m" dev "$TUNDEV"
        i=$((i + 1))
    done
    for r in $KN_EXTRA_ROUTES; do ip route add "$r" dev "$TUNDEV"; done
    exit 0
    """
)


@dataclass(repr=False)
class Peer:
    ns: Namespace
    hub_addr: str
    iface: str
    tmp: Path
    pid_file: Path = field(init=False)

    def __post_init__(self) -> None:
        self.pid_file = self.tmp / f"{self.iface}.pid"

    def connect(
        self,
        pin: str,
        *,
        user: str | None = None,
        password: str | None = None,
        cert: tuple[Path, Path] | None = None,
        extra_routes: tuple[str, ...] = (),
    ) -> bool:
        script = self.tmp / "vpnc-script"
        if not script.exists():
            script.write_text(VPNC_SCRIPT, encoding="utf-8")
            script.chmod(0o755)
        argv = [
            "openconnect",
            "--interface",
            self.iface,
            "--background",
            f"--pid-file={self.pid_file}",
            f"--script={script}",
            "--servercert",
            pin,
            "--non-inter",
        ]
        if user is not None:
            argv.extend(["--user", user, "--passwd-on-stdin"])
        if cert is not None:
            argv.extend(["--certificate", str(cert[0]), "--sslkey", str(cert[1])])
        argv.append(f"https://{self.hub_addr}:443")
        env = {
            **os.environ,
            "KN_ENV_DUMP": str(self.tmp / f"{self.iface}.env"),
            "KN_EXTRA_ROUTES": " ".join(extra_routes),
        }
        # Output to a file, not a pipe: the backgrounded child inherits stdout,
        # and a pipe would keep the call open until the timeout.
        with (self.tmp / f"{self.iface}.openconnect.log").open("ab") as log:
            completed = subprocess.run(  # noqa: S603 - explicit argv, no shell
                ["ip", "netns", "exec", self.ns.full_name, *argv],
                input=f"{password}\n".encode() if password is not None else b"",
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
                timeout=30,
                check=False,
            )
        if completed.returncode != 0:
            return False
        try:
            _wait_until(lambda: self.address() is not None, f"{self.iface} address", timeout=10)
        except TimeoutError:
            return False
        return True

    def address(self) -> str | None:
        result = self.ns.run(["ip", "-4", "-o", "addr", "show", "dev", self.iface], check=False)
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
        return match.group(1) if match else None

    def pushed_routes(self) -> list[str]:
        env = read_env(self.tmp / f"{self.iface}.env.connect")
        count = int(env.get("CISCO_SPLIT_INC", "0"))
        return [
            f"{env[f'CISCO_SPLIT_INC_{i}_ADDR']}/{env[f'CISCO_SPLIT_INC_{i}_MASKLEN']}"
            for i in range(count)
        ]

    def stop(self) -> None:
        _kill_openconnect(self.pid_file)


def issue_client_cert(
    ns: Namespace, ca_crt: Path, ca_key: Path, out_dir: Path, cn: str, *, unit: str | None
) -> tuple[Path, Path]:
    """Client certificate signed by the given CA; `unit` becomes the OU (ocserv group)."""
    key, crt, tmpl = out_dir / f"{cn}.key", out_dir / f"{cn}.crt", out_dir / f"{cn}.tmpl"
    lines = [f"cn = {cn}", "tls_www_client", "signing_key", "expiration_days = 30"]
    if unit is not None:
        lines.insert(1, f"unit = {unit}")
    tmpl.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ns.run(["certtool", "--generate-privkey", "--outfile", str(key)])
    ns.run(
        [
            "certtool", "--generate-certificate",
            "--load-privkey", str(key),
            "--load-ca-certificate", str(ca_crt),
            "--load-ca-privkey", str(ca_key),
            "--template", str(tmpl),
            "--outfile", str(crt),
        ]
    )  # fmt: skip
    return crt, key


def read_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            env[key] = value
    return env
