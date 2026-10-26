"""Spike S-08 (docs/redesign/DECISIONS.md, D-101): an AGENT's ocserv accepts other agents
on a virtual host (direct agent<->agent links), next to a refused default host.

Hand-written ocserv.conf like the S-03/S-07 spikes: it pins down the ocserv behaviour the
peer-link renderer will rely on, before any product code exists. Namespace `hub` plays the
LISTENER agent B; peer `agent` (certificate `agent-3`) and peer `rogue` (certificate
`agent-4`) are dialer agents. Questions answered here:

1. Does a cert-only vhost with its own `ipv4-network`, `explicit-ipv4`, `route` and `iroute`
   per peer work, and which address does the listener side of the tun get?
2. Is the default host refusable for everybody while the vhost keeps working (connect script)?
3. Two peers at once on one ocserv: distinct devices and addresses, and how does the
   listener tell them apart (occtl: username + device)?
4. Routed traffic keeps its REAL source address across the link (no NAT).
"""

from __future__ import annotations

import re
import textwrap
from collections.abc import Iterator
from ipaddress import ip_network
from pathlib import Path

import pytest
from tests.netlab.kornode_nodes import _popen_in_namespace, _terminate_process, _wait_until
from tests.netlab.lab import Lab, Namespace
from tests.netlab.ocserv_peers import issue_client_cert
from tests.netlab.test_spike_p3_groups import (
    AGENT_ID,
    HUB_LAN_ADDR,
    GroupsLab,
    _start,
    spike_tmp,  # noqa: F401 - fixture
)
from tests.netlab.test_spike_p4_vhosts import _pin

pytestmark = pytest.mark.netlab

PEER_VHOST = "peer.kornode.test"
PEER_NET = "10.99.128.0/27"  # the listener's peer network: its first host is the tun's local end
SECOND_ID = 4
A_POOL = "10.100.3.0/24"  # what dialer agent-3 exports
A_HOST = "10.100.3.5"
B_LAN = f"{HUB_LAN_ADDR}/24"  # what the listener agent exports (its `lan0`)
SOURCE_PORT = 9100

SOURCE_SERVER = textwrap.dedent(
    """
    import socket, sys
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(8)
    while True:
        conn, peer = s.accept()
        open(sys.argv[3], "a").write(peer[0] + "\\n")
        conn.close()
    """
)

PEER_CONNECT_SCRIPT = textwrap.dedent(
    """\
    #!/bin/sh
    echo "vhost=$VHOST user=$USERNAME group=$GROUPNAME ip=$IP_REMOTE local=$IP_LOCAL" >> {log}
    # The default host serves nobody; the peer vhost only allow-listed agents.
    [ "$VHOST" = "{vhost}" ] || exit 1
    case "$GROUPNAME:$USERNAME" in
      agents:agent-3 | agents:agent-4) exit 0 ;;
    esac
    exit 1
    """
)


def _write_peer_conf(hub: Namespace, tmp: Path) -> None:
    pki = tmp / "pki"
    (pki / "peer.tmpl").write_text(
        f"cn = {PEER_VHOST}\ndns_name = {PEER_VHOST}\ntls_www_server\n"
        "signing_key\nencryption_key\nexpiration_days = 30\n",
        encoding="utf-8",
    )
    hub.run(["certtool", "--generate-privkey", "--outfile", str(pki / "peer.key")])
    hub.run(
        [
            "certtool", "--generate-certificate",
            "--load-privkey", str(pki / "peer.key"),
            "--load-ca-certificate", str(pki / "ca.crt"),
            "--load-ca-privkey", str(pki / "ca.key"),
            "--template", str(pki / "peer.tmpl"),
            "--outfile", str(pki / "peer.crt"),
        ]
    )  # fmt: skip
    info = hub.run(["certtool", "-i", "--infile", str(pki / "peer.crt")]).stdout
    (pki / "peer.pin").write_text(_pin(info), encoding="utf-8")

    users = tmp / "peer-users"
    users.mkdir()
    for agent_id in (AGENT_ID, SECOND_ID):
        # The dialer's address inside the listener's peer network, what it exports (iroute:
        # ocserv routes those prefixes to this session) and what the listener exports to it.
        (users / f"agent-{agent_id}").write_text(
            f"explicit-ipv4 = 10.99.128.{agent_id}\n"
            f"iroute = 10.100.{agent_id}.0/24\n"
            f"route = {ip_network(B_LAN, strict=False)}\n"
            "route = 10.100.2.0/24\n",
            encoding="utf-8",
        )
    empty = tmp / "ocpasswd-empty"
    empty.write_text("", encoding="utf-8")
    script = tmp / "connect.sh"
    script.write_text(
        PEER_CONNECT_SCRIPT.format(log=tmp / "connect.log", vhost=PEER_VHOST), encoding="utf-8"
    )
    script.chmod(0o755)
    (tmp / "ocserv.conf").write_text(
        textwrap.dedent(
            f"""\
            tcp-port = 443
            udp-port = 443
            device = vpns
            run-as-user = nobody
            run-as-group = nogroup
            use-occtl = true
            occtl-socket-file = {tmp}/occtl.sock
            socket-file = {tmp}/ocserv.sock
            log-level = 3
            server-cert = {pki}/server.crt
            server-key = {pki}/server.key
            connect-script = {script}
            ipv4-network = 10.100.2.0/24
            max-clients = 16
            max-same-clients = 2
            keepalive = 30
            dpd = 30
            isolate-workers = false
            predictable-ips = true
            auth-timeout = 30
            cookie-timeout = 300
            auth = "plain[passwd={empty}]"

            [vhost:{PEER_VHOST}]
            udp-port = 443
            server-cert = {pki}/peer.crt
            server-key = {pki}/peer.key
            ca-cert = {pki}/ca.crt
            auth = "certificate"
            cert-user-oid = 2.5.4.3
            cert-group-oid = 2.5.4.11
            config-per-user = {users}/
            ipv4-network = {PEER_NET}
            """
        ),
        encoding="utf-8",
    )


class PeerLab:
    def __init__(self, handle: GroupsLab, second_cert: tuple[Path, Path]) -> None:
        self.handle = handle
        self.listener = handle.hub
        self.dialer = handle.agent  # agent-3
        self.second = handle.rogue  # agent-4
        self.second_cert = second_cert
        self.pin = (handle.tmp / "pki" / "peer.pin").read_text(encoding="utf-8")

    def dial(self, peer: object, cert: tuple[Path, Path], **kwargs: object) -> bool:
        return peer.connect(self.pin, cert=cert, sni=PEER_VHOST, **kwargs)  # type: ignore[attr-defined]

    def listener_device(self, remote: str) -> str:
        """The listener-side tun device of the session whose peer address is `remote`."""
        out = self.listener.run(["ip", "-o", "-4", "addr", "show"], check=False).stdout
        for line in out.splitlines():
            if f"peer {remote}/" in line:
                return line.split()[1]
        raise AssertionError(out)

    def listener_local(self, remote: str) -> str:
        out = self.listener.run(["ip", "-o", "-4", "addr", "show"], check=False).stdout
        for line in out.splitlines():
            if f"peer {remote}/" in line:
                return re.search(r"inet (\S+) peer", line).group(1)  # type: ignore[union-attr]
        raise AssertionError(out)

    def log(self) -> str:
        path = self.handle.tmp / "connect.log"
        return path.read_text(encoding="utf-8") if path.exists() else ""


@pytest.fixture
def peer_lab(lab: Lab, spike_tmp: Path) -> Iterator[PeerLab]:  # noqa: F811
    handle = _start(lab, spike_tmp, guard=False, write_conf=_write_peer_conf)
    second_cert = issue_client_cert(
        handle.hub,
        spike_tmp / "pki" / "ca.crt",
        spike_tmp / "pki" / "ca.key",
        spike_tmp / "pki",
        f"agent-{SECOND_ID}",
        unit="agents",
    )
    try:
        yield PeerLab(handle, second_cert)
    finally:
        handle.stop()


def test_s08_agent_certificate_logs_in_to_the_peer_vhost_with_its_own_network(
    peer_lab: PeerLab,
) -> None:
    assert peer_lab.dial(peer_lab.dialer, peer_lab.handle.agent_cert)
    assert peer_lab.dialer.address() == f"10.99.128.{AGENT_ID}"
    local = peer_lab.listener_local(f"10.99.128.{AGENT_ID}")
    print("listener tun local address:", local, "dialer:", peer_lab.dialer.address())  # noqa: T201
    assert ip_network(PEER_NET).network_address < ip_network(f"{local}/32").network_address
    assert local in {str(h) for h in ip_network(PEER_NET).hosts()}
    pushed = peer_lab.dialer.pushed_routes()
    assert str(ip_network(B_LAN, strict=False)) in pushed and "10.100.2.0/24" in pushed
    assert f"vhost={PEER_VHOST} user=agent-{AGENT_ID} group=agents" in peer_lab.log()


def test_s08_default_host_serves_nobody(peer_lab: PeerLab) -> None:
    handle = peer_lab.handle
    # An agent certificate and a client certificate on the default host: refused.
    assert not handle.rogue.connect(handle.pin, cert=handle.agent_cert)
    assert not handle.rogue.connect(handle.pin, cert=handle.client_cert)
    assert handle.rogue.address() is None
    # The vhost refuses an OU-less client certificate (not an agent) and an unlisted agent.
    assert not handle.rogue.connect(peer_lab.pin, cert=handle.client_cert, sni=PEER_VHOST)


def test_s08_two_peers_get_distinct_devices_and_addresses(peer_lab: PeerLab) -> None:
    assert peer_lab.dial(peer_lab.dialer, peer_lab.handle.agent_cert)
    assert peer_lab.dial(peer_lab.second, peer_lab.second_cert)
    assert peer_lab.dialer.address() == f"10.99.128.{AGENT_ID}"
    assert peer_lab.second.address() == f"10.99.128.{SECOND_ID}"
    devices = {
        peer_lab.listener_device(f"10.99.128.{AGENT_ID}"),
        peer_lab.listener_device(f"10.99.128.{SECOND_ID}"),
    }
    assert len(devices) == 2
    # What the reconciler would read to map users to devices.
    users = peer_lab.listener.run(
        ["occtl", "-s", str(peer_lab.handle.tmp / "occtl.sock"), "-j", "show", "users"],
        check=False,
    ).stdout
    print(users)  # noqa: T201 - spike evidence
    assert "agent-3" in users and "agent-4" in users and all(d in users for d in devices)


def test_s08_routed_traffic_keeps_the_real_source_address(peer_lab: PeerLab) -> None:
    handle = peer_lab.handle
    assert peer_lab.dial(peer_lab.dialer, handle.agent_cert)
    listener, dialer = peer_lab.listener, peer_lab.dialer.ns
    # What the reconciler installs in the product (ocserv installs no iroute routes, S-03).
    device = peer_lab.listener_device(f"10.99.128.{AGENT_ID}")
    listener.run(["ip", "route", "add", A_POOL, "dev", device])
    listener.run(["sysctl", "-qw", "net.ipv4.conf.all.rp_filter=2"])
    dialer.run(["ip", "addr", "add", f"{A_HOST}/32", "dev", "lo"])
    # The pushed `route = <B's LAN>` is installed by the dialer's vpnc script already.
    assert (
        str(ip_network(B_LAN, strict=False))
        in dialer.run(["ip", "route", "show", "dev", peer_lab.dialer.iface]).stdout
    )
    seen = handle.tmp / "source.log"
    server = _popen_in_namespace(
        listener,
        ["python3", "-c", SOURCE_SERVER, HUB_LAN_ADDR, str(SOURCE_PORT), str(seen)],
        handle.tmp / "source-server.log",
    )
    handle.processes.append(server)
    try:
        _wait_until(lambda: server.poll() is None, "source server")
        code = (
            "import socket\n"
            f"s = socket.socket(); s.bind(('{A_HOST}', 0)); s.settimeout(5)\n"
            f"s.connect(('{HUB_LAN_ADDR}', {SOURCE_PORT})); s.close()\n"
        )
        dialer.run(["python3", "-c", code], timeout=15)
        _wait_until(lambda: seen.exists() and A_HOST in seen.read_text(), "source address seen")
    finally:
        _terminate_process(server)
    assert seen.read_text().split() == [
        A_HOST
    ]  # the dialer's own prefix address, not a tun/NAT one
