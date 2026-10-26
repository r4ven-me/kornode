"""Spike S-08 (docs/redesign/DECISIONS.md): direct agent<->agent links over a vhost.

Agent B runs ocserv with a `peer.kornode.test` vhost next to its default host; agent A
dials it with its agent certificate and SNI while it also keeps a tunnel to a hub ocserv.
No kornode renderer is involved: the tests pin down ocserv/openconnect/kernel behaviour
that the peer-link design (agents' `oc-p<id>` tunnels, exit-table metric routes, reconciler
installed return routes) relies on.

    hub ---- 192.0.2.4/30 ---- a        a: lan0 10.50.1.1/24   oc-hub0 + oc-pb
     |                         |        b: lan0 10.60.1.1/24   ocserv (default host + peer vhost)
    192.0.2.8/30         192.0.2.0/30
     |                         |
     +------------ b ----------+
"""

from __future__ import annotations

import textwrap
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from tests.netlab.helpers import tcp_check
from tests.netlab.kornode_nodes import _popen_in_namespace, _terminate_process, _wait_until
from tests.netlab.lab import Lab, Namespace
from tests.netlab.ocserv_peers import Peer, issue_client_cert
from tests.netlab.test_spike_p3_groups import _make_pki, spike_tmp  # noqa: F401 - fixture
from tests.netlab.test_spike_p4_vhosts import _pin

pytestmark = pytest.mark.netlab

PEER_HOST = "peer.kornode.test"
PEER_NET = "10.99.128.0/27"
A_LAN, B_LAN = "10.50.1.0/24", "10.60.1.0/24"
A_LAN_ADDR, B_LAN_ADDR = "10.50.1.1", "10.60.1.1"
A_PEER_ADDR = "10.99.128.2"
HUB_NET = "10.99.0.0/24"
PORT = 7000

CONNECT_SCRIPT = textwrap.dedent(
    """\
    #!/bin/sh
    echo "vhost=$VHOST user=$USERNAME group=$GROUPNAME ip=$IP_REMOTE local=$IP_LOCAL dev=$DEVICE" >> {log}
    case "$VHOST" in
        {peer_host}) [ -e {users}/"$USERNAME" ] || {{ echo REJECT >> {log}; exit 1; }} ;;
        *) case "$USERNAME" in agent-*) echo REJECT >> {log}; exit 1 ;; esac ;;
    esac
    exit 0
    """
)

RECORDER = textwrap.dedent(
    """
    import socket, sys
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[1], int(sys.argv[2])))
    s.listen(8)
    while True:
        conn, addr = s.accept()
        with open(sys.argv[3], "a") as out:
            out.write(addr[0] + "\\n")
        conn.close()
    """
)


@dataclass(repr=False)
class PeerLab:
    a: Namespace
    b: Namespace
    hub: Namespace
    tmp: Path
    b_pin: str
    hub_pin: str
    a_cert: tuple[Path, Path]
    stranger_cert: tuple[Path, Path]
    to_b: Peer  # A's peer tunnel, oc-pb
    to_hub: Peer  # A's hub tunnel, oc-hub0
    processes: list

    @property
    def log(self) -> str:
        path = self.tmp / "connect.log"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    @property
    def seen(self) -> list[str]:
        path = self.tmp / "seen.log"
        return path.read_text(encoding="utf-8").split() if path.exists() else []

    def connect_peer(self, **kwargs: object) -> bool:
        return self.to_b.connect(self.b_pin, cert=self.a_cert, sni=PEER_HOST, **kwargs)  # type: ignore[arg-type]

    def connect_hub(self) -> bool:
        return self.to_hub.connect(self.hub_pin, cert=self.a_cert)

    def route_dev(self, dst: str, *, src: str = A_LAN_ADDR) -> str:
        out = self.a.run(["ip", "-o", "route", "get", dst, "from", src], check=False).stdout
        parts = out.split()
        return parts[parts.index("dev") + 1] if "dev" in parts else "unreachable"

    def connect_from_lan(self) -> bool:
        code = (
            "import socket\n"
            "s = socket.socket(); s.settimeout(3)\n"
            f"s.bind(({A_LAN_ADDR!r}, 0)); s.connect(({B_LAN_ADDR!r}, {PORT}))\n"
        )
        return self.a.run(["python3", "-c", code], check=False).returncode == 0

    def stop(self) -> None:
        self.to_b.stop()
        self.to_hub.stop()
        for process in self.processes:
            _terminate_process(process)


def _cert(ns: Namespace, pki: Path, cn: str, tmpl: str) -> None:
    (pki / f"{cn}.tmpl").write_text(tmpl, encoding="utf-8")
    ns.run(["certtool", "--generate-privkey", "--outfile", str(pki / f"{cn}.key")])
    ns.run(
        [
            "certtool", "--generate-certificate",
            "--load-privkey", str(pki / f"{cn}.key"),
            "--load-ca-certificate", str(pki / "ca.crt"),
            "--load-ca-privkey", str(pki / "ca.key"),
            "--template", str(pki / f"{cn}.tmpl"),
            "--outfile", str(pki / f"{cn}.crt"),
        ]
    )  # fmt: skip


def _ocserv_conf(tmp: Path, name: str, body: str) -> Path:
    path = tmp / f"{name}.conf"
    path.write_text(
        textwrap.dedent(
            f"""\
            tcp-port = 443
            udp-port = 443
            device = vpns
            run-as-user = nobody
            run-as-group = nogroup
            use-occtl = true
            occtl-socket-file = {tmp}/{name}.occtl.sock
            socket-file = {tmp}/{name}.sock
            log-level = 3
            max-clients = 16
            max-same-clients = 2
            keepalive = 30
            dpd = 30
            isolate-workers = false
            predictable-ips = true
            auth-timeout = 30
            cookie-timeout = 300
            cert-user-oid = 2.5.4.3
            cert-group-oid = 2.5.4.11
            """
        )
        + textwrap.dedent(body),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def peer_lab(lab: Lab, spike_tmp: Path) -> Iterator[PeerLab]:  # noqa: F811
    tmp = spike_tmp
    a, b, hub = (lab.add_namespace(n) for n in ("a", "b", "hub"))
    lab.add_veth(a, b, addr_a="192.0.2.2/30", addr_b="192.0.2.1/30")
    lab.add_veth(a, hub, addr_a="192.0.2.6/30", addr_b="192.0.2.5/30")
    lab.add_veth(b, hub, addr_a="192.0.2.10/30", addr_b="192.0.2.9/30")
    for ns, lan in ((a, f"{A_LAN_ADDR}/24"), (b, f"{B_LAN_ADDR}/24")):
        ns.run(["ip", "link", "add", "lan0", "type", "dummy"])
        ns.run(["ip", "addr", "add", lan, "dev", "lan0"])
        ns.run(["ip", "link", "set", "lan0", "up"])
    hub.run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    # Strict reverse-path filtering on B: the plan relies on it staying valid for peers.
    for key in ("all", "default"):
        b.run(["sysctl", "-qw", f"net.ipv4.conf.{key}.rp_filter=1"])
    hub.run(["ip", "route", "add", B_LAN, "via", "192.0.2.10"])
    # B's return path to A's LAN through the hub (the "fallback" route, higher metric).
    b.run(["ip", "route", "add", A_LAN, "via", "192.0.2.9", "metric", "100"])

    pki = tmp / "pki"
    b_pin = _make_pki(b, tmp)  # default host certificate (server.crt) and CA
    _cert(
        b, pki, "peer",
        f"cn = {PEER_HOST}\ndns_name = {PEER_HOST}\ntls_www_server\nsigning_key\n"
        "encryption_key\nexpiration_days = 30\n",
    )  # fmt: skip
    peer_pin = _pin(b.run(["certtool", "-i", "--infile", str(pki / "peer.crt")]).stdout)
    a_cert = issue_client_cert(b, pki / "ca.crt", pki / "ca.key", pki, "agent-1", unit="agents")
    stranger = issue_client_cert(b, pki / "ca.crt", pki / "ca.key", pki, "agent-9", unit="agents")

    users, groups, hub_users = tmp / "users", tmp / "groups", tmp / "hub-users"
    for path in (users, groups, hub_users):
        path.mkdir()
    # Only agent-1 is on B's allow-list (a per-user file); agent-9 has none.
    (users / "agent-1").write_text(f"explicit-ipv4 = {A_PEER_ADDR}\niroute = {A_LAN}\n")
    (groups / "agents").write_text(f"ipv4-network = {PEER_NET}\nroute = {PEER_NET}\n")
    (hub_users / "agent-1").write_text("explicit-ipv4 = 10.99.0.2\n")
    (tmp / "hub-groups").mkdir()
    (tmp / "hub-groups" / "agents").write_text(f"ipv4-network = {HUB_NET}\nroute = {HUB_NET}\n")
    script = tmp / "connect.sh"
    script.write_text(
        CONNECT_SCRIPT.format(log=tmp / "connect.log", peer_host=PEER_HOST, users=users),
        encoding="utf-8",
    )
    script.chmod(0o755)
    (tmp / "passwd").write_text("", encoding="utf-8")

    b_conf = _ocserv_conf(
        tmp,
        "b",
        f"""\
        server-cert = {pki}/server.crt
        server-key = {pki}/server.key
        connect-script = {script}
        ipv4-network = 10.100.1.0/24
        auth = "plain[passwd={tmp}/passwd]"

        [vhost:{PEER_HOST}]
        server-cert = {pki}/peer.crt
        server-key = {pki}/peer.key
        ca-cert = {pki}/ca.crt
        auth = "certificate"
        config-per-group = {groups}/
        config-per-user = {users}/
        ipv4-network = {PEER_NET}
        """,
    )
    hub_conf = _ocserv_conf(
        tmp,
        "hub",
        f"""\
        server-cert = {pki}/server.crt
        server-key = {pki}/server.key
        ca-cert = {pki}/ca.crt
        auth = "certificate"
        config-per-group = {tmp}/hub-groups/
        config-per-user = {hub_users}/
        ipv4-network = {HUB_NET}
        """,
    )
    (tmp / "recorder.py").write_text(RECORDER, encoding="utf-8")
    processes = [
        _popen_in_namespace(
            b, ["python3", str(tmp / "recorder.py"), B_LAN_ADDR, str(PORT), str(tmp / "seen.log")],
            tmp / "recorder.log",
        ),
        _popen_in_namespace(b, ["ocserv", "-f", "--log-stderr", "-c", str(b_conf)], tmp / "b.log"),
        _popen_in_namespace(
            hub, ["ocserv", "-f", "--log-stderr", "-c", str(hub_conf)], tmp / "hub.log"
        ),
    ]
    handle = PeerLab(
        a=a, b=b, hub=hub, tmp=tmp, b_pin=peer_pin, hub_pin=b_pin, a_cert=a_cert,
        stranger_cert=stranger,
        to_b=Peer(ns=a, hub_addr="192.0.2.1", iface="oc-pb", tmp=tmp),
        to_hub=Peer(ns=a, hub_addr="192.0.2.5", iface="oc-hub0", tmp=tmp),
        processes=processes,
    )  # fmt: skip
    try:
        _wait_until(
            lambda: tcp_check(a, "192.0.2.1", 443) and tcp_check(a, "192.0.2.5", 443),
            "both ocserv on 443",
        )
    except BaseException:
        handle.stop()
        raise
    lab.log_dirs.append(tmp)
    try:
        yield handle
    finally:
        handle.stop()


def _install_routes(lab: PeerLab) -> None:
    """What the reconcilers will do: B/hub session routes (S-03) and A's metric routes."""
    for ns, dst, via in ((lab.b, A_LAN, A_PEER_ADDR), (lab.hub, A_LAN, "10.99.0.2")):
        dev = ns.run(["ip", "-o", "route", "get", via]).stdout.split()
        ns.run(["ip", "route", "replace", dst, "dev", dev[dev.index("dev") + 1],
                "metric", "10", "proto", "77"])  # fmt: skip
    lab.a.run(["ip", "route", "replace", B_LAN, "dev", "oc-pb", "metric", "10"])
    lab.a.run(["ip", "route", "replace", B_LAN, "dev", "oc-hub0", "metric", "100"])


def test_s08_dial_with_agent_certificate_and_sni(peer_lab: PeerLab) -> None:
    assert peer_lab.connect_peer()
    print(peer_lab.log)  # noqa: T201 - spike evidence
    # explicit-ipv4 inside the vhost's own network; B's local address is its first host?
    assert peer_lab.to_b.address() == A_PEER_ADDR
    assert f"vhost={PEER_HOST} user=agent-1 group=agents ip={A_PEER_ADDR} local=10.99.128.1" in (
        peer_lab.log
    )
    assert peer_lab.to_b.pushed_routes() == [PEER_NET]


def test_s08_peer_guard_refuses_a_certificate_outside_the_allow_list(peer_lab: PeerLab) -> None:
    other = Peer(ns=peer_lab.a, hub_addr="192.0.2.1", iface="oc-px", tmp=peer_lab.tmp)
    assert not other.connect(peer_lab.b_pin, cert=peer_lab.stranger_cert, sni=PEER_HOST)
    assert "user=agent-9" in peer_lab.log and "REJECT" in peer_lab.log


def test_s08_agent_certificate_is_refused_on_the_default_host(peer_lab: PeerLab) -> None:
    other = Peer(ns=peer_lab.a, hub_addr="192.0.2.1", iface="oc-px", tmp=peer_lab.tmp)
    assert not other.connect(peer_lab.hub_pin, cert=peer_lab.a_cert)


def test_s08_hub_tunnel_and_peer_tunnel_coexist(peer_lab: PeerLab) -> None:
    assert peer_lab.connect_hub()
    assert peer_lab.connect_peer()
    assert peer_lab.to_hub.address() == "10.99.0.2"
    assert peer_lab.to_b.address() == A_PEER_ADDR


def test_s08_real_source_address_and_metric_fallback(peer_lab: PeerLab) -> None:
    assert peer_lab.connect_hub()
    assert peer_lab.connect_peer()
    _install_routes(peer_lab)
    # Direct path preferred; A's real LAN address reaches B's listener (no NAT, strict RPF).
    assert peer_lab.route_dev(B_LAN_ADDR) == "oc-pb"
    assert peer_lab.connect_from_lan()
    assert peer_lab.seen == [A_LAN_ADDR]

    # Direct tunnel dies: its route disappears with the device, the hub route takes over.
    peer_lab.to_b.stop()
    _wait_until(lambda: peer_lab.route_dev(B_LAN_ADDR) == "oc-hub0", "route fell back to hub")
    _wait_until(
        lambda: "dev vpns" not in peer_lab.b.run(["ip", "route", "show", A_LAN]).stdout,
        "B dropped the session route",
    )
    assert peer_lab.connect_from_lan()
    assert peer_lab.seen == [A_LAN_ADDR, A_LAN_ADDR]

    # Both gone: nothing but the explicit unreachable default would remain.
    peer_lab.to_hub.stop()
    _wait_until(lambda: peer_lab.route_dev(B_LAN_ADDR) == "unreachable", "no route left")


def test_s08_peer_tunnel_redial_restores_the_direct_path(peer_lab: PeerLab) -> None:
    assert peer_lab.connect_peer()
    peer_lab.to_b.stop()
    assert peer_lab.connect_peer()
    assert peer_lab.to_b.address() == A_PEER_ADDR


def test_s08_dtls_on_the_peer_vhost(peer_lab: PeerLab) -> None:
    assert peer_lab.connect_peer()
    log = peer_lab.tmp / "oc-pb.openconnect.log"
    _wait_until(
        lambda: "Established DTLS connection" in log.read_text(errors="replace"),
        "DTLS on the peer vhost",
        timeout=10,
    )
