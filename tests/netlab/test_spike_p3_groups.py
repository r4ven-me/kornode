"""Spikes S-01, S-02 and S-04 (docs/redesign/DECISIONS.md) on a hand-written ocserv.

One ocserv, three groups: `clients` (password), `agents` (certificate, group from
the certificate OU), `enroll` (password, restricted to the control API port).
No kornode renderer is involved: these tests pin down the ocserv behaviour that
P3-02 renders from the registry.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import textwrap
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest
from tests.netlab.helpers import tcp_check
from tests.netlab.kornode_nodes import (
    _popen_in_namespace,
    _terminate_process,
    _wait_until,
)
from tests.netlab.lab import Lab, Namespace
from tests.netlab.ocserv_peers import LISTENER, Peer, issue_client_cert

pytestmark = pytest.mark.netlab

HUB_INTERLINK_ADDR = "10.99.0.1"
HUB_LAN_ADDR = "172.30.1.1"
INET_ADDR = "198.51.100.2"
CONTROL_PORT = 8444
CLIENT_POOL = "10.100.1.0/24"
INTERLINK_CIDR = "10.99.0.0/24"
ENROLL_POOL = "10.99.255.240/28"
AGENT_ID = 3
CLIENT_USER = "alice"
CLIENT_PASSWORD = "alice-password"
ENROLL_USER = "enroll-3-k2f9"
ENROLL_PASSWORD = "enroll-secret"

# The guard under test for S-01: with `enable-auth = certificate` any
# certificate of the hub CA logs in without a password; a certificate without
# OU yields an empty group, which is refused here.
CONNECT_SCRIPT = textwrap.dedent(
    """\
    #!/bin/sh
    echo "user=$USERNAME group=$GROUPNAME ip=$IP_REMOTE local=$IP_LOCAL dev=$DEVICE" >> {log}
    {guard}
    exit 0
    """
)
GUARD = 'case "$GROUPNAME" in clients|agents|enroll) ;; *) echo REJECT >> {log}; exit 1;; esac'


# S-04 fallback: enroll leases come from a dedicated pool, so one static rule
# set (no per-session state) limits them to the control API on the hub.
ENROLL_NFT = textwrap.dedent(
    f"""\
    table inet spike_enroll {{
        chain input {{
            type filter hook input priority filter; policy accept;
            ip saddr {ENROLL_POOL} ip daddr {HUB_INTERLINK_ADDR} tcp dport {CONTROL_PORT} accept
            ip saddr {ENROLL_POOL} drop
        }}
        chain forward {{
            type filter hook forward priority filter; policy accept;
            ip saddr {ENROLL_POOL} drop
            ip daddr {ENROLL_POOL} drop
        }}
    }}
    """
)


@dataclass(repr=False)
class GroupsLab:
    hub: Namespace
    tmp: Path
    pin: str
    client: Peer
    agent: Peer
    enroll: Peer
    rogue: Peer
    agent_cert: tuple[Path, Path]
    client_cert: tuple[Path, Path]
    connect_log: Path
    processes: list[subprocess.Popen[bytes]]

    def show_users(self) -> str:
        result = self.hub.run(
            ["occtl", "-s", str(self.tmp / "occtl.sock"), "show", "users"], check=False
        )
        return result.stdout

    def stop(self) -> None:
        for peer in (self.client, self.agent, self.enroll, self.rogue):
            peer.stop()
        for process in self.processes:
            _terminate_process(process)


@pytest.fixture
def spike_tmp() -> Iterator[Path]:
    # World-readable like test_p0_upstream.node_tmp: ocserv workers drop privileges.
    path = Path(tempfile.mkdtemp(prefix="kornode-spike-"))
    path.chmod(0o755)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _start(
    lab: Lab,
    tmp: Path,
    *,
    guard: bool,
    revoke_client_cert: bool = False,
    write_conf: Callable[[Namespace, Path], None] | None = None,
) -> GroupsLab:
    """`write_conf(hub, tmp)` replaces the default ocserv.conf before ocserv starts (S-07)."""
    hub = lab.add_namespace("hub")
    inet = lab.add_namespace("inet")
    hub.run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    lab.add_veth(hub, inet, addr_a="198.51.100.1/24", addr_b=f"{INET_ADDR}/24")
    inet.run(["ip", "route", "add", "10.0.0.0/8", "via", "198.51.100.1"])
    for name, cidr in (("fab0", f"{HUB_INTERLINK_ADDR}/32"), ("lan0", f"{HUB_LAN_ADDR}/24")):
        hub.run(["ip", "link", "add", name, "type", "dummy"])
        hub.run(["ip", "addr", "add", cidr, "dev", name])
        hub.run(["ip", "link", "set", name, "up"])

    peers: dict[str, Peer] = {}
    for index, name in enumerate(("client", "agent", "enroll", "rogue")):
        ns = lab.add_namespace(name)
        base = 4 * index
        lab.add_veth(hub, ns, addr_a=f"192.0.2.{base + 1}/30", addr_b=f"192.0.2.{base + 2}/30")
        peers[name] = Peer(ns=ns, hub_addr=f"192.0.2.{base + 1}", iface=f"oc-{name}", tmp=tmp)

    pin = _make_pki(hub, tmp)
    agent_cert = issue_client_cert(
        hub,
        tmp / "pki" / "ca.crt",
        tmp / "pki" / "ca.key",
        tmp / "pki",
        f"agent-{AGENT_ID}",
        unit="agents",
    )
    client_cert = issue_client_cert(
        hub, tmp / "pki" / "ca.crt", tmp / "pki" / "ca.key", tmp / "pki", CLIENT_USER, unit=None
    )
    _write_ocserv_files(hub, tmp, guard=guard)
    if write_conf is not None:
        write_conf(hub, tmp)
    if revoke_client_cert:
        _revoke(hub, tmp, client_cert[0])
    (tmp / "enroll.nft").write_text(ENROLL_NFT, encoding="utf-8")
    hub.run(["nft", "-f", str(tmp / "enroll.nft")])

    processes: list[subprocess.Popen[bytes]] = []
    groups_lab = GroupsLab(
        hub=hub,
        tmp=tmp,
        pin=pin,
        client=peers["client"],
        agent=peers["agent"],
        enroll=peers["enroll"],
        rogue=peers["rogue"],
        agent_cert=agent_cert,
        client_cert=client_cert,
        connect_log=tmp / "connect.log",
        processes=processes,
    )
    try:
        (tmp / "listener.py").write_text(LISTENER, encoding="utf-8")
        processes.append(
            _popen_in_namespace(
                hub,
                [
                    "python3",
                    str(tmp / "listener.py"),
                    f"{HUB_INTERLINK_ADDR}:{CONTROL_PORT}",
                    f"{HUB_INTERLINK_ADDR}:22",
                    f"{HUB_LAN_ADDR}:{CONTROL_PORT}",
                ],
                tmp / "hub-listener.log",
            )
        )
        processes.append(
            _popen_in_namespace(
                inet, ["python3", str(tmp / "listener.py"), f"{INET_ADDR}:80"], tmp / "inet.log"
            )
        )
        ocserv = _popen_in_namespace(
            hub,
            ["ocserv", "-f", "--log-stderr", "-c", str(tmp / "ocserv.conf")],
            tmp / "ocserv.log",
        )
        processes.append(ocserv)
        _wait_until(
            lambda: (
                ocserv.poll() is None
                and tcp_check(peers["client"].ns, peers["client"].hub_addr, 443)
            ),
            "ocserv on 443",
        )
    except BaseException:
        groups_lab.stop()
        raise
    lab.log_dirs.append(tmp)
    return groups_lab


def _make_pki(hub: Namespace, tmp: Path) -> str:
    pki = tmp / "pki"
    pki.mkdir()
    (pki / "ca.tmpl").write_text(
        "cn = spike CA\nca\ncert_signing_key\ncrl_signing_key\nexpiration_days = 30\n",
        encoding="utf-8",
    )
    (pki / "server.tmpl").write_text(
        "cn = hub\ntls_www_server\nsigning_key\nencryption_key\nexpiration_days = 30\n",
        encoding="utf-8",
    )
    hub.run(["certtool", "--generate-privkey", "--outfile", str(pki / "ca.key")])
    hub.run(
        [
            "certtool", "--generate-self-signed",
            "--load-privkey", str(pki / "ca.key"),
            "--template", str(pki / "ca.tmpl"),
            "--outfile", str(pki / "ca.crt"),
        ]
    )  # fmt: skip
    hub.run(["certtool", "--generate-privkey", "--outfile", str(pki / "server.key")])
    hub.run(
        [
            "certtool", "--generate-certificate",
            "--load-privkey", str(pki / "server.key"),
            "--load-ca-certificate", str(pki / "ca.crt"),
            "--load-ca-privkey", str(pki / "ca.key"),
            "--template", str(pki / "server.tmpl"),
            "--outfile", str(pki / "server.crt"),
        ]
    )  # fmt: skip
    info = hub.run(["certtool", "-i", "--infile", str(pki / "server.crt")]).stdout
    match = re.search(r"pin-sha256:[A-Za-z0-9+/=]+", info)
    assert match is not None, info
    return match.group(0)


def _revoke(hub: Namespace, tmp: Path, certificate: Path) -> None:
    """What CertificateService.revoke_certificate_pem does: CRL signed by the CA."""
    pki = tmp / "pki"
    (pki / "crl.tmpl").write_text("crl_next_update = 30\n", encoding="utf-8")
    hub.run(
        [
            "certtool", "--generate-crl",
            "--load-ca-privkey", str(pki / "ca.key"),
            "--load-ca-certificate", str(pki / "ca.crt"),
            "--load-certificate", str(certificate),
            "--template", str(pki / "crl.tmpl"),
            "--outfile", str(pki / "crl.pem"),
        ]
    )  # fmt: skip
    with (tmp / "ocserv.conf").open("a", encoding="utf-8") as conf:
        conf.write(f"crl = {pki}/crl.pem\n")


def _write_ocserv_files(hub: Namespace, tmp: Path, *, guard: bool) -> None:
    pki = tmp / "pki"
    groups, users = tmp / "groups", tmp / "users"
    groups.mkdir()
    users.mkdir()
    (groups / "clients").write_text(f"ipv4-network = {CLIENT_POOL}\n", encoding="utf-8")
    (groups / "agents").write_text(
        f"ipv4-network = {INTERLINK_CIDR}\nroute = {INTERLINK_CIDR}\n"
        "restrict-user-to-routes = false\n",
        encoding="utf-8",
    )
    # No restrict-user-to-*: ocserv enforces them through /usr/libexec/ocserv-fw
    # (iptables), a second kernel writer that silently does nothing without
    # iptables. The enroll restriction is ENROLL_NFT, compiled by kornode.net.
    (groups / "enroll").write_text(
        f"ipv4-network = {ENROLL_POOL}\nroute = {HUB_INTERLINK_ADDR}/32\nmax-same-clients = 1\n",
        encoding="utf-8",
    )
    (users / f"agent-{AGENT_ID}").write_text(
        f"explicit-ipv4 = 10.99.0.{AGENT_ID}\n", encoding="utf-8"
    )
    passwd = tmp / "ocpasswd"
    for user, password, group in (
        (CLIENT_USER, CLIENT_PASSWORD, "clients"),
        (ENROLL_USER, ENROLL_PASSWORD, "enroll"),
    ):
        hub.run(
            ["ocpasswd", "-c", str(passwd), "-g", group, user],
            input_text=f"{password}\n{password}\n",
        )
    log = tmp / "connect.log"
    script = tmp / "connect.sh"
    script.write_text(
        CONNECT_SCRIPT.format(log=log, guard=GUARD.format(log=log) if guard else ""),
        encoding="utf-8",
    )
    script.chmod(0o755)
    (tmp / "ocserv.conf").write_text(
        textwrap.dedent(
            f"""\
            tcp-port = 443
            device = vpns
            run-as-user = nobody
            run-as-group = nogroup
            use-occtl = true
            occtl-socket-file = {tmp}/occtl.sock
            socket-file = {tmp}/ocserv.sock
            log-level = 3
            server-cert = {pki}/server.crt
            server-key = {pki}/server.key
            ca-cert = {pki}/ca.crt
            auth = "plain[passwd={passwd}]"
            enable-auth = "certificate"
            cert-user-oid = 2.5.4.3
            cert-group-oid = 2.5.4.11
            config-per-group = {groups}/
            config-per-user = {users}/
            connect-script = {script}
            ipv4-network = {CLIENT_POOL}
            max-clients = 16
            max-same-clients = 2
            keepalive = 30
            dpd = 30
            isolate-workers = false
            predictable-ips = true
            auth-timeout = 30
            cookie-timeout = 300
            """
        ),
        encoding="utf-8",
    )


@pytest.fixture
def groups_lab(lab: Lab, spike_tmp: Path) -> Iterator[GroupsLab]:
    handle = _start(lab, spike_tmp, guard=True)
    try:
        yield handle
    finally:
        handle.stop()


def test_s01_s02_password_client_and_certificate_agent_share_one_listener(
    groups_lab: GroupsLab,
) -> None:
    assert groups_lab.client.connect(groups_lab.pin, user=CLIENT_USER, password=CLIENT_PASSWORD)
    assert groups_lab.agent.connect(groups_lab.pin, cert=groups_lab.agent_cert)

    client_addr = groups_lab.client.address()
    assert client_addr is not None and ip_address(client_addr) in ip_network(CLIENT_POOL)
    assert groups_lab.agent.address() == f"10.99.0.{AGENT_ID}"
    assert groups_lab.agent.pushed_routes() == [INTERLINK_CIDR]

    log = groups_lab.connect_log.read_text(encoding="utf-8")
    assert f"user={CLIENT_USER} group=clients" in log
    assert f"user=agent-{AGENT_ID} group=agents" in log
    print(groups_lab.show_users())  # noqa: T201 - spike evidence
    print(log)  # noqa: T201
    # The hub side of every agent session is the hub interlink address.
    agent_line = f"user=agent-{AGENT_ID} group=agents ip=10.99.0.{AGENT_ID}"
    assert f"{agent_line} local={HUB_INTERLINK_ADDR}" in log

    assert tcp_check(groups_lab.client.ns, INET_ADDR, 80)
    assert tcp_check(groups_lab.client.ns, HUB_LAN_ADDR, CONTROL_PORT)
    assert tcp_check(groups_lab.agent.ns, HUB_INTERLINK_ADDR, CONTROL_PORT)
    assert tcp_check(groups_lab.agent.ns, HUB_INTERLINK_ADDR, 22)


def test_s01_client_certificate_without_password_is_refused(groups_lab: GroupsLab) -> None:
    assert not groups_lab.rogue.connect(groups_lab.pin, cert=groups_lab.client_cert)
    assert groups_lab.rogue.address() is None
    print(
        groups_lab.connect_log.read_text(encoding="utf-8")
        if groups_lab.connect_log.exists()
        else "no connect-script call"
    )  # noqa: E501, T201


def test_s01_without_guard_a_client_certificate_bypasses_the_password(
    lab: Lab, spike_tmp: Path
) -> None:
    """Documents why the connect-script guard exists. If this starts failing,
    ocserv refuses OU-less certificates itself and the guard is redundant."""
    handle = _start(lab, spike_tmp, guard=False)
    try:
        connected = handle.rogue.connect(handle.pin, cert=handle.client_cert)
        print(
            handle.connect_log.read_text(encoding="utf-8")
            if handle.connect_log.exists()
            else "no connect-script call"
        )  # noqa: E501, T201
        assert connected
    finally:
        handle.stop()


def test_a_revoked_ou_less_certificate_is_refused_even_without_the_guard(
    lab: Lab, spike_tmp: Path
) -> None:
    """P4-04 (D-67): the listener certificate of an access agent is hub-CA signed
    without OU and is revoked in the hub CRL when it is issued, so the hub refuses it
    by itself, independent of the connect-script guard and of group selection."""
    handle = _start(lab, spike_tmp, guard=False, revoke_client_cert=True)
    try:
        assert not handle.rogue.connect(handle.pin, cert=handle.client_cert)
        assert handle.rogue.address() is None
    finally:
        handle.stop()


def test_s04_enroll_session_reaches_only_the_control_api(groups_lab: GroupsLab) -> None:
    assert groups_lab.enroll.connect(
        groups_lab.pin,
        user=ENROLL_USER,
        password=ENROLL_PASSWORD,
        extra_routes=(f"{HUB_LAN_ADDR}/32", f"{INET_ADDR}/32"),
    )
    addr = groups_lab.enroll.address()
    assert addr is not None and ip_address(addr) in ip_network(ENROLL_POOL), addr
    assert groups_lab.enroll.pushed_routes() == [f"{HUB_INTERLINK_ADDR}/32"]
    reach = {
        "control api": tcp_check(groups_lab.enroll.ns, HUB_INTERLINK_ADDR, CONTROL_PORT),
        "hub interlink :22": tcp_check(groups_lab.enroll.ns, HUB_INTERLINK_ADDR, 22),
        "hub lan": tcp_check(groups_lab.enroll.ns, HUB_LAN_ADDR, CONTROL_PORT),
        "internet": tcp_check(groups_lab.enroll.ns, INET_ADDR, 80),
    }
    assert reach == {
        "control api": True,
        "hub interlink :22": False,
        "hub lan": False,
        "internet": False,
    }
    # The rule set must not affect other groups.
    assert groups_lab.client.connect(groups_lab.pin, user=CLIENT_USER, password=CLIENT_PASSWORD)
    assert tcp_check(groups_lab.client.ns, INET_ADDR, 80)
