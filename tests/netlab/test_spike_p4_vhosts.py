"""Spike S-07 (docs/redesign/DECISIONS.md, D-70): one ocserv on 443 serves the interlink and
clients through SNI-selected virtual hosts.

`interlink.kornode.test` (vhost): agent certificates and enroll users, own server
certificate and password file. Default host: clients, by password or by client
certificate + password. Hand-written ocserv.conf like the P3 spikes: this pins down
ocserv behaviour, the kornode renderer comes after the spike passes.
"""

from __future__ import annotations

import re
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.netlab.kornode_nodes import _wait_until
from tests.netlab.lab import Lab, Namespace
from tests.netlab.ocserv_peers import Peer
from tests.netlab.test_spike_p3_groups import (
    AGENT_ID,
    CLIENT_PASSWORD,
    CLIENT_POOL,
    CLIENT_USER,
    ENROLL_PASSWORD,
    ENROLL_USER,
    INTERLINK_CIDR,
    GroupsLab,
    _start,
    spike_tmp,  # noqa: F401 - fixture
)

pytestmark = pytest.mark.netlab

INTERLINK_HOST = "interlink.kornode.test"
DTLS_ESTABLISHED = "Established DTLS connection"


def _write_vhost_conf(hub: Namespace, tmp: Path, *, client_cert_required: bool) -> None:
    """Replaces the single-host ocserv.conf of the P3 spike (same groups/users/script)."""
    pki = tmp / "pki"
    (pki / "interlink.tmpl").write_text(
        f"cn = {INTERLINK_HOST}\ndns_name = {INTERLINK_HOST}\ntls_www_server\n"
        "signing_key\nencryption_key\nexpiration_days = 30\n",
        encoding="utf-8",
    )
    hub.run(["certtool", "--generate-privkey", "--outfile", str(pki / "interlink.key")])
    hub.run(
        [
            "certtool", "--generate-certificate",
            "--load-privkey", str(pki / "interlink.key"),
            "--load-ca-certificate", str(pki / "ca.crt"),
            "--load-ca-privkey", str(pki / "ca.key"),
            "--template", str(pki / "interlink.tmpl"),
            "--outfile", str(pki / "interlink.crt"),
        ]
    )  # fmt: skip
    info = hub.run(["certtool", "-i", "--infile", str(pki / "interlink.crt")]).stdout
    (pki / "interlink.pin").write_text(_pin(info), encoding="utf-8")

    # One password file per host: a client password must not log in to the interlink
    # vhost and an enroll password must not log in to the default host.
    for passwd, user, password, group in (
        (tmp / "ocpasswd-clients", CLIENT_USER, CLIENT_PASSWORD, "clients"),
        (tmp / "ocpasswd-enroll", ENROLL_USER, ENROLL_PASSWORD, "enroll"),
    ):
        hub.run(
            ["ocpasswd", "-c", str(passwd), "-g", group, user],
            input_text=f"{password}\n{password}\n",
        )
    if client_cert_required:
        default_auth = f'auth = "certificate"\nauth = "plain[passwd={tmp}/ocpasswd-clients]"'
        default_ca = f"ca-cert = {pki}/ca.crt\ncert-user-oid = 2.5.4.3"
    else:
        default_auth = f'auth = "plain[passwd={tmp}/ocpasswd-clients]"'
        default_ca = ""
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
            connect-script = {tmp}/connect.sh
            ipv4-network = {CLIENT_POOL}
            max-clients = 16
            max-same-clients = 2
            keepalive = 30
            dpd = 30
            isolate-workers = false
            predictable-ips = true
            auth-timeout = 30
            cookie-timeout = 300
            config-per-group = {tmp}/groups/
            """
        )
        + default_auth
        + "\n"
        + default_ca
        + "\n"
        + textwrap.dedent(
            f"""\

            [vhost:{INTERLINK_HOST}]
            udp-port = 443
            server-cert = {pki}/interlink.crt
            server-key = {pki}/interlink.key
            ca-cert = {pki}/ca.crt
            auth = "plain[passwd={tmp}/ocpasswd-enroll]"
            enable-auth = "certificate"
            cert-user-oid = 2.5.4.3
            cert-group-oid = 2.5.4.11
            config-per-group = {tmp}/groups/
            config-per-user = {tmp}/users/
            ipv4-network = {CLIENT_POOL}
            """
        ),
        encoding="utf-8",
    )


def _pin(certtool_info: str) -> str:
    match = re.search(r"pin-sha256:[A-Za-z0-9+/=]+", certtool_info)
    assert match is not None, certtool_info
    return match.group(0)


@pytest.fixture(params=["password", "certificate+password"])
def vhost_lab(request: pytest.FixtureRequest, lab: Lab, spike_tmp: Path) -> Iterator[GroupsLab]:  # noqa: F811
    required = request.param == "certificate+password"
    handle = _start(
        lab,
        spike_tmp,
        guard=True,
        write_conf=lambda hub, tmp: _write_vhost_conf(hub, tmp, client_cert_required=required),
    )
    handle.client_auth = request.param  # type: ignore[attr-defined]
    try:
        yield handle
    finally:
        handle.stop()


def _interlink_pin(handle: GroupsLab) -> str:
    return (handle.tmp / "pki" / "interlink.pin").read_text(encoding="utf-8")


def _connect_client(handle: GroupsLab, peer: Peer, **kwargs: object) -> bool:
    """Client login on the default host: password, plus certificate in the second mode."""
    cert = handle.client_cert if handle.client_auth == "certificate+password" else None  # type: ignore[attr-defined]
    return peer.connect(
        handle.pin,
        user=CLIENT_USER,
        password=CLIENT_PASSWORD,
        cert=cert,
        **kwargs,  # type: ignore[arg-type]
    )


def _log(handle: GroupsLab) -> str:
    return handle.connect_log.read_text(encoding="utf-8") if handle.connect_log.exists() else ""


def test_s07_agent_certificate_logs_in_to_the_interlink_vhost(vhost_lab: GroupsLab) -> None:
    assert vhost_lab.agent.connect(
        _interlink_pin(vhost_lab), cert=vhost_lab.agent_cert, sni=INTERLINK_HOST
    )
    assert vhost_lab.agent.address() == f"10.99.0.{AGENT_ID}"
    assert vhost_lab.agent.pushed_routes() == [INTERLINK_CIDR]
    print(_log(vhost_lab))  # noqa: T201 - spike evidence
    assert f"user=agent-{AGENT_ID} group=agents" in _log(vhost_lab)


def test_s07_agent_certificate_is_refused_on_the_default_host(vhost_lab: GroupsLab) -> None:
    assert not vhost_lab.rogue.connect(vhost_lab.pin, cert=vhost_lab.agent_cert)
    assert vhost_lab.rogue.address() is None


def test_s07_client_logs_in_to_the_default_host(vhost_lab: GroupsLab) -> None:
    assert _connect_client(vhost_lab, vhost_lab.client)
    assert vhost_lab.client.address() is not None
    assert f"user={CLIENT_USER} group=clients" in _log(vhost_lab)


def test_s07_client_is_refused_on_the_interlink_vhost(vhost_lab: GroupsLab) -> None:
    pin = _interlink_pin(vhost_lab)
    assert not vhost_lab.rogue.connect(
        pin, user=CLIENT_USER, password=CLIENT_PASSWORD, sni=INTERLINK_HOST
    )
    assert vhost_lab.rogue.address() is None
    # An OU-less client certificate is the case the connect-script guard rejects.
    assert not vhost_lab.rogue.connect(pin, cert=vhost_lab.client_cert, sni=INTERLINK_HOST)
    assert vhost_lab.rogue.address() is None


def test_s07_enroll_password_works_only_on_the_interlink_vhost(vhost_lab: GroupsLab) -> None:
    assert not vhost_lab.rogue.connect(
        vhost_lab.pin, user=ENROLL_USER, password=ENROLL_PASSWORD, cert=vhost_lab.client_cert
    )
    assert not vhost_lab.rogue.connect(vhost_lab.pin, user=ENROLL_USER, password=ENROLL_PASSWORD)
    assert vhost_lab.enroll.connect(
        _interlink_pin(vhost_lab), user=ENROLL_USER, password=ENROLL_PASSWORD, sni=INTERLINK_HOST
    )
    assert f"user={ENROLL_USER} group=enroll" in _log(vhost_lab)


def _dtls_established(handle: GroupsLab, peer: Peer) -> bool:
    log = handle.tmp / f"{peer.iface}.openconnect.log"
    try:
        _wait_until(
            lambda: DTLS_ESTABLISHED in log.read_text(encoding="utf-8", errors="replace"),
            "DTLS",
            timeout=10,
        )
    except TimeoutError:
        return False
    return True


def test_s07_dtls_and_tcp_only_work_on_both_vhosts(vhost_lab: GroupsLab) -> None:
    assert vhost_lab.agent.connect(
        _interlink_pin(vhost_lab), cert=vhost_lab.agent_cert, sni=INTERLINK_HOST
    )
    dtls = {
        "interlink": _dtls_established(vhost_lab, vhost_lab.agent),
    }
    assert _connect_client(vhost_lab, vhost_lab.client)
    dtls["default"] = _dtls_established(vhost_lab, vhost_lab.client)
    print(dtls)  # noqa: T201 - spike evidence
    assert dtls == {"interlink": True, "default": True}

    vhost_lab.agent.stop()
    vhost_lab.client.stop()
    assert vhost_lab.agent.connect(
        _interlink_pin(vhost_lab), cert=vhost_lab.agent_cert, sni=INTERLINK_HOST, no_dtls=True
    )
    assert vhost_lab.agent.address() == f"10.99.0.{AGENT_ID}"
    assert _connect_client(vhost_lab, vhost_lab.client, no_dtls=True)
