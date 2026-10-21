"""P3-03/P3-05: enrollment, revocation, the control API over the fabric, spoofing.

Reuses the P3-02 hub fixture, which also runs the real control API on the hub
fabric address. `enroll` and everything an agent does is real HTTP(S) from the
peer's namespace. Admin-side calls that have no HTTP surface yet (P3-08:
`issue_token`, `revoke_node`) run as small scripts in the hub namespace against
the same registry/ocpasswd/CA ocserv uses.
"""

# ruff: noqa: F811 - pytest fixtures imported from test_p3_groups
from __future__ import annotations

import base64
import json
import os
import re
import sys
import textwrap
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from tests.netlab.helpers import tcp_check
from tests.netlab.kornode_nodes import _wait_until
from tests.netlab.lab import Namespace
from tests.netlab.ocserv_peers import Peer
from tests.netlab.test_p3_groups import (  # noqa: F401 - fixtures
    CONTROL_PORT,
    ENROLL_PASSWORD,
    ENROLL_USER,
    FABRIC_CIDR,
    HUB_FABRIC_ADDR,
    HUB_LAN_ADDR,
    INET_ADDR,
    RenderedHub,
    node_tmp,
    rendered_hub,
)

from kornode.services.command import CommandError

pytestmark = pytest.mark.netlab

NEW_ID = 4
HUB_SCRIPT = textwrap.dedent(
    """
    import base64, json, os, signal, sys
    from pathlib import Path
    from kornode.config.loader import load_config
    from kornode.registry.db import migrate, open_registry
    from kornode.registry.repository import Registry
    from kornode.services.enrollment import EnrollmentService

    cfg = load_config(Path(sys.argv[1]), cli_overrides={}, environ={})
    op, args = sys.argv[2], sys.argv[3:]
    ocserv_pid = int(os.environ["KN_OCSERV_PID"])
    svc = EnrollmentService(
        cfg, reload_ocserv=lambda: os.kill(ocserv_pid, signal.SIGHUP), hub="hub:443"
    )
    if op == "create":
        conn = open_registry(cfg.system.data_dir / "registry.db")
        migrate(conn)
        Registry(conn).create_node(id=int(args[0]), name=f"node{args[0]}")
    elif op == "token":
        print(svc.issue_token(int(args[0])))
    elif op == "revoke":
        svc.revoke_node(int(args[0]))
    elif op == "delete":
        conn = open_registry(cfg.system.data_dir / "registry.db")
        migrate(conn)
        Registry(conn).delete_node(int(args[0]))
        from kornode.services.fabric_groups import FabricGroupsService
        FabricGroupsService(cfg).sync()
    """
)


def _ocserv_pid(hub: RenderedHub) -> int:
    for process in hub.processes:
        argv = process.args
        if isinstance(argv, list) and "ocserv" in argv:
            return process.pid
    raise AssertionError("ocserv process not found")


def _hub_call(hub: RenderedHub, op: str, *args: str) -> str:
    env = {"KN_OCSERV_PID": str(_ocserv_pid(hub))}
    bin_dir = Path(sys.executable).absolute().parent
    full_env = {**os.environ, **env, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    try:
        result = hub.hub.run(
            [sys.executable, "-c", HUB_SCRIPT, str(hub.root.config_path), op, *args],
            env=full_env,
            timeout=90,
        )
    except CommandError as exc:
        raise AssertionError(f"hub call {op} failed:\n{exc.result.stderr}") from exc
    return result.stdout


HTTP_CLIENT = textwrap.dedent(
    """
    import http.client, ssl, sys
    ca, host, port, method, path, body_file, *cert = sys.argv[1:]
    ctx = ssl.create_default_context(cafile=ca)
    if cert:
        ctx.load_cert_chain(cert[0], cert[1])
    conn = http.client.HTTPSConnection(host, int(port), context=ctx, timeout=20)
    body = open(body_file).read() if body_file != "-" else None
    conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    print(response.status)
    print(response.read().decode())
    """
)


def _http(
    hub: RenderedHub,
    ns: Namespace,
    method: str,
    path: str,
    *,
    body: Path | None = None,
    cert: tuple[Path, Path] | None = None,
) -> tuple[int, str]:
    argv = [
        sys.executable,
        "-c",
        HTTP_CLIENT,
        str(hub.root.data_dir / "certs" / "ca.crt"),
        HUB_FABRIC_ADDR,
        str(CONTROL_PORT),
        method,
        path,
        str(body) if body else "-",
    ]
    if cert is not None:
        argv.extend(str(item) for item in cert)
    try:
        output = ns.run(argv, timeout=60).stdout
    except CommandError as exc:
        raise AssertionError(f"{method} {path} failed:\n{exc.result.stderr}") from exc
    status, _, rest = output.partition("\n")
    return int(status), rest.strip()


def _decode(token: str) -> dict[str, str]:
    return json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))


def _csr(out: Path, name: str) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(key, hashes.SHA256())
    )
    key_path, csr_path = out / f"{name}.key", out / f"{name}.csr"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return key_path, csr_path


def _enroll_agent(hub: RenderedHub, node_tmp_dir: Path) -> tuple[Path, Path]:
    """Whole happy path: token -> enroll session -> CSR -> certificate for agent-4."""
    _hub_call(hub, "create", str(NEW_ID))
    doc = _decode(_hub_call(hub, "token", str(NEW_ID)).strip())
    doc_path = node_tmp_dir / "token.json"
    doc_path.write_text(json.dumps(doc), encoding="utf-8")
    assert hub.connect_fabric(hub.enroll, user=doc["user"], password=doc["secret"])
    key, csr = _csr(node_tmp_dir, f"agent-{NEW_ID}")
    request = node_tmp_dir / "enroll-request.json"
    request.write_text(
        json.dumps(
            {
                "token_id": doc["id"],
                "secret": doc["secret"],
                "csr_pem": csr.read_text(encoding="utf-8"),
                "seal_pubkey_b64": base64.b64encode(b"\x07" * 32).decode(),
            }
        ),
        encoding="utf-8",
    )
    status, body = _http(hub, hub.enroll.ns, "POST", "/agent/v1/enroll", body=request)
    assert status == 200, body
    result = json.loads(body)
    crt = node_tmp_dir / f"agent-{NEW_ID}.crt"
    crt.write_text(result["cert_pem"], encoding="utf-8")
    hub.enroll.stop()
    return crt, key


def _agent_sessions(hub: RenderedHub) -> str:
    sock = hub.root.generated_dir / "occtl.sock"
    return hub.hub.run(["occtl", "-s", str(sock), "show", "users"], check=False).stdout


def test_enroll_by_csr_then_certificate_joins_agents_group(
    rendered_hub: RenderedHub, node_tmp: Path
) -> None:
    hub = rendered_hub
    crt, key = _enroll_agent(hub, node_tmp)

    # the one-shot enroll user is gone: the same credentials no longer log in
    assert hub.enroll.address() is None
    assert hub.connect_fabric(hub.agent, cert=(crt, key))
    assert hub.agent.address() == f"10.99.0.{NEW_ID}"
    assert hub.agent.pushed_routes() == [FABRIC_CIDR]
    assert tcp_check(hub.agent.ns, HUB_FABRIC_ADDR, CONTROL_PORT)


def test_agent_polls_its_bundle_over_the_fabric_and_revocation_gives_403(
    rendered_hub: RenderedHub, node_tmp: Path
) -> None:
    hub = rendered_hub
    crt, key = _enroll_agent(hub, node_tmp)
    assert hub.connect_fabric(hub.agent, cert=(crt, key))

    status, body = _http(hub, hub.agent.ns, "GET", "/agent/v1/poll?since=0", cert=(crt, key))
    assert status == 200, body
    bundle = json.loads(body)["bundle"]
    assert bundle is not None and bundle["signature"].startswith("ed25519:")
    status, body = _http(hub, hub.agent.ns, "GET", "/agent/v1/ping", cert=(crt, key))
    assert status == 204, body

    _hub_call(hub, "revoke", str(NEW_ID))

    # The session is cut, so the refusal is observed from the hub itself.
    status, body = _http(hub, hub.hub, "GET", "/agent/v1/ping", cert=(crt, key))
    assert status == 403 and json.loads(body)["error"] == "revoked", body


def test_enroll_session_cannot_use_the_agent_api_without_a_certificate(
    rendered_hub: RenderedHub,
) -> None:
    hub = rendered_hub
    assert hub.connect_fabric(hub.enroll, user=ENROLL_USER, password=ENROLL_PASSWORD)

    status, body = _http(hub, hub.enroll.ns, "GET", "/agent/v1/poll?since=0")

    assert status == 401 and json.loads(body)["error"] == "unauthorized", body


def test_revoked_certificate_cannot_connect_and_live_session_is_cut(
    rendered_hub: RenderedHub, node_tmp: Path
) -> None:
    hub = rendered_hub
    crt, key = _enroll_agent(hub, node_tmp)
    assert hub.connect_fabric(hub.agent, cert=(crt, key))
    assert f"agent-{NEW_ID}" in _agent_sessions(hub)

    _hub_call(hub, "revoke", str(NEW_ID))

    _wait_until(lambda: f"agent-{NEW_ID}" not in _agent_sessions(hub), "session cut", timeout=15)
    hub.agent.stop()
    assert not hub.connect_fabric(hub.agent, cert=(crt, key))
    assert f"agent-{NEW_ID}" not in _agent_sessions(hub)


def test_agent_removed_from_registry_cannot_connect_with_a_live_certificate(
    rendered_hub: RenderedHub,
) -> None:
    hub = rendered_hub
    assert hub.connect_fabric(hub.agent, cert=hub.agent_cert)  # registered, active
    hub.agent.stop()

    _hub_call(hub, "delete", "3")

    assert not hub.connect_fabric(hub.agent, cert=hub.agent_cert)


def test_enroll_session_cannot_spoof_a_source_outside_its_pool(
    rendered_hub: RenderedHub,
) -> None:
    """A blind attack: the enroll session forges the address of a live agent (D-47).

    The probe table hooks after kornode's chains, so its counters see only
    what kornode let through. A real agent-3 session first proves the probes
    do count such packets; otherwise "0 packets" would prove nothing.
    """
    hub = rendered_hub
    spoofed = "10.99.0.3"
    probes = ((HUB_FABRIC_ADDR, 2222), (INET_ADDR, 80))
    hub.hub.run(
        ["nft", "-f", "-"],
        input_text=textwrap.dedent(
            f"""
            table ip spoofprobe {{
              chain input {{
                type filter hook input priority 100; policy accept;
                ip saddr {spoofed} tcp dport 2222 counter
              }}
              chain forward {{
                type filter hook forward priority 100; policy accept;
                ip saddr {spoofed} ip daddr {INET_ADDR} tcp dport 80 counter
              }}
            }}
            """
        ),
    )

    def counters() -> tuple[int, int]:
        text = hub.hub.run(["nft", "list", "table", "ip", "spoofprobe"]).stdout
        found = [int(item) for item in re.findall(r"counter packets (\d+)", text)]
        return found[0], found[1]

    def send(peer: Peer) -> None:
        for host, port in probes:
            peer.ns.run(
                ["python3", "-c", SPOOFED_SYN, spoofed, host, str(port)], check=False, timeout=15
            )

    assert hub.connect_fabric(hub.agent, cert=hub.agent_cert, extra_routes=(f"{INET_ADDR}/32",))
    send(hub.agent)
    control = counters()
    assert control[0] > 0 and control[1] > 0, control
    # The agent stays connected: its address is routed on the hub, so the
    # kernel's loose rp_filter lets a forged source through (it would only
    # drop sources without any route).
    hub.hub.run(["nft", "reset", "rules", "table", "ip", "spoofprobe"])

    assert hub.connect_fabric(
        hub.enroll,
        user="enroll-3-k2f9",
        password="enroll-secret",
        extra_routes=(f"{INET_ADDR}/32", f"{HUB_FABRIC_ADDR}/32"),
    )
    hub.enroll.ns.run(["ip", "addr", "add", f"{spoofed}/32", "dev", hub.enroll.iface])
    send(hub.enroll)
    assert counters() == (0, 0)


SPOOFED_SYN = textwrap.dedent(
    """
    import socket, sys
    src, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.bind((src, 0))
    try:
        s.connect((dst, port))
    except OSError:
        pass
    """
)
