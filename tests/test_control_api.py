"""Control API over a real mTLS listener on loopback (spec 05, D-49)."""

from __future__ import annotations

import base64
import http.client
import json
import shutil
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from tests.test_enrollment import Env as EnrollEnv
from tests.test_enrollment import make_csr

from kornode.control.app import create_app
from kornode.control.auth import RevocationList
from kornode.control.errors import ControlError
from kornode.control.service import ControlService
from kornode.control.tls import server_config
from kornode.services.certificates import CertificateService
from kornode.services.config import ConfigService

pytestmark = pytest.mark.skipif(shutil.which("certtool") is None, reason="certtool not installed")

HOST = "127.0.0.1"
GRACE = 1.0


class Client:
    def __init__(self, port: int, ca: Path, cert: tuple[Path, Path] | None = None) -> None:
        self.port = port
        self.context = ssl.create_default_context(cafile=str(ca))
        if cert is not None:
            self.context.load_cert_chain(str(cert[0]), str(cert[1]))

    def request(
        self, method: str, path: str, body: Any = None, *, raw: bytes | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPSConnection(HOST, self.port, context=self.context, timeout=15)
        try:
            payload = raw if raw is not None else (None if body is None else json.dumps(body))
            conn.request(method, path, body=payload, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            headers = {key.lower(): value for key, value in response.getheaders()}
            return response.status, headers, response.read()
        finally:
            conn.close()

    def json(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        status, _, data = self.request(method, path, body)
        return status, (json.loads(data) if data else None)


class Hub:
    def __init__(self, env: EnrollEnv, tmp_path: Path) -> None:
        self.env = env
        self.tmp_path = tmp_path
        self.config = env.config
        certificates = CertificateService(self.config, runner=env.runner)
        certificates.ensure_crl()
        certificates.ensure_control_certificate(HOST)
        # The CRL lifetime follows the wall clock; env.clock only moves issuance.
        revocations = RevocationList(
            self.config.cert_path("crl.pem"), self.config.cert_path("ca.crt")
        )
        self.service = ControlService(
            self.config, clock=env.clock, enrollment=env.service, revocations=revocations
        )
        with socket.socket() as probe:
            probe.bind((HOST, 0))
            self.port = int(probe.getsockname()[1])
        self.server = uvicorn.Server(
            server_config(
                create_app(self.config, self.service, enroll_grace_seconds=GRACE),
                host=HOST,
                port=self.port,
                certfile=str(self.config.cert_path("control.crt")),
                keyfile=str(self.config.cert_path("control.key")),
                ca_certs=str(self.config.cert_path("ca.crt")),
                log_level="warning",
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 20
        while not self.server.started:
            assert time.monotonic() < deadline, "control server did not start"
            time.sleep(0.05)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)

    @property
    def ca(self) -> Path:
        return self.config.cert_path("ca.crt")

    def anonymous(self) -> Client:
        return Client(self.port, self.ca)

    def enroll(self, node_id: int = 3) -> Client:
        doc = self.env.token(node_id)
        key = ec.generate_private_key(ec.SECP256R1())
        status, result = self.anonymous().json(
            "POST",
            "/agent/v1/enroll",
            {
                "token_id": doc["id"],
                "secret": doc["secret"],
                "csr_pem": make_csr(key),
                "seal_pubkey_b64": base64.b64encode(b"\x07" * 32).decode(),
            },
        )
        assert status == 200, result
        crt = self.tmp_path / f"agent-{node_id}.crt"
        pem = self.tmp_path / f"agent-{node_id}.key"
        crt.write_text(result["cert_pem"])
        pem.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.first_bundle = result["bundle"]
        return Client(self.port, self.ca, (crt, pem))


@pytest.fixture
def hub(tmp_path: Path) -> Iterator[Hub]:
    env = EnrollEnv(tmp_path)
    instance = Hub(env, tmp_path)
    try:
        yield instance
    finally:
        instance.stop()


def _report(**overrides: Any) -> dict[str, Any]:
    return {"agent_version": "2.0.0", "applied_version": 1, **overrides}


def test_every_route_but_enroll_refuses_a_missing_certificate(hub: Hub) -> None:
    anonymous = hub.anonymous()

    for method, path in (
        ("GET", "/agent/v1/ping"),
        ("GET", "/agent/v1/bundle"),
        ("GET", "/agent/v1/poll"),
        ("GET", "/agent/v1/commands"),
        ("POST", "/agent/v1/report"),
        ("POST", "/agent/v1/renew"),
        ("POST", "/agent/v1/commands/abc/result"),
        ("GET", "/agent/v1/nothing"),
        ("GET", "/openapi.json"),
    ):
        status, body = anonymous.json(method, path)
        assert (status, body["error"]) == (401, "unauthorized"), (method, path)


def test_enroll_then_ping_bundle_and_not_modified(hub: Hub) -> None:
    agent = hub.enroll()

    assert agent.request("GET", "/agent/v1/ping")[0] == 204
    first = hub.first_bundle
    status, headers, body = agent.request("GET", "/agent/v1/bundle?since=0")
    assert status == 200
    assert headers["x-kornode-version"] == str(first["version"])
    assert headers["x-kornode-signature"] == first["signature"]
    assert body == base64.b64decode(first["body_b64"])
    assert agent.request("GET", f"/agent/v1/bundle?since={first['version']}")[0] == 304
    assert hub.env.registry.get_node(3).last_seen is not None


def test_long_poll_wakes_up_on_a_new_bundle(hub: Hub) -> None:
    agent = hub.enroll()
    version = hub.first_bundle["version"]

    def change() -> None:
        time.sleep(1.0)
        hub.env.registry.update_node(3, transport={"dpd": 20})
        hub.service.compile_all("test change")

    worker = threading.Thread(target=change)
    started = time.monotonic()
    worker.start()
    status, body = agent.json("GET", f"/agent/v1/poll?since={version}&wait=20")
    worker.join()

    assert status == 200
    assert body["bundle"]["version"] > version
    assert body["commands"] == []
    assert time.monotonic() - started < 15


def test_poll_times_out_with_an_empty_answer(hub: Hub) -> None:
    agent = hub.enroll()
    version = hub.first_bundle["version"]

    status, body = agent.json("GET", f"/agent/v1/poll?since={version}&wait=1")

    assert (status, body) == (200, {"bundle": None, "commands": []})


def test_since_above_latest_recovers_with_a_higher_version(hub: Hub) -> None:
    agent = hub.enroll()
    version = hub.first_bundle["version"]

    status, body = agent.json("GET", f"/agent/v1/poll?since={version + 10}")

    assert status == 200
    assert body["bundle"]["version"] == version + 11
    assert hub.env.registry.get_node(3).high_water_version == version + 10


def test_out_of_range_version_is_invalid(hub: Hub) -> None:
    agent = hub.enroll()

    for path in (
        "/agent/v1/bundle?since=99999999999999",
        "/agent/v1/poll?since=-1",
        "/agent/v1/poll?since=x",
    ):
        status, body = agent.json("GET", path)
        assert (status, body["error"]) == (400, "invalid"), path


def test_report_updates_the_registry_and_high_water_is_monotonic(hub: Hub) -> None:
    agent = hub.enroll()

    assert (
        agent.json("POST", "/agent/v1/report", _report(applied_version=4, high_water_version=9))[0]
        == 204
    )
    assert (
        agent.json("POST", "/agent/v1/report", _report(applied_version=5, high_water_version=2))[0]
        == 204
    )

    node = hub.env.registry.get_node(3)
    assert (node.applied_version, node.high_water_version) == (5, 9)
    assert [item.body["applied_version"] for item in hub.env.registry.list_reports(3)] == [5, 4]


def test_report_is_validated(hub: Hub) -> None:
    agent = hub.enroll()

    status, body = agent.json("POST", "/agent/v1/report", _report(node_id=7))
    assert (status, body["error"]) == (400, "invalid")
    status, body = agent.json("POST", "/agent/v1/report", {"applied_version": "1"})
    assert (status, body["error"]) == (400, "invalid")
    status, _, data = agent.request("POST", "/agent/v1/report", raw=b"{not json")
    assert (status, json.loads(data)["error"]) == (400, "invalid")
    status, _, data = agent.request("POST", "/agent/v1/report", raw=b" " * (300 * 1024))
    assert status == 413
    assert hub.env.registry.list_reports(3) == []


def test_report_carries_the_resolved_addresses_of_exit_rules_and_wakes_the_reconciler(
    hub: Hub, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-79: only a changed `exit_sets` wakes the hub reconciler; malformed ones are refused."""
    wakes: list[int] = []
    monkeypatch.setattr(
        "kornode.control.service.NetService.wake", lambda self: wakes.append(1) or True
    )
    agent = hub.enroll()

    first = _report(applied_version=1) | {"exit_sets": {"web": ["203.0.113.9"]}}
    assert agent.json("POST", "/agent/v1/report", first)[0] == 204
    assert agent.json("POST", "/agent/v1/report", first)[0] == 204
    assert wakes == [1]
    again = _report(applied_version=2) | {"exit_sets": {"web": ["203.0.113.9", "198.51.100.1"]}}
    assert agent.json("POST", "/agent/v1/report", again)[0] == 204
    assert wakes == [1, 1]

    for bad in ({"web": ["nope"]}, {"web": "203.0.113.9"}, ["web"]):
        status, body = agent.json("POST", "/agent/v1/report", _report() | {"exit_sets": bad})
        assert (status, body["error"]) == (400, "invalid"), bad


def test_commands_are_delivered_once_and_finished_by_their_node_only(hub: Hub) -> None:
    agent = hub.enroll()
    command = hub.env.registry.enqueue_command(3, "reconnect", {"tunnel": "fabric"})

    assert agent.request("GET", "/agent/v1/commands")[0] == 200
    assert agent.request("GET", "/agent/v1/commands")[0] == 204
    status, body = agent.json(
        "POST", f"/agent/v1/commands/{command.id}/result", {"ok": True, "output": "done"}
    )
    assert status == 204 and body is None
    assert hub.env.registry.get_command(command.id).state == "done"
    status, body = agent.json("POST", "/agent/v1/commands/nope/result", {"ok": True})
    assert (status, body["error"]) == (404, "not_found")


def test_poll_returns_commands_alongside_the_bundle(hub: Hub) -> None:
    agent = hub.enroll()
    version = hub.first_bundle["version"]
    hub.env.registry.enqueue_command(3, "restart")

    status, body = agent.json("GET", f"/agent/v1/poll?since={version}")

    assert status == 200
    assert body["bundle"] is None
    assert [item["type"] for item in body["commands"]] == ["restart"]


def test_revoked_agent_gets_403_with_the_same_certificate(hub: Hub) -> None:
    agent = hub.enroll()
    assert agent.request("GET", "/agent/v1/ping")[0] == 204

    hub.env.service.revoke_node(3)

    status, body = agent.json("GET", "/agent/v1/ping")
    assert (status, body["error"]) == (403, "revoked")
    status, _ = agent.json("GET", "/agent/v1/poll")
    assert status == 403


def test_a_non_agent_certificate_is_refused(hub: Hub) -> None:
    certificates = CertificateService(hub.config, runner=hub.env.runner)
    certificates.create_user_certificate("bob")
    user = hub.config.cert_path("users/bob.crt")
    key = hub.config.cert_path("users/bob.key")
    if not user.exists():
        pytest.skip("user certificate layout differs")
    client = Client(hub.port, hub.ca, (user, key))

    status, body = client.json("GET", "/agent/v1/ping")

    assert (status, body["error"]) == (401, "unauthorized")


def test_a_missing_revocation_list_fails_closed(hub: Hub) -> None:
    agent = hub.enroll()
    hub.config.cert_path("crl.pem").unlink()

    status, body = agent.json("GET", "/agent/v1/ping")

    assert (status, body["error"]) == (503, "internal")


def test_enroll_is_rate_limited_per_source(hub: Hub) -> None:
    anonymous = hub.anonymous()
    attempt = {
        "token_id": "deadbeef",
        "secret": "x",
        "csr_pem": make_csr(),
        "seal_pubkey_b64": base64.b64encode(b"\x07" * 32).decode(),
    }

    statuses = [anonymous.json("POST", "/agent/v1/enroll", attempt)[0] for _ in range(7)]

    assert statuses == [403] * 5 + [429] * 2


def test_renew_uses_the_certificate_identity(hub: Hub) -> None:
    agent = hub.enroll()
    csr = {"csr_pem": make_csr(cn="agent-1", ou="agents")}

    status, body = agent.json("POST", "/agent/v1/renew", csr)
    assert (status, body["error"]) == (409, "conflict")

    hub.env.clock.now += timedelta(days=70)
    status, body = agent.json("POST", "/agent/v1/renew", csr)
    assert status == 200
    cert = x509.load_pem_x509_certificate(body["cert_pem"].encode())
    assert cert.subject.rfc4514_string().startswith("CN=agent-3")


def test_service_denies_unknown_agents_and_audits(hub: Hub) -> None:
    with pytest.raises(ControlError) as caught:
        hub.service.authenticate(None, "192.0.2.1")
    assert caught.value.status == 401
    audit = (hub.config.system.log_dir / "audit.jsonl").read_text()
    assert "control.auth" in audit and "192.0.2.1" in audit


def test_saving_the_hub_configuration_recompiles_bundles(hub: Hub) -> None:
    hub.enroll()
    before = hub.env.registry.get_node(3).desired_version
    changed = hub.config.model_copy(deep=True)
    changed.server.port = 8443

    ConfigService().write_rendered_files(changed)

    assert hub.env.registry.get_node(3).desired_version == before + 1


def test_enroll_session_is_cut_only_after_the_answer(hub: Hub) -> None:
    hub.enroll()

    # enroll() already returned; the cut is scheduled after the grace period.
    assert hub.env.runner.occtl() == []
    deadline = time.monotonic() + 10
    while not hub.env.runner.occtl():
        assert time.monotonic() < deadline, "enroll session was never cut"
        time.sleep(0.1)
    assert hub.env.runner.occtl()[0][-3:-1] == ["disconnect", "user"]
    assert hub.env.runner.occtl()[0][-1].startswith("enroll-3-")
