from __future__ import annotations

import base64
import json
import os
import shutil
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

from kornode.bundle.validator import validate
from kornode.config.models import AppConfig
from kornode.registry.db import migrate, open_registry
from kornode.registry.repository import Registry
from kornode.services import enrollment as enrollment_module
from kornode.services.certificates import CertificateService
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.enrollment import (
    EnrollmentError,
    EnrollmentService,
    hash_secret,
)

pytestmark = pytest.mark.skipif(shutil.which("certtool") is None, reason="certtool not installed")


class FakeRunner(CommandRunner):
    """certtool runs for real; ocpasswd/occtl are recorded and simulated."""

    def __init__(self, passwd: Path) -> None:
        super().__init__()
        self.passwd = passwd
        self.calls: list[list[str]] = []
        self.extra_secrets: list[str] = []

    def run(self, argv: Sequence[str], **kwargs: Any) -> CommandResult:
        self.calls.append(list(argv))
        self.extra_secrets.extend(kwargs.get("extra_secrets") or [])
        if argv[0] == "ocpasswd":
            user = argv[-1]
            group = argv[argv.index("-g") + 1] if "-g" in argv else ""
            with self.passwd.open("a", encoding="utf-8") as handle:
                handle.write(f"{user}:{group}:$hash\n")
            return CommandResult(tuple(argv), 0, "", "")
        if argv[0] == "occtl":
            return CommandResult(tuple(argv), 0, "", "")
        return super().run(argv, **kwargs)

    def occtl(self) -> list[list[str]]:
        return [call for call in self.calls if call[0] == "occtl"]


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "log_dir": tmp_path / "logs",
                "secrets_dir": tmp_path / "secrets",
            },
            "fabric": {"enabled": True},
            "control": {"enabled": True},
            "auth": {"password": {"enabled": True}},
            "identity": {
                "config_per_group_dir": tmp_path / "generated" / "groups",
                "config_per_user_dir": tmp_path / "generated" / "users",
            },
        }
    )


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.config = _config(tmp_path)
        self.runner = FakeRunner(self.config.secret_path("ocpasswd"))
        self.clock = Clock()
        self.reloads = 0
        certs = CertificateService(self.config, runner=self.runner)
        certs.init_ca()
        certs.create_server_certificate()
        conn = open_registry(self.config.system.data_dir / "registry.db")
        migrate(conn)
        self.registry = Registry(conn)
        self.registry.create_node(id=1, name="hub", state="active")
        self.registry.create_node(id=3, name="node3", state="pending")
        self.service = EnrollmentService(
            self.config,
            runner=self.runner,
            reload_ocserv=self._reload,
            hub="vpn.example.com:443",
            clock=self.clock,
        )

    def _reload(self) -> None:
        self.reloads += 1

    def token(self, node_id: int = 3) -> dict[str, Any]:
        raw = self.service.issue_token(node_id)
        padded = raw + "=" * (-len(raw) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))

    def passwd_lines(self) -> list[str]:
        path = self.config.secret_path("ocpasswd")
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def enroll(self, doc: Mapping[str, Any], csr: str | None = None) -> dict[str, Any]:
        return self.service.enroll(
            token_id=doc["id"],
            secret=doc["secret"],
            csr_pem=csr or make_csr(),
            seal_pubkey_b64=base64.b64encode(b"\x07" * 32).decode(),
        )


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def make_csr(key: Any = None, cn: str = "evil", ou: str = "clients") -> str:
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        ]
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def tampered_csr() -> str:
    """Valid structure, but the signature no longer matches the content."""
    der = bytearray(
        x509.load_pem_x509_csr(make_csr().encode()).public_bytes(serialization.Encoding.DER)
    )
    der[-1] ^= 0xFF
    body = base64.encodebytes(bytes(der)).decode()
    return f"-----BEGIN CERTIFICATE REQUEST-----\n{body}-----END CERTIFICATE REQUEST-----\n"


def test_issue_token_document_and_enroll_user(env: Env) -> None:
    doc = env.token()

    assert doc["v"] == 1
    assert doc["hub"] == "vpn.example.com:443"
    assert doc["pin"].startswith("pin-sha256:")
    assert doc["user"] == f"enroll-3-{doc['id']}"
    assert doc["exp"] == "2026-10-13T13:00:00Z"
    assert env.passwd_lines() == [f"{doc['user']}:enroll:$hash"]
    stored = env.registry.get_enroll_token(doc["id"])
    assert stored.secret_hash == hash_secret(doc["secret"])
    assert doc["secret"] not in json.dumps(stored.__dict__)


def test_issue_token_replaces_previous_and_requires_pending(env: Env) -> None:
    first = env.token()
    second = env.token()

    assert [t.id for t in env.registry.list_enroll_tokens(3)] == [second["id"]]
    assert first["user"] != second["user"]
    # only the new enroll user is left in ocpasswd
    assert first["user"] not in "".join(env.passwd_lines())
    assert second["user"] in "".join(env.passwd_lines())
    env.registry.set_state(3, "active")
    with pytest.raises(EnrollmentError) as exc:
        env.service.issue_token(3)
    assert exc.value.status == 409
    with pytest.raises(EnrollmentError) as missing:
        env.service.issue_token(99)
    assert missing.value.status == 404


def test_enroll_issues_cert_with_hub_chosen_subject(env: Env) -> None:
    doc = env.token()
    result = env.enroll(doc, make_csr(cn="admin", ou="clients"))

    cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "agent-3"
    assert (
        cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "agents"
    )
    days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    lifetime = env.config.control.cert_lifetime_days
    assert days in (lifetime, lifetime + 1)
    ca = x509.load_pem_x509_certificate(result["ca_pem"].encode())
    cert.verify_directly_issued_by(ca)
    assert result["node_id"] == 3
    bundle = result["bundle"]
    assert bundle["version"] == 1
    trusted = {
        item["key_id"]: Ed25519PublicKey.from_public_bytes(base64.b64decode(item["pubkey_b64"]))
        for item in result["signing_keys"]
    }
    checked = validate(
        base64.b64decode(bundle["body_b64"]),
        bundle["signature"],
        trusted=trusted,
        high_water_version=0,
        agent_version="2.0.0", expected_node_id=3,
    )
    assert checked.bundle.node_id == 3

    node = env.registry.get_node(3)
    assert node.state == "active"
    assert node.cert_serial == format(cert.serial_number, "x")
    assert node.seal_pubkey == b"\x07" * 32
    assert env.registry.get_enroll_token(doc["id"]).used_at is not None
    # enroll user removed from ocpasswd, session cut, per-user file rendered
    assert env.passwd_lines() == []
    assert [
        "occtl",
        "-s",
        env.runner.occtl()[0][2],
        "disconnect",
        "user",
        doc["user"],
    ] in env.runner.occtl()
    assert (env.config.identity.config_per_user_dir / "agent-3").is_file()  # type: ignore[operator]


def test_enroll_wrong_secret_is_403_and_audited(env: Env) -> None:
    doc = env.token()
    with pytest.raises(EnrollmentError) as exc:
        env.service.enroll(
            token_id=doc["id"],
            secret="nope",
            csr_pem=make_csr(),
            seal_pubkey_b64=base64.b64encode(b"\x00" * 32).decode(),
            source_ip="10.99.255.241",
        )
    assert exc.value.status == 403
    with pytest.raises(EnrollmentError) as unknown:
        env.service.enroll(
            token_id="deadbeef",
            secret=doc["secret"],
            csr_pem=make_csr(),
            seal_pubkey_b64=base64.b64encode(b"\x00" * 32).decode(),
        )
    assert unknown.value.status == 403
    audit = (env.config.system.log_dir / "audit.jsonl").read_text(encoding="utf-8")
    assert '"outcome":"denied"' in audit
    assert doc["secret"] not in audit
    assert env.registry.get_node(3).state == "pending"


def test_enroll_token_is_one_shot_and_expires(env: Env) -> None:
    doc = env.token()
    env.enroll(doc)
    with pytest.raises(EnrollmentError) as used:
        env.enroll(doc)
    assert used.value.status == 410

    env.registry.create_node(id=4, name="node4", state="pending")
    late = env.token(4)
    env.clock.now += timedelta(hours=2)
    with pytest.raises(EnrollmentError) as expired:
        env.enroll(late)
    assert expired.value.status == 410


def test_enroll_node_not_pending_is_409(env: Env) -> None:
    doc = env.token()
    env.registry.set_state(3, "revoked")
    with pytest.raises(EnrollmentError) as exc:
        env.enroll(doc)
    assert exc.value.status == 409


@pytest.mark.parametrize(
    "csr",
    [
        "not a csr",
        make_csr(key=rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        make_csr(key=ec.generate_private_key(ec.SECP384R1())),
        tampered_csr(),
    ],
)
def test_enroll_rejects_bad_csr_without_burning_token(env: Env, csr: str) -> None:
    doc = env.token()
    with pytest.raises(EnrollmentError) as exc:
        env.enroll(doc, csr)
    assert exc.value.status == 400
    assert env.registry.get_enroll_token(doc["id"]).used_at is None
    assert env.registry.get_node(3).state == "pending"


def test_enroll_rejects_bad_seal_key(env: Env) -> None:
    doc = env.token()
    with pytest.raises(EnrollmentError) as exc:
        env.service.enroll(
            token_id=doc["id"],
            secret=doc["secret"],
            csr_pem=make_csr(),
            seal_pubkey_b64=base64.b64encode(b"short").decode(),
        )
    assert exc.value.status == 400


def test_renew_only_after_two_thirds_and_keeps_old_cert(env: Env) -> None:
    env.enroll(env.token())
    old_serial = env.registry.get_node(3).cert_serial

    with pytest.raises(EnrollmentError) as early:
        env.service.renew(3, make_csr())
    assert early.value.status == 409

    env.clock.now += timedelta(days=61)  # > 2/3 of 90 days
    result = env.service.renew(3, make_csr())
    new = x509.load_pem_x509_certificate(result["cert_pem"].encode())
    node = env.registry.get_node(3)
    assert node.cert_serial == format(new.serial_number, "x") != old_serial
    agents_dir = env.service.certificates.cert_dir / "agents"
    assert len(list(agents_dir.glob("agent-3-*.crt"))) == 2
    assert not (env.service.certificates.cert_dir / "revoked.pem").exists()


def test_renewal_warning_window(env: Env) -> None:
    env.enroll(env.token())
    node = env.registry.get_node(3)
    assert not env.service.renewal_warning(node)
    env.clock.now += timedelta(days=80)
    assert env.service.renewal_warning(node)


def test_revoke_node_crl_reload_disconnect_and_sync(env: Env) -> None:
    env.enroll(env.token())
    env.registry.set_prefixes(3, [{"prefix": "10.100.3.0/24", "kind": "pool"}])
    env.clock.now += timedelta(days=61)
    env.service.renew(3, make_csr())  # two live certificates

    env.service.revoke_node(3)

    node = env.registry.get_node(3)
    assert node.state == "revoked"
    assert env.registry.list_prefixes(3) == []
    cert_dir = env.service.certificates.cert_dir
    revoked = (cert_dir / "revoked.pem").read_text(encoding="utf-8")
    assert revoked.count("BEGIN CERTIFICATE") == 2
    crl = x509.load_pem_x509_crl((cert_dir / "crl.pem").read_bytes())
    assert len(list(crl)) == 2
    assert env.reloads == 1
    assert any(call[-3:] == ["disconnect", "user", "agent-3"] for call in env.runner.occtl())
    assert not (env.config.identity.config_per_user_dir / "agent-3").exists()  # type: ignore[operator]


def test_revoke_pending_node_drops_token_and_user(env: Env) -> None:
    doc = env.token()
    env.service.revoke_node(3)
    assert env.registry.list_enroll_tokens(3) == []
    assert env.passwd_lines() == []
    with pytest.raises(EnrollmentError):
        env.enroll(doc)


def test_maintain_purges_expired_and_refreshes_stale_crl(env: Env) -> None:
    env.token()
    assert env.service.maintain()["purged_tokens"] == 0
    env.clock.now += timedelta(hours=2)
    result = env.service.maintain()
    assert result["purged_tokens"] == 1
    assert env.passwd_lines() == []
    assert env.registry.list_enroll_tokens() == []

    crl = env.service.certificates.cert_dir / "crl.pem"
    old = crl.stat().st_mtime - 11 * 24 * 3600
    os.utime(crl, (old, old))
    before = env.reloads
    assert env.service.maintain()["crl_refreshed"] == 1
    assert env.reloads == before + 1


def test_secret_is_masked_and_never_logged(env: Env) -> None:
    doc = env.token()
    env.enroll(doc)
    # the password goes over stdin and is registered for masking, not put in argv
    assert doc["secret"] in env.runner.extra_secrets
    for call in env.runner.calls:
        assert doc["secret"] not in " ".join(call)
    audit = (env.config.system.log_dir / "audit.jsonl").read_text(encoding="utf-8")
    assert doc["secret"] not in audit


def test_revoke_between_check_and_commit_is_not_undone(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = env.token()
    real = enrollment_module._validated_seal_key

    def revoke_then_validate(value: str) -> bytes:
        env.service.revoke_node(3)  # lands after enroll() read the node as pending
        return real(value)

    monkeypatch.setattr(enrollment_module, "_validated_seal_key", revoke_then_validate)
    with pytest.raises(EnrollmentError) as exc:
        env.enroll(doc)
    assert exc.value.status == 409
    assert env.registry.get_node(3).state == "revoked"
    assert not (env.config.identity.config_per_user_dir / "agent-3").exists()  # type: ignore[operator]


def test_enroll_survives_post_commit_failure_and_maintain_heals(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = env.token()
    calls = {"n": 0}
    real_sync = env.service.groups.sync

    def flaky_sync(*, dry_run: bool = False) -> list[Path]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk full")
        return real_sync(dry_run=dry_run)

    monkeypatch.setattr(env.service.groups, "sync", flaky_sync)
    result = env.enroll(doc)  # no 500: the registry is committed
    assert result["node_id"] == 3
    user_file = env.config.identity.config_per_user_dir / "agent-3"  # type: ignore[operator]
    assert not user_file.exists()
    audit = (env.config.system.log_dir / "audit.jsonl").read_text(encoding="utf-8")
    assert "sync groups" in audit

    env.service.maintain()
    assert user_file.is_file()


def test_revoke_runs_every_step_and_reports_failures(env: Env) -> None:
    env.enroll(env.token())

    def broken_reload() -> None:
        raise RuntimeError("supervisor down")

    env.service._reload_ocserv = broken_reload
    with pytest.raises(EnrollmentError) as exc:
        env.service.revoke_node(3)
    assert "reload ocserv" in exc.value.message
    # the other steps still ran
    assert env.registry.get_node(3).state == "revoked"
    assert (env.service.certificates.cert_dir / "crl.pem").exists()
    assert any(call[-3:] == ["disconnect", "user", "agent-3"] for call in env.runner.occtl())


def test_malformed_token_id_is_403(env: Env) -> None:
    with pytest.raises(EnrollmentError) as exc:
        env.service.enroll(
            token_id="../x" * 20,
            secret="s",
            csr_pem=make_csr(),
            seal_pubkey_b64=base64.b64encode(b"\x00" * 32).decode(),
        )
    assert exc.value.status == 403


def test_enroll_recompiles_other_active_agents(env: Env) -> None:
    env.registry.create_node(
        id=2, name="node2", state="active", seal_pubkey=b"\x05" * 32
    )
    env.service.bundles.compile_node(env.registry, 2, "setup")
    before = env.registry.get_node(2).desired_version
    env.registry.set_prefixes(3, [{"prefix": "192.168.3.0/24", "kind": "lan"}])

    env.enroll(env.token())

    assert env.registry.get_node(2).desired_version == before + 1
