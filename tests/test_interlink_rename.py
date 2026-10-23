"""D-85 compatibility: read legacy state, write interlink, preserve authenticated identity."""

from __future__ import annotations

import base64
import copy
import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError
from tests.test_agent_apply import World
from tests.test_bundle import _example
from tests.test_bundle_service import Env

from kornode.bundle.canonical import canonical_json
from kornode.bundle.errors import BundleError
from kornode.bundle.models import BUNDLE_FORMAT, Bundle
from kornode.bundle.sealing import public_bytes, seal
from kornode.bundle.signing import sign
from kornode.config.loader import load_config, load_default_config, load_yaml_file
from kornode.net.model import EgressPolicy, Source
from kornode.services.bundle import policy_with_implicit_rules
from kornode.services.certificates import CertificateService
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.interlink import InterlinkService
from kornode.tunnels.pin import certificate_file_pin
from kornode_agent import __version__
from kornode_agent.config import load_config as load_agent_config
from kornode_agent.config import save_config as save_agent_config
from kornode_agent.store import State, StoreError
from kornode_agent.tunnels import specs_for


@pytest.mark.parametrize("source", ["yaml", "env", "dotenv", "discovered_dotenv"])
def test_old_hub_section_loads_without_rewriting_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, source: str
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("node: {id: 3}\n", encoding="utf-8")
    values = {"domain": "kornode.internal", "cidr": "10.77.0.0/24"}
    environ: dict[str, str] = {}
    env_file = tmp_path / (".env" if source == "discovered_dotenv" else "custom.env")
    if source == "yaml":
        path.write_text(yaml.safe_dump({"node": {"id": 3}, "fabric": values}))
    elif source == "env":
        environ = {f"KORNODE_FABRIC__{key.upper()}": value for key, value in values.items()}
    else:
        env_file.write_text(
            "\n".join(
                f"export KORNODE_FABRIC__{key.upper()}='{value}'" for key, value in values.items()
            )
        )
    original = path.read_bytes()
    with caplog.at_level(logging.WARNING):
        config = load_config(
            path,
            environ=environ,
            env_file=env_file if source == "dotenv" else None,
        )
    assert config.interlink.domain == "kornode.internal"
    assert config.interlink.server_name == "interlink.kornode.internal"
    assert config.interlink.cidr == "10.77.0.0/24"
    assert config.server.ipv4_network == "10.100.3.0/24"
    assert path.read_bytes() == original
    assert "section `fabric` is now called `interlink`" in caplog.text
    assert "fabric" not in config.model_dump()


@pytest.mark.parametrize("source", ["yaml", "env", "dotenv", "mixed_environment"])
def test_conflicting_section_names_fail_even_with_disjoint_fields(
    tmp_path: Path, source: str
) -> None:
    path, env_file = tmp_path / "config.yaml", tmp_path / ".env"
    path.write_text("{}")
    environ: dict[str, str] = {}
    if source == "yaml":
        path.write_text("fabric: {domain: old.example}\ninterlink: {cidr: 10.77.0.0/24}\n")
    elif source == "env":
        environ = {
            "KORNODE_FABRIC__DOMAIN": "old.example",
            "KORNODE_INTERLINK__CIDR": "10.77.0.0/24",
        }
    elif source == "dotenv":
        env_file.write_text(
            "KORNODE_FABRIC__DOMAIN=old.example\nKORNODE_INTERLINK__CIDR=10.77.0.0/24\n"
        )
    else:
        env_file.write_text("KORNODE_FABRIC__DOMAIN=old.example\n")
        environ = {"KORNODE_INTERLINK__DOMAIN": "new.example"}
    with pytest.raises(ValueError, match="both `fabric` and `interlink`"):
        load_config(path, environ=environ)


@pytest.mark.parametrize("yaml_name,env_name", [("fabric", "interlink"), ("interlink", "fabric")])
def test_aliases_preserve_precedence_between_sources(
    tmp_path: Path, yaml_name: str, env_name: str
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(f"{yaml_name}: {{domain: yaml.example}}\n")
    env_file = tmp_path / ".env"
    env_file.write_text(f"KORNODE_{env_name.upper()}__DOMAIN=dotenv.example\n")
    environ = {
        f"KORNODE_{env_name.upper()}__DOMAIN": "process.example",
        f"KORNODE_{env_name.upper()}__CIDR": "10.77.0.0/24",
    }
    config = load_config(path, environ=environ)
    assert config.interlink.domain == "yaml.example"
    assert config.interlink.cidr == "10.77.0.0/24"
    assert (
        load_config(
            path, environ=environ, cli_overrides={"interlink": {"domain": "cli.example"}}
        ).interlink.domain
        == "cli.example"
    )
    path.write_text("{}")
    assert load_config(path, environ=environ).interlink.domain == "process.example"
    assert load_config(path, environ={}).interlink.domain == "dotenv.example"


def test_settings_save_upgrades_the_section_without_losing_values(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("fabric: {domain: kornode.internal, reserved: [192.0.2.0/24]}\n")
    from tests.test_config_source_api import _client

    _client(path)  # local runtime paths for transactional rendered writes
    path.write_text(
        path.read_text() + "fabric: {domain: kornode.internal, reserved: [192.0.2.0/24]}\n"
    )
    service = InterlinkService(load_config(path, environ={}), path, sync=lambda config: None)
    service.set({"domain": "custom.example"})
    written = yaml.safe_load(path.read_text())
    assert "fabric" not in written
    assert written["interlink"] == {"domain": "custom.example", "reserved": ["192.0.2.0/24"]}
    assert load_yaml_file(path) == written


def test_legacy_rules_are_normalized_without_mutating_registry_data() -> None:
    stored = {
        "egress": [
            {"from": ["host"], "to": "fabric", "via": "fabric"},
            {"from": ["fabric"], "to": "any", "via": "local"},
            {"from": ["clients"], "to": "any", "via": "exit:2"},
        ]
    }
    original = copy.deepcopy(stored)
    policy = EgressPolicy.model_validate(stored)
    emitted = policy.model_dump(mode="json", by_alias=True)
    assert emitted["egress"][0]["to"] == "interlink"
    assert emitted["egress"][0]["via"] == "interlink"
    assert emitted["egress"][1]["from"] == ["interlink"]
    assert emitted["egress"][2]["via"] == "node:2"
    bundled = policy_with_implicit_rules(stored, ["gateway"])
    assert len(bundled["egress"]) == 3  # no duplicate implicit rules after normalization
    assert EgressPolicy.model_validate(bundled) == policy
    assert stored == original


@pytest.mark.parametrize("name", ["fabric", "interlink"])
def test_old_and_new_builtin_source_names_are_reserved(name: str) -> None:
    with pytest.raises(ValidationError, match="reserved"):
        Source(name=name, interface="eth1", cidr="192.0.2.0/24")


def test_aliases_cannot_hide_duplicate_source_classes() -> None:
    with pytest.raises(ValidationError, match="duplicate entries"):
        EgressPolicy.model_validate(
            {"egress": [{"from": ["fabric", "interlink"], "to": "any", "via": "local"}]}
        )


def _agent_document() -> dict[str, Any]:
    return {
        "node_id": 3,
        "hub": {
            "host": "hub.example",
            "port": 443,
            "pin": "pin-sha256:test",
            "control_url": "https://10.99.0.1:8444",
            "server_name": "fabric.kornode.internal",
        },
        "fabric": {"interface": "oc-old0", "transport": "tcp"},
    }


def test_old_agent_yaml_is_read_and_saved_under_new_name(tmp_path: Path) -> None:
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(_agent_document()))
    original = path.read_bytes()
    config = load_agent_config(tmp_path)
    assert config.interlink.interface == "oc-old0"
    assert config.interlink.transport == "tcp"
    # Do not guess a new SNI during parsing: re-enrollment is a separate operation.
    assert config.hub.server_name == "fabric.kornode.internal"
    assert path.read_bytes() == original
    save_agent_config(tmp_path, config)
    written = yaml.safe_load(path.read_text())
    assert "fabric" not in written
    assert written["interlink"] == _agent_document()["fabric"]
    assert path.stat().st_mode & 0o777 == 0o600


def test_agent_yaml_conflicting_names_are_rejected(tmp_path: Path) -> None:
    doc = _agent_document()
    doc["interlink"] = doc["fabric"].copy()
    (tmp_path / "agent.yaml").write_text(yaml.safe_dump(doc))
    with pytest.raises(StoreError, match="both `fabric` and `interlink`"):
        load_agent_config(tmp_path)


def _legacy_bundle() -> dict[str, Any]:
    doc = _example()
    doc["format"] = "kornode.bundle/v1"
    doc["min_agent_version"] = "2.0.0"
    doc["fabric"] = doc.pop("interlink")
    doc["fabric"]["domain"] = "kornode.internal"
    for prefix in doc["fabric"]["prefixes"]:
        if prefix["kind"] == "interlink":
            prefix["kind"] = "fabric"
    doc["node"]["fabric_address"] = doc["node"].pop("interlink_address")
    doc["node"]["roles"] = ["access", "exit"]
    doc["tunnels"]["fabric"] = doc["tunnels"].pop("interlink")
    doc["tunnels"]["upstreams"] = []
    doc.pop("access")
    doc["policy"] = {
        "egress": [
            {"from": ["host"], "to": "fabric", "via": "fabric"},
            {"from": ["fabric"], "to": "any", "via": "local"},
            {"from": ["clients"], "to": "any", "via": "exit:2"},
        ]
    }
    return doc


def _cache(world: World, doc: dict[str, Any]) -> tuple[bytes, str]:
    # Deliberately non-canonical: the signature must cover original bytes, not reserialization.
    body = json.dumps(doc, indent=2).encode()
    envelope = sign(body, world.signer)
    world.store.write_bundle(doc["version"], body, envelope)
    world.store.save_state(
        State(current=doc["version"], confirmed=[doc["version"]], high_water=doc["version"] + 10)
    )
    return body, envelope


def test_signed_v1_cache_boots_unseals_old_aad_and_keeps_original_bytes(tmp_path: Path) -> None:
    world = World(tmp_path)
    doc = _legacy_bundle()
    secret = "cached-camouflage-value"
    doc["tunnels"]["fabric"]["camouflage"] = seal(
        secret, public_bytes(world.seal.public_key()), 3, "/tunnels/fabric/camouflage"
    )
    original = copy.deepcopy(doc)
    body, envelope = _cache(world, doc)
    applier = world.restart()
    assert applier.state.current == 42 and applier.state.high_water == 52
    assert applier.active is not None
    bundle = applier.active.bundle
    assert bundle.format == BUNDLE_FORMAT
    assert bundle.node.roles == ("access", "gateway")
    assert bundle.node.interlink_address == "10.99.0.3"
    assert bundle.interlink.domain == "kornode.internal"
    assert bundle.interlink.prefixes[0].kind == "interlink"
    assert bundle.policy.egress[0].via == "interlink"
    assert bundle.policy.egress[1].from_ == ("interlink",)
    assert bundle.policy.egress[2].via == "node:2"
    assert applier.active.secrets == {"/tunnels/interlink/camouflage": secret}
    (tmp_path / "agent.yaml").write_text(yaml.safe_dump(_agent_document()))
    specs = specs_for(applier.active, load_agent_config(tmp_path), tmp_path)
    assert specs["interlink"].dials[0].camouflage_secret == secret
    cached = world.store.read_bundle(42)
    assert cached is not None and (cached.body, cached.signature) == (body, envelope)
    assert doc == original


def test_signature_is_checked_before_json_parsing_or_v1_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(tmp_path)
    body, envelope = _cache(world, _legacy_bundle())

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("unverified bundle was parsed or upgraded")

    with monkeypatch.context() as patch:
        patch.setattr("kornode.bundle.validator.json.loads", forbidden)
        patch.setattr("kornode.bundle.models.upgrade_v1", forbidden)
        with pytest.raises(BundleError) as bad:
            world.applier._verify(body + b" ", envelope, version=42)
    assert bad.value.code == "bad_signature"


def test_upgraded_bytes_cannot_reuse_the_v1_signature(tmp_path: Path) -> None:
    world = World(tmp_path)
    body, envelope = _cache(world, _legacy_bundle())
    upgraded = Bundle.model_validate_json(body).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    with pytest.raises(BundleError) as bad:
        world.applier._verify(canonical_json(upgraded), envelope, version=42)
    assert bad.value.code == "bad_signature"


@pytest.mark.parametrize("location", ["root", "node", "tunnels"])
def test_v1_bundle_conflicting_aliases_are_rejected(tmp_path: Path, location: str) -> None:
    world = World(tmp_path)
    doc = _legacy_bundle()
    target = doc if location == "root" else doc[location]
    old, new = (
        ("fabric_address", "interlink_address") if location == "node" else ("fabric", "interlink")
    )
    target[new] = copy.deepcopy(target[old])
    body, envelope = _cache(world, doc)
    with pytest.raises(BundleError) as bad:
        world.applier._verify(body, envelope, version=42)
    assert bad.value.code == "malformed"
    assert "both" in bad.value.message


def test_tampered_v1_cache_is_not_activated(tmp_path: Path) -> None:
    world = World(tmp_path)
    body, envelope = _cache(world, _legacy_bundle())
    world.store.write_bundle(42, body.replace(b"10.99.0.3", b"10.99.0.4"), envelope)
    assert world.restart().active is None
    assert world.runtime.activated == [None]
    assert any("bad_signature" in event.get("error", "") for event in world.events)


@pytest.mark.parametrize("configured", ["2.0.0", "2.1.0", "2.10.0"])
def test_new_bundles_are_v2_and_require_at_least_agent_2_1(tmp_path: Path, configured: str) -> None:
    assert __version__ == "2.1.0"
    assert load_default_config().control.min_agent_version == "2.1.0"
    assert load_default_config().interlink.domain == "kornode.lan"
    env = Env(tmp_path)
    try:
        env.config.control.min_agent_version = configured
        env.add(3)
        stored = env.compile(3)
        doc = json.loads(stored.body)
        assert doc["format"] == BUNDLE_FORMAT
        assert doc["min_agent_version"] == ("2.10.0" if configured == "2.10.0" else "2.1.0")
        assert "fabric" not in doc and "fabric" not in doc["tunnels"]
        assert "fabric_address" not in doc["node"]
    finally:
        env.registry.conn.close()


@pytest.mark.parametrize("declared_minimum", [None, "2.0.0", "2.1.0"])
def test_v2_format_cannot_claim_support_for_pre_rename_agents(
    tmp_path: Path, declared_minimum: str | None
) -> None:
    world = World(tmp_path)
    world.applier.agent_version = "2.0.0"
    doc = _example()
    if declared_minimum is None:
        doc.pop("min_agent_version")
    else:
        doc["min_agent_version"] = declared_minimum
    body = canonical_json(doc)
    with pytest.raises(BundleError) as bad:
        world.applier._verify(body, sign(body, world.signer), version=None)
    assert bad.value.code == "too_old"


def test_stored_transport_ciphertext_survives_rename(tmp_path: Path) -> None:
    env = Env(tmp_path)
    try:
        env.add(3)
        blob = env.service.encrypt_external_secrets(3, "fabric-transport", {"camouflage": "hidden"})

        env.registry.update_node(3, transport={"camouflage_enc": base64.b64encode(blob).decode()})
        result = env.check(env.compile(3))
        assert result.secrets == {"/tunnels/interlink/camouflage": "hidden"}
    finally:
        env.registry.conn.close()


def _certificate(
    key: ec.EllipticCurvePrivateKey,
    name: str,
    *,
    issuer_key: ec.EllipticCurvePrivateKey | None = None,
    issuer: x509.Name | None = None,
) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(issuer_key or key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize("dry_run", [False, True])
def test_existing_fabric_key_migration_is_pin_stable_and_non_destructive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dry_run: bool
) -> None:
    env = Env(tmp_path)
    try:
        service = CertificateService(env.config)
        certs = service.cert_dir
        certs.mkdir(parents=True)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        legacy_key, legacy_cert = certs / "fabric.key", certs / "fabric.crt"
        legacy_key.write_bytes(pem)
        old_cert = _certificate(key, "fabric.kornode.internal")
        legacy_cert.write_bytes(old_cert)
        pin = certificate_file_pin(legacy_cert).pin
        from tests.test_certificates import WritingRunner

        CertificateService(env.config, runner=WritingRunner()).init_ca()
        issuer_key = serialization.load_pem_private_key(
            env.config.cert_path("ca.key").read_bytes(), password=None
        )
        assert isinstance(issuer_key, ec.EllipticCurvePrivateKey)
        issuer = x509.load_pem_x509_certificate(env.config.cert_path("ca.crt").read_bytes()).subject
        calls: list[list[str]] = []

        def run(self: CommandRunner, argv: list[str], **kwargs: Any) -> CommandResult:
            calls.append(argv)
            assert "--generate-privkey" not in argv
            if not kwargs.get("dry_run"):
                assert Path(argv[argv.index("--load-privkey") + 1]).read_bytes() == pem
                Path(argv[argv.index("--outfile") + 1]).write_bytes(
                    _certificate(
                        key, env.config.interlink.server_name, issuer_key=issuer_key, issuer=issuer
                    )
                )
            return CommandResult(tuple(argv), 0, "", "")

        monkeypatch.setattr(CommandRunner, "run", run)
        assert service.ensure_interlink_certificate(dry_run=dry_run)
        assert legacy_key.read_bytes() == pem and legacy_cert.read_bytes() == old_cert
        if dry_run:
            assert not (certs / "interlink.key").exists()
            assert not (certs / "interlink.crt").exists()
        else:
            assert (certs / "interlink.key").read_bytes() == pem
            assert (certs / "interlink.key").stat().st_mode & 0o777 == 0o600
            assert certificate_file_pin(certs / "interlink.crt").pin == pin
            assert not service.ensure_interlink_certificate()  # idempotent, no reissue
        assert len(calls) == 1
    finally:
        env.registry.conn.close()


@pytest.mark.parametrize("source", ["yaml", "dotenv", "env"])
def test_api_and_cli_settings_writes_accept_old_hub_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    from fastapi.testclient import TestClient
    from tests.test_config_source_api import _client

    from kornode.api.app import create_app
    from kornode.cli import STATE, save_config_patch

    path = tmp_path / "config.yaml"
    _client(path)  # writes a local authenticated configuration, no runtime operations
    if source == "yaml":
        path.write_text(path.read_text() + "fabric: {domain: kornode.internal}\n")
    elif source == "dotenv":
        (tmp_path / ".env").write_text("KORNODE_FABRIC__DOMAIN=kornode.internal\n")
    else:
        monkeypatch.setenv("KORNODE_FABRIC__DOMAIN", "kornode.internal")
    client = TestClient(create_app(config_path=path))
    response = client.patch(
        "/api/config",
        auth=("admin", "secret"),
        json={
            "patch": {"server": {"realm": "API write"}},
            "write_rendered": False,
        },
    )
    assert response.status_code == 200, response.text
    assert load_config(path).interlink.domain == "kornode.internal"
    assert "fabric" not in yaml.safe_load(path.read_text())
    monkeypatch.setitem(STATE, "config_path", path)
    monkeypatch.setitem(STATE, "env_file", None)
    config = save_config_patch({"server": {"realm": "CLI write"}}, write_rendered=False)
    assert config.interlink.domain == "kornode.internal"
    assert config.server.realm == "CLI write"


def test_source_editor_validates_and_saves_old_yaml_as_interlink(tmp_path: Path) -> None:
    from tests.test_config_source_api import _client

    path = tmp_path / "config.yaml"
    client = _client(path)
    source = path.read_text() + "fabric: {domain: kornode.internal}\n"
    etag = client.get("/api/config/source", auth=("admin", "secret")).headers["etag"]
    response = client.post(
        "/api/config/source",
        auth=("admin", "secret"),
        json={
            "content": source,
            "write_rendered": False,
            "etag": etag,
        },
    )
    assert response.status_code == 200, response.text
    written = yaml.safe_load(path.read_text())
    assert "fabric" not in written
    assert written["interlink"]["domain"] == "kornode.internal"


@pytest.mark.parametrize("endpoint", ["source/validate", "source", "validate"])
def test_legacy_config_validation_errors_never_echo_secret_input(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, endpoint: str
) -> None:
    from tests.test_config_source_api import _client

    path = tmp_path / "config.yaml"
    client = _client(path)
    before = path.read_bytes()
    payload = yaml.safe_load(before)
    payload["fabric"] = {"domain": "kornode.internal"}
    sensitive = "d85-private-value"
    # Invalid type: Pydantic must name the field without including its raw value.
    payload["web"]["admin_password"] = [sensitive]
    request = (
        payload
        if endpoint == "validate"
        else {
            "content": yaml.safe_dump(payload),
            "write_rendered": False,
            "etag": client.get("/api/config/source", auth=("admin", "secret")).headers["etag"],
        }
    )
    response = client.post(f"/api/config/{endpoint}", auth=("admin", "secret"), json=request)
    assert response.status_code == 400
    assert any(error["loc"] == ["web", "admin_password"] for error in response.json()["detail"])
    assert sensitive not in response.text
    assert sensitive not in caplog.text
    assert "input_value=" not in response.text
    assert path.read_bytes() == before


def test_v1_camouflage_is_not_decrypted_using_a_renamed_pointer(tmp_path: Path) -> None:
    world = World(tmp_path)
    doc = _legacy_bundle()
    # A ciphertext sealed for the new pointer cannot be transplanted to an old body.
    doc["tunnels"]["fabric"]["camouflage"] = seal(
        "not-transferable",
        public_bytes(world.seal.public_key()),
        3,
        "/tunnels/interlink/camouflage",
    )
    body, envelope = _cache(world, doc)
    with pytest.raises(BundleError) as bad:
        world.applier._verify(body, envelope, version=42)
    assert bad.value.code == "unseal_failed"


def test_cached_v1_keeps_replay_and_node_identity_guards(tmp_path: Path) -> None:
    world = World(tmp_path)
    body, envelope = _cache(world, _legacy_bundle())
    world.applier.state = world.store.load_state()
    with pytest.raises(BundleError) as bad:
        world.applier._verify(body, envelope, version=None)
    assert bad.value.code == "replay"
    world.applier.node_id = 4
    with pytest.raises(BundleError) as bad:
        world.applier._verify(body, envelope, version=42)
    assert bad.value.code == "wrong_node"


def test_malformed_legacy_prefixes_report_bundle_error(tmp_path: Path) -> None:
    world = World(tmp_path)
    doc = _legacy_bundle()
    doc["fabric"]["prefixes"] = 7
    body, envelope = _cache(world, doc)
    with pytest.raises(BundleError) as bad:
        world.applier._verify(body, envelope, version=42)
    assert bad.value.code == "malformed"


@pytest.mark.parametrize("source", [["fabric"], {"source": "fabric"}])
def test_malformed_legacy_rule_class_reports_bundle_error(tmp_path: Path, source: Any) -> None:
    world = World(tmp_path)
    doc = _legacy_bundle()
    doc["policy"]["egress"][0]["from"] = [source]
    body, envelope = _cache(world, doc)
    with pytest.raises(BundleError) as bad:
        world.applier._verify(body, envelope, version=42)
    assert bad.value.code == "malformed"


def test_existing_interlink_key_is_not_overwritten_by_a_legacy_key(tmp_path: Path) -> None:
    env = Env(tmp_path)
    try:
        service = CertificateService(env.config)
        service.cert_dir.mkdir(parents=True)
        active = ec.generate_private_key(ec.SECP256R1())
        active_pem = active.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        new_key = service.cert_dir / "interlink.key"
        new_key.write_bytes(active_pem)
        (service.cert_dir / "interlink.crt").write_bytes(
            _certificate(active, env.config.interlink.server_name)
        )
        old_key = service.cert_dir / "fabric.key"
        old_key.write_bytes(b"legacy-key-must-not-win")
        assert not service.ensure_interlink_certificate()
        assert new_key.read_bytes() == active_pem
        assert old_key.read_bytes() == b"legacy-key-must-not-win"
    finally:
        env.registry.conn.close()


def test_failed_certificate_issue_keeps_legacy_identity_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path)
    try:
        service = CertificateService(env.config)
        service.cert_dir.mkdir(parents=True)
        old_key = service.cert_dir / "fabric.key"
        old_key.write_bytes(b"pinned-legacy-key")
        old_cert = service.cert_dir / "fabric.crt"
        old_cert.write_bytes(b"legacy-certificate")

        def fail(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("certificate issuance unavailable")

        monkeypatch.setattr(CommandRunner, "run", fail)
        for _ in range(2):
            with pytest.raises(RuntimeError, match="issuance unavailable"):
                service.ensure_interlink_certificate()
            assert old_key.read_bytes() == b"pinned-legacy-key"
            assert old_cert.read_bytes() == b"legacy-certificate"
            assert not (service.cert_dir / "interlink.key").exists()
            assert not (service.cert_dir / "interlink.crt").exists()
    finally:
        env.registry.conn.close()


def test_pre_rename_backup_configuration_and_identity_can_be_staged(tmp_path: Path) -> None:
    from tests.test_hub_backup import certificate_pair

    from kornode.services.backup import BackupService
    from kornode.services.backup_crypto import decrypt, encrypt

    env = Env(tmp_path / "live")
    try:
        env.config.interlink.domain = "kornode.internal"
        for name in ("ca", "server", "fabric"):
            certificate_pair(env.config.cert_path("ca.crt").parent, name)
        env.add(3)
        stored = env.compile(3)
        service = BackupService(env.config)
        password = "test-only-archive-passphrase"
        archive = service.create(password)
        state = json.loads(decrypt(archive, password))
        state["config"]["fabric"] = state["config"].pop("interlink")
        state["config"]["control"]["min_agent_version"] = "2.0.0"
        old_archive = encrypt(json.dumps(state).encode(), password)
        result = service.restore(old_archive, password, target=tmp_path / "staged")
        restored = load_config(result["config_path"], environ={})
        assert restored.interlink.domain == "kornode.internal"
        assert "fabric" not in yaml.safe_load(Path(result["config_path"]).read_text())
        assert (
            restored.cert_path("fabric.key").read_bytes()
            == env.config.cert_path("fabric.key").read_bytes()
        )
        # Restore stages state rather than editing signed bundle bytes or live files.
        with sqlite3.connect(restored.system.data_dir / "registry.db") as conn:
            body, signature = conn.execute(
                "SELECT body, signature FROM bundles WHERE node_id = 3 AND version = ?",
                (stored.version,),
            ).fetchone()
        assert (body, signature) == (stored.body, stored.signature)
        assert result["staged"] and result["restart_required"]
    finally:
        env.registry.conn.close()


@pytest.mark.parametrize("failure", ["command", "invalid", "issuer", "publish"])
def test_legacy_certificate_migration_failure_publishes_no_partial_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import os

    from tests.test_certificates import WritingRunner

    from kornode.services.command import CommandError

    env = Env(tmp_path)
    try:
        runner = WritingRunner()
        service = CertificateService(env.config, runner=runner)
        service.init_ca()
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        old_key, old_cert = service.cert_dir / "fabric.key", service.cert_dir / "fabric.crt"
        old_key.write_bytes(pem)
        old_cert.write_bytes(_certificate(key, "fabric.kornode.internal"))
        originals = old_key.read_bytes(), old_cert.read_bytes()
        run, replace = runner.run, os.replace

        def fail_run(argv: Any, **kwargs: Any) -> CommandResult:
            assert "--generate-privkey" not in argv
            result = run(argv, **kwargs)
            if failure == "command":
                raise CommandError(CommandResult(tuple(argv), 1, "", "issuance failed"))
            target = Path(argv[argv.index("--outfile") + 1])
            if failure == "invalid":
                target.write_bytes(b"invalid certificate")
            elif failure == "issuer":
                # Correct key/SAN, wrong issuer: pair matching alone is not sufficient.
                target.write_bytes(_certificate(key, env.config.interlink.server_name))
            return result

        def fail_publish(source: Any, target: Any) -> None:
            if Path(target) == service.cert_dir / "interlink.crt":
                raise OSError("publication failed")
            replace(source, target)

        with monkeypatch.context() as changes:
            changes.setattr(runner, "run", fail_run)
            if failure == "publish":
                changes.setattr(os, "replace", fail_publish)
            with pytest.raises((CommandError, ValueError, OSError)):
                service.ensure_interlink_certificate()
        assert (old_key.read_bytes(), old_cert.read_bytes()) == originals
        assert not (service.cert_dir / "interlink.key").exists()
        assert not (service.cert_dir / "interlink.crt").exists()
        assert not list(service.cert_dir.glob(".issue-*"))
        assert not list(service.cert_dir.glob(".publish-*"))
        assert not env.config.generated_path("interlink.tmpl").exists()
        assert service.ensure_interlink_certificate()
        assert (service.cert_dir / "interlink.key").read_bytes() == pem
        assert (old_key.read_bytes(), old_cert.read_bytes()) == originals
    finally:
        env.registry.conn.close()


@pytest.mark.parametrize("name", ["fabric", "interlink"])
def test_unsaved_candidate_and_cli_aliases_use_loader_precedence_and_provenance(
    tmp_path: Path, name: str
) -> None:
    from kornode.config.loader import validate_config_data

    path = tmp_path / "config.yaml"
    raw = {name: {"domain": "yaml.example"}, "web": {"admin_password": "${SECRET:ADMIN}"}}
    original = copy.deepcopy(raw)
    path.write_text(yaml.safe_dump(raw))
    overrides = {name: {"client_pool": "10.120.{id}.0/24"}, "node": {"id": 7}}
    original_overrides = copy.deepcopy(overrides)
    environment = {"ADMIN": "not-persisted", "KORNODE_FABRIC__DOMAIN": "env.example"}
    candidate = validate_config_data(raw, path, cli_overrides=overrides, environ=environment)
    assert candidate == load_config(path, cli_overrides=overrides, environ=environment)
    assert candidate.interlink.domain == "yaml.example"
    assert candidate.server.ipv4_network == "10.120.7.0/24"
    assert candidate.internal_dns.listen == "10.120.7.1"
    assert candidate.web.admin_password == "not-persisted"
    assert raw == original
    assert overrides == original_overrides
    assert "not-persisted" not in path.read_text()


def test_cli_rejects_ambiguous_section_aliases(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="both `fabric` and `interlink`"):
        load_config(
            tmp_path / "missing.yaml",
            environ={},
            cli_overrides={"fabric": {"domain": "old.example"}, "interlink": {}},
        )
