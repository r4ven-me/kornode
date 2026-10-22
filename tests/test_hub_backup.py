from __future__ import annotations

import base64
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from tests.test_bundle_service import Env

from kornode.bundle.signing import key_id, load_or_create_signing_key, verify
from kornode.config.loader import load_config
from kornode.services.agent_models import ManagementError
from kornode.services.backup import BackupService
from kornode.services.backup_crypto import decrypt, encrypt
from kornode.services.backup_state import ArchiveState
from kornode.services.control_management import ControlManagement

PASSWORD = "private-backup-passphrase-δοκιμή"


def certificate_pair(directory: Path, name: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=name == "ca", path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (directory / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / f"{name}.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.fixture
def hub(tmp_path: Path) -> Any:
    env = Env(tmp_path / "original")
    certificate_pair(env.config.cert_path("ca.key").parent, "ca")
    certificate_pair(env.config.cert_path("server.key").parent, "server")
    env.config.system.secrets_dir.mkdir(parents=True)
    env.config.secret_path("ocpasswd").write_text("alice:clients:password-hash\n")
    env.config.system.generated_dir.mkdir(parents=True)
    env.config.identity.config_per_user_dir.mkdir(parents=True)
    (env.config.identity.config_per_user_dir / "alice").write_text("explicit-ipv4 = 10.8.0.2\n")
    env.add(2)
    env.compile(2)
    yield env
    env.registry.conn.close()


def state_of(archive: bytes) -> dict[str, Any]:
    return json.loads(decrypt(archive, PASSWORD))


def mutated(archive: bytes, change: Any) -> bytes:
    state = state_of(archive)
    change(state)
    return encrypt(json.dumps(state).encode(), PASSWORD)


def test_encrypted_wipe_restore_preserves_identity_registry_and_secret(
    hub: Any, tmp_path: Path
) -> None:
    hub.registry.set_external(
        2,
        "office",
        {
            "server": "vpn.example.org",
            "interface": "oc-office",
            "port": 443,
            "auth_type": "password",
            "username": "node2",
        },
        hub.service.encrypt_external_secrets(2, "office", {"password": "upstream-private"}),
    )
    original_key = hub.service.signing_key().public_key()
    original_ca = hub.config.cert_path("ca.key").read_bytes()
    original_master = hub.service.master_key()
    archive = BackupService(hub.config).create(PASSWORD)
    assert all(
        secret not in archive for secret in (PASSWORD.encode(), b"PRIVATE KEY", b"upstream-private")
    )
    target = tmp_path / "restored"
    hub.registry.conn.close()
    shutil.rmtree(hub.config.system.data_dir)
    shutil.rmtree(hub.config.system.secrets_dir)
    result = BackupService(hub.config).restore(archive, PASSWORD, target=target)
    config = load_config(result["config_path"], environ={})
    assert config.cert_path("ca.key").read_bytes() == original_ca
    assert config.secret_path("ocpasswd").read_text().startswith("alice:clients:")
    assert (config.identity.config_per_user_dir / "alice").is_file()
    from kornode.services.agents import AgentService
    from kornode.services.bundle import BundleService

    with AgentService(config).registry() as registry:
        restored = BundleService(
            config, hub_pin="pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        )
        assert restored.master_key() == original_master
        assert key_id(restored.signing_key().public_key()) == key_id(original_key)
        stored = registry.latest_bundle(2)
        verify(stored.body, stored.signature, {key_id(original_key): original_key})
        registry.update_node(2, high_water_version=500)
        assert restored.compile_node(registry, 2, "restore", force=True).version == 501
        external = registry.list_externals(2)[0]
        assert (
            restored._decrypt_external_secrets(2, "office", external.secrets)["password"]
            == "upstream-private"
        )
    assert result["staged"] and result["restart_required"]
    assert target.stat().st_mode & 0o777 == 0o700
    assert (target / "config.yaml").stat().st_mode & 0o777 == 0o600
    assert not list(target.rglob("*.lock"))


@pytest.mark.parametrize("promoted", [False, True])
def test_rotation_custom_outside_keys_survive_backup_and_restore(
    hub: Any, tmp_path: Path, promoted: bool
) -> None:
    clock = [datetime.now(UTC)]
    hub.service._clock = lambda: clock[0]
    custom = tmp_path / "outside" / "signing.pem"
    load_or_create_signing_key(custom)
    hub.config.control.signing_key = custom
    manager = ControlManagement(hub.config, bundles=hub.service, clock=lambda: clock[0])
    manager.rotate()
    if promoted:
        clock[0] += timedelta(days=8)
        manager.rotate()
    rotation = hub.registry.rotation()
    keys = {
        path: Path(path).read_bytes()
        for path in [rotation["active_path"], rotation["next_path"], str(custom)]
    }
    archive = BackupService(hub.config).create(PASSWORD)
    custom.unlink()
    result = BackupService(hub.config).restore(archive, PASSWORD, target=tmp_path / "restored")
    config = load_config(result["config_path"], environ={})
    from kornode.services.agents import AgentService

    with AgentService(config).registry() as registry:
        restored_rotation = registry.rotation()
        assert restored_rotation["started_at"] == rotation["started_at"]
        for field in ("active_path", "next_path"):
            restored_path = Path(restored_rotation[field])
            assert restored_path.is_relative_to(tmp_path / "restored")
            assert restored_path.read_bytes() == keys[rotation[field]]
        assert config.control.signing_key.read_bytes() == keys[str(custom)]


def test_restore_dry_run_does_not_write_tree_or_modify_live_files(hub: Any, tmp_path: Path) -> None:
    service = BackupService(hub.config)
    archive = service.create(PASSWORD)
    before = hub.config.cert_path("ca.key").read_bytes()
    target = tmp_path / "not-created"
    result = service.restore(archive, PASSWORD, target=target, dry_run=True)
    assert result["dry_run"] and not result["staged"] and not target.exists()
    assert hub.config.cert_path("ca.key").read_bytes() == before


@pytest.mark.parametrize("kind", ["password", "tamper", "truncate", "header"])
def test_wrong_password_or_damaged_archive_never_writes(
    hub: Any, tmp_path: Path, kind: str
) -> None:
    service = BackupService(hub.config)
    archive = service.create(PASSWORD)
    password = PASSWORD
    if kind == "password":
        password = "wrong-password-secret"
    if kind == "tamper":
        archive = archive[:-1] + bytes([archive[-1] ^ 1])
    if kind == "truncate":
        archive = archive[:50]
    if kind == "header":
        archive = b"X" + archive[1:]
    target = tmp_path / "bad"
    with pytest.raises(ManagementError) as exc:
        service.restore(archive, password, target=target)
    assert password not in str(exc.value) and not target.exists()


@pytest.mark.parametrize(
    "name",
    ["../outside", "/tmp/outside", "data/../../outside", "data//x", "data/./x", "data\\outside"],
)
def test_unsafe_paths_in_authenticated_archive_refused(hub: Any, tmp_path: Path, name: str) -> None:
    service = BackupService(hub.config)
    archive = service.create(PASSWORD)
    archive = mutated(
        archive, lambda state: state["files"].update({name: next(iter(state["files"].values()))})
    )
    with pytest.raises(ManagementError):
        service.restore(archive, PASSWORD, target=tmp_path / "bad")
    assert not (tmp_path / "bad").exists()


def test_archive_missing_rotation_key_fails_closed(hub: Any, tmp_path: Path) -> None:
    ControlManagement(hub.config, bundles=hub.service).rotate()
    service = BackupService(hub.config)
    archive = service.create(PASSWORD)
    state = state_of(archive)
    missing = state["paths"][hub.registry.rotation()["next_path"]]
    del state["files"][missing]
    with pytest.raises(ManagementError):
        service.restore(
            encrypt(json.dumps(state).encode(), PASSWORD), PASSWORD, target=tmp_path / "bad"
        )


def test_missing_live_key_is_not_regenerated_by_backup(hub: Any) -> None:
    path = hub.config.control.signing_key
    path.unlink()
    with pytest.raises(ManagementError):
        BackupService(hub.config).create(PASSWORD)
    assert not path.exists()


def test_archive_hash_and_identity_mismatch_refused(hub: Any, tmp_path: Path) -> None:
    archive = BackupService(hub.config).create(PASSWORD)

    def change(state: dict[str, Any]) -> None:
        key = state["paths"][str(hub.config.cert_path("ca.key"))]
        state["files"][key]["data"] = base64.b64encode(b"not a key").decode()

    with pytest.raises(ManagementError):
        BackupService(hub.config).restore(
            mutated(archive, change), PASSWORD, target=tmp_path / "bad"
        )


def test_no_clobber_encrypted_output_and_restore_target(hub: Any, tmp_path: Path) -> None:
    service = BackupService(hub.config)
    archive = service.create(PASSWORD)
    output = tmp_path / "backup.knbackup"
    service.publish(output, archive)
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ManagementError):
        service.publish(output, b"different")
    assert output.read_bytes() == archive
    target = tmp_path / "existing"
    target.mkdir()
    (target / "user-file").write_text("keep me")
    with pytest.raises(ManagementError):
        service.restore(archive, PASSWORD, target=target)
    assert (target / "user-file").read_text() == "keep me"


def test_source_symlink_refused_and_runtime_files_excluded(hub: Any, tmp_path: Path) -> None:
    data = hub.config.system.data_dir
    (data / "backups").mkdir()
    (data / "backups" / "old").write_bytes(b"old archive")
    (data / "run").mkdir()
    (data / "run" / "state").write_bytes(b"runtime")
    state = state_of(BackupService(hub.config).create(PASSWORD))
    assert not any(name.startswith(("data/run/", "data/backups/")) for name in state["files"])
    (data / "link").symlink_to(tmp_path / "outside")
    with pytest.raises(ManagementError):
        BackupService(hub.config).create(PASSWORD)


def test_wal_snapshot_is_consistent_and_database_only_snapshot_is_not_backup(hub: Any) -> None:
    hub.registry.update_node(2, description="committed in WAL")
    archive = BackupService(hub.config).create(PASSWORD)
    state = ArchiveState.model_validate(state_of(archive))
    assert "data/registry.db" in state.files
    assert not any(name.endswith(("-wal", "-shm")) for name in state.files)
    assert state.config["system"]["data_dir"] == str(hub.config.system.data_dir)
    with pytest.raises(ManagementError):
        BackupService(hub.config).restore(b"SQLite format 3\x00", PASSWORD)


def test_managed_hook_is_regenerated_with_restored_paths(hub: Any, tmp_path: Path) -> None:
    from kornode.services.config import ConfigService

    hub.config.server.connect_script = hub.config.generated_path("ocserv-connect-script-kornode")
    old_hook = hub.config.server.connect_script
    old_hook.write_text("stale hook with old paths")
    archive = BackupService(hub.config).create(PASSWORD)
    assert not any(
        name.endswith("ocserv-connect-script-kornode") for name in state_of(archive)["files"]
    )
    result = BackupService(hub.config).restore(archive, PASSWORD, target=tmp_path / "restored")
    config = load_config(result["config_path"], environ={})
    assert config.server.connect_script == config.generated_path("ocserv-connect-script-kornode")
    hook = ConfigService().ocserv_renderer.render_connect_script(config)
    assert str(config.identity.config_per_user_dir) in hook
    assert str(hub.config.identity.config_per_user_dir) not in hook


def test_explicit_external_tls_symlink_is_materialized(hub: Any, tmp_path: Path) -> None:
    external = hub.config.system.data_dir / "external"
    certificate_pair(external, "external")
    link = external / "current.crt"
    link.symlink_to(external / "external.crt")
    hub.config.certificates.server_cert = link
    hub.config.certificates.server_key = external / "external.key"
    archive = BackupService(hub.config).create(PASSWORD)
    result = BackupService(hub.config).restore(archive, PASSWORD, target=tmp_path / "restored")
    config = load_config(result["config_path"], environ={})
    assert not config.certificates.server_cert.is_symlink()
    assert config.certificates.server_cert.read_bytes() == link.read_bytes()
    assert config.certificates.server_key.read_bytes() == (external / "external.key").read_bytes()


def test_detected_source_change_refuses_backup(hub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from kornode.services.backup_state import Collector

    original = Collector.verify_unchanged

    def changed(collector: Collector) -> None:
        hub.config.secret_path("ocpasswd").write_text("changed concurrently")
        original(collector)

    monkeypatch.setattr(Collector, "verify_unchanged", changed)
    with pytest.raises(ManagementError) as exc:
        BackupService(hub.config).create(PASSWORD)
    assert exc.value.error == "state_changed"


def test_partial_restore_io_failure_cleans_only_its_tree(
    hub: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kornode.services.files import FileManager

    archive = BackupService(hub.config).create(PASSWORD)
    target = tmp_path / "restored"
    original = FileManager.atomic_write_bytes

    def fail(manager: FileManager, path: Path, content: bytes, mode: int = 0o600) -> None:
        if path.is_relative_to(target):
            raise OSError("simulated disk failure")
        original(manager, path, content, mode)

    monkeypatch.setattr(FileManager, "atomic_write_bytes", fail)
    with pytest.raises(ManagementError):
        BackupService(hub.config).restore(archive, PASSWORD, target=target)
    assert not target.exists() and hub.config.cert_path("ca.key").exists()


def test_newer_database_is_refused_without_touching_original(hub: Any, tmp_path: Path) -> None:
    import hashlib
    import sqlite3

    archive = BackupService(hub.config).create(PASSWORD)
    state = state_of(archive)
    record = state["files"]["data/registry.db"]
    database = tmp_path / "newer.db"
    database.write_bytes(base64.b64decode(record["data"]))
    with sqlite3.connect(database) as conn:
        conn.execute("PRAGMA user_version=999")
    data = database.read_bytes()
    record.update(data=base64.b64encode(data).decode(), sha256=hashlib.sha256(data).hexdigest())
    with pytest.raises(ManagementError):
        BackupService(hub.config).restore(
            encrypt(json.dumps(state).encode(), PASSWORD), PASSWORD, target=tmp_path / "restored"
        )
    assert hub.registry.conn.execute("PRAGMA user_version").fetchone()[0] == 4
    assert not (tmp_path / "restored").exists()


def test_private_key_cannot_be_restored_with_public_mode(hub: Any, tmp_path: Path) -> None:
    archive = BackupService(hub.config).create(PASSWORD)

    def change(state: dict[str, Any]) -> None:
        name = state["paths"][str(hub.config.cert_path("ca.key"))]
        state["files"][name]["mode"] = 0o644

    with pytest.raises(ManagementError):
        BackupService(hub.config).restore(
            mutated(archive, change), PASSWORD, target=tmp_path / "restored"
        )


def test_restore_target_cannot_follow_symlink_parent(hub: Any, tmp_path: Path) -> None:
    archive = BackupService(hub.config).create(PASSWORD)
    (tmp_path / "link").symlink_to(hub.config.system.data_dir, target_is_directory=True)
    with pytest.raises(ManagementError):
        BackupService(hub.config).restore(archive, PASSWORD, target=tmp_path / "link" / "child")
    assert not (hub.config.system.data_dir / "child").exists()


def test_operation_lock_bounds_parallel_kdf_work(hub: Any) -> None:
    service = BackupService(hub.config)
    with service._operation(), pytest.raises(ManagementError) as exc:
        BackupService(hub.config).restore(b"not an archive", PASSWORD)
    assert exc.value.error == "busy"


def test_same_state_encrypts_differently_each_time(hub: Any) -> None:
    service = BackupService(hub.config)
    one, two = service.create(PASSWORD), service.create(PASSWORD)
    assert one != two
    assert state_of(one)["files"] == state_of(two)["files"]


def test_certbot_live_archive_symlink_layout_is_backed_up(hub: Any, tmp_path: Path) -> None:
    """live/<d>/*.pem -> ../../archive/<d>/*N.pem, entirely outside data_dir."""
    letsencrypt = tmp_path / "letsencrypt"
    archive_dir = letsencrypt / "archive" / "hub.example"
    live = letsencrypt / "live" / "hub.example"
    live.mkdir(parents=True)
    certificate_pair(archive_dir, "x")
    (archive_dir / "fullchain1.pem").write_bytes((archive_dir / "x.crt").read_bytes())
    (archive_dir / "privkey1.pem").write_bytes((archive_dir / "x.key").read_bytes())
    (live / "fullchain.pem").symlink_to("../../archive/hub.example/fullchain1.pem")
    (live / "privkey.pem").symlink_to("../../archive/hub.example/privkey1.pem")
    hub.config.certificates.server_cert = live / "fullchain.pem"
    hub.config.certificates.server_key = live / "privkey.pem"
    archive = BackupService(hub.config).create(PASSWORD)
    result = BackupService(hub.config).restore(archive, PASSWORD, target=tmp_path / "restored")
    config = load_config(result["config_path"], environ={})
    assert config.certificates.server_cert.read_bytes() == (live / "fullchain.pem").read_bytes()


def test_default_cert_names_symlinked_into_certs_dir_are_materialized(
    hub: Any, tmp_path: Path
) -> None:
    """certbot deploy hooks often link data_dir/certs/server.{crt,key} to live/."""
    certs = hub.config.cert_path("server.crt").parent
    external = tmp_path / "le"
    certificate_pair(external, "le")
    for name in ("server.crt", "server.key"):
        (certs / name).unlink(missing_ok=True)
    (certs / "server.crt").symlink_to(external / "le.crt")
    (certs / "server.key").symlink_to(external / "le.key")
    hub.config.certificates.server_cert = None
    hub.config.certificates.server_key = None
    archive = BackupService(hub.config).create(PASSWORD)
    result = BackupService(hub.config).restore(archive, PASSWORD, target=tmp_path / "restored")
    config = load_config(result["config_path"], environ={})
    assert config.cert_path("server.crt").read_bytes() == (external / "le.crt").read_bytes()


def test_restored_tree_directories_are_all_private(hub: Any, tmp_path: Path) -> None:
    old = os.umask(0o022)
    try:
        archive = BackupService(hub.config).create(PASSWORD)
        target = tmp_path / "restored"
        BackupService(hub.config).restore(archive, PASSWORD, target=target)
    finally:
        os.umask(old)
    modes = {p: p.stat().st_mode & 0o777 for p in [target, *target.rglob("*")] if p.is_dir()}
    assert modes and all(mode == 0o700 for mode in modes.values()), modes


def test_new_hub_without_master_key_can_be_backed_up(tmp_path: Path) -> None:
    env = Env(tmp_path / "fresh")
    certificate_pair(env.config.cert_path("ca.key").parent, "ca")
    certificate_pair(env.config.cert_path("server.key").parent, "server")
    env.config.system.secrets_dir.mkdir(parents=True)
    master = env.config.system.data_dir / "control" / "master.key"
    try:
        assert not master.exists()
        # Needs the signing key (created by the hub at init) but no compiled bundle.
        load_or_create_signing_key(env.config.control.signing_key)
        BackupService(env.config).create(PASSWORD)
        assert master.exists() and len(master.read_bytes()) == 32
    finally:
        env.registry.conn.close()


def test_missing_master_key_with_sealed_data_is_still_refused(hub: Any) -> None:
    master = hub.config.system.data_dir / "control" / "master.key"
    master.unlink()
    with pytest.raises(ManagementError):
        BackupService(hub.config).create(PASSWORD)
    assert not master.exists()


def test_disk_failure_is_a_503_not_a_validation_error(
    hub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("kornode.services.backup.encrypt", boom)
    with pytest.raises(ManagementError) as exc:
        BackupService(hub.config).create(PASSWORD)
    assert exc.value.status == 503 and exc.value.error == "backup_io"
    assert "space" not in str(exc.value)
