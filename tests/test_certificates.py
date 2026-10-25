from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from kornode.config.models import AppConfig
from kornode.services.certificates import CertificateService
from kornode.services.command import CommandResult, CommandRunner


class CommandCall(TypedDict):
    argv: tuple[str, ...]
    timeout: int
    cwd: str | None
    input_text: str | None
    env: Mapping[str, str] | None
    check: bool
    dry_run: bool
    extra_secrets: tuple[str, ...]


class RecordingRunner(CommandRunner):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[CommandCall] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        cwd: str | None = None,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
        **_kwargs: Any,
    ) -> CommandResult:
        self.calls.append(
            CommandCall(
                argv=tuple(argv),
                timeout=timeout,
                cwd=cwd,
                input_text=input_text,
                env=env,
                check=check,
                dry_run=dry_run,
                extra_secrets=tuple(extra_secrets or ()),
            )
        )
        return CommandResult(tuple(argv), 0, "", "", dry_run=dry_run)


def _key_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _certificate(
    key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool = True,
    issuer_key: ec.EllipticCurvePrivateKey | None = None,
    issuer: x509.Name | None = None,
) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "audit test")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key or key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


class WritingRunner(RecordingRunner):
    """Produce real, matching crypto fixtures without executing certtool."""

    def run(self, argv: Sequence[str], **kwargs: Any) -> CommandResult:
        result = super().run(argv, **kwargs)
        if result.dry_run or "--outfile" not in argv:
            return result
        out = Path(argv[argv.index("--outfile") + 1])
        if "--generate-crl" not in argv:
            assert out.stat().st_mode & 0o777 == 0o600
        if "--generate-privkey" in argv:
            out.write_bytes(_key_bytes(ec.generate_private_key(ec.SECP256R1())))
        elif "--generate-crl" in argv:
            out.write_text("test CRL")
        else:
            key = serialization.load_pem_private_key(
                Path(argv[argv.index("--load-privkey") + 1]).read_bytes(),
                password=None,
            )
            assert isinstance(key, ec.EllipticCurvePrivateKey)
            if "--generate-self-signed" in argv:
                out.write_bytes(_certificate(key))
            else:
                issuer_key = serialization.load_pem_private_key(
                    Path(argv[argv.index("--load-ca-privkey") + 1]).read_bytes(),
                    password=None,
                )
                assert isinstance(issuer_key, ec.EllipticCurvePrivateKey)
                issuer = x509.load_pem_x509_certificate(
                    Path(argv[argv.index("--load-ca-certificate") + 1]).read_bytes(),
                ).subject
                out.write_bytes(_certificate(key, ca=False, issuer_key=issuer_key, issuer=issuer))
        return result


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "log_dir": tmp_path / "logs",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )


def test_create_p12_uses_non_interactive_passphrase_options(tmp_path: Path) -> None:
    runner = RecordingRunner()
    service = CertificateService(_config(tmp_path), runner=runner)

    result = service.create_p12(
        "alice",
        "bundle-secret",
        apple_compatible=True,
        dry_run=True,
    )

    argv = runner.calls[0]["argv"]
    assert result.dry_run is True
    assert argv == (
        "certtool",
        "--to-p12",
        "--outder",
        "--p12-name",
        "alice",
        "--load-certificate",
        str(tmp_path / "data" / "certs" / "users" / "alice.crt"),
        "--load-privkey",
        str(tmp_path / "data" / "certs" / "users" / "alice.key"),
        "--outfile",
        str(tmp_path / "data" / "certs" / "users" / "alice.p12"),
        "--pkcs-cipher",
        "3des-pkcs12",
        "--hash",
        "SHA1",
        "--password",
        "bundle-secret",
    )
    assert runner.calls[0]["extra_secrets"] == ("bundle-secret",)


def test_create_p12_uses_aes_cipher_by_default(tmp_path: Path) -> None:
    runner = RecordingRunner()
    service = CertificateService(_config(tmp_path), runner=runner)

    service.create_p12("alice", "bundle-secret", dry_run=True)

    argv = runner.calls[0]["argv"]
    assert "--pkcs-cipher" in argv
    assert argv[argv.index("--pkcs-cipher") + 1] == "aes-256"
    assert "--hash" not in argv


def test_create_p12_uses_explicit_empty_password_when_no_passphrase(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner()
    service = CertificateService(_config(tmp_path), runner=runner)

    service.create_p12("alice", dry_run=True)

    argv = runner.calls[0]["argv"]
    assert "--empty-password" in argv
    assert "--password" not in argv


def test_server_certificate_template_contains_dns_san(tmp_path: Path) -> None:
    config = _config(tmp_path)
    service = CertificateService(config, runner=RecordingRunner())

    service.create_server_certificate(dry_run=True)

    template = config.generated_path("server.tmpl").read_text(encoding="utf-8")
    assert "cn = vpn.example.com" in template
    assert "dns_name = vpn.example.com" in template


def test_init_ca_chmods_the_private_key_to_owner_only(tmp_path: Path) -> None:
    # Regression test: certtool writes the key file with whatever the
    # process's ambient umask allows (world-readable under a common 022
    # umask) -- protection previously relied entirely on cert_dir's own
    # 0o700 mode, with no defense-in-depth at the individual file level.
    config = _config(tmp_path)
    service = CertificateService(config, runner=WritingRunner())

    service.init_ca()

    mode = config.cert_path("ca.key").stat().st_mode & 0o777
    assert mode == 0o600


def test_create_user_certificate_chmods_the_private_key_to_owner_only(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    service = CertificateService(config, runner=WritingRunner())

    service.init_ca()
    service.create_user_certificate("alice")

    mode = (config.system.data_dir / "certs" / "users" / "alice.key").stat().st_mode & 0o777
    assert mode == 0o600


def test_init_ca_dry_run_does_not_touch_a_nonexistent_key_file(tmp_path: Path) -> None:
    # dry_run never actually writes ca.key -- chmod-ing it must not raise.
    config = _config(tmp_path)
    service = CertificateService(config, runner=WritingRunner())

    service.init_ca(dry_run=True)

    assert not config.cert_path("ca.key").exists()


def test_save_ca_material_writes_private_files(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )

    key = ec.generate_private_key(ec.SECP256R1())
    result = CertificateService(config).save_ca_material(
        ca_cert=_certificate(key),
        ca_key=_key_bytes(key),
    )

    assert result.returncode == 0
    assert (
        config.cert_path("ca.crt")
        .read_text(encoding="utf-8")
        .startswith("-----BEGIN CERTIFICATE-----")
    )
    assert (
        config.cert_path("ca.key")
        .read_text(encoding="utf-8")
        .startswith("-----BEGIN PRIVATE KEY-----")
    )


def test_revoke_certificate_pem_appends_revoked_and_generates_crl(tmp_path: Path) -> None:
    class Runner(CommandRunner):
        def run(
            self,
            argv: Sequence[str],
            *,
            timeout: int = 30,
            input_text: str | None = None,
            env: Mapping[str, str] | None = None,
            check: bool = True,
            dry_run: bool = False,
            extra_secrets: Sequence[str] | None = None,
            **_kwargs: Any,
        ) -> CommandResult:
            del timeout, input_text, env, check, dry_run, extra_secrets
            return CommandResult(tuple(argv), 0, "crl\n", "")

    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    service = CertificateService(config, runner=Runner())

    result = service.revoke_certificate_pem(
        b"-----BEGIN CERTIFICATE-----\nuser\n-----END CERTIFICATE-----\n"
    )

    assert result.returncode == 0
    assert "user" in (tmp_path / "data" / "certs" / "revoked.pem").read_text(encoding="utf-8")


def test_concurrent_revocations_do_not_lose_changes(tmp_path: Path) -> None:
    # Regression test: append_revoked_certificate() read-modify-writes the
    # whole revoked.pem file, and uvicorn serves API requests on parallel
    # threads -- without a lock, concurrent revocations of different
    # certificates would each read the same original file and the last
    # write would silently discard the others, so generate_crl() would
    # produce a CRL that doesn't actually revoke the "lost" certificate.
    from concurrent.futures import ThreadPoolExecutor

    config = _config(tmp_path)
    service = CertificateService(config, runner=RecordingRunner())
    certs = [f"-----BEGIN CERTIFICATE-----\nuser{i}\n-----END CERTIFICATE-----\n" for i in range(8)]

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(service.append_revoked_certificate, cert) for cert in certs]
        for future in futures:
            future.result()

    revoked = config.cert_path("revoked.pem").read_text(encoding="utf-8")
    for i in range(8):
        assert f"user{i}" in revoked


def test_list_revoked_certificates_empty_when_no_revocations(tmp_path: Path) -> None:
    service = CertificateService(_config(tmp_path), runner=RecordingRunner())

    assert service.list_revoked_certificates() == []


def test_list_revoked_certificates_parses_one_entry_per_pem_block(tmp_path: Path) -> None:
    certtool_info = {
        "alice": (
            "\tSerial Number (hex): 01\n"
            "\tSubject: CN=alice\n"
            "\t\tNot Before: Mon Jan 01 00:00:00 UTC 2024\n"
            "\t\tNot After: Wed Jan 01 00:00:00 UTC 2025\n"
        ),
        "bob": (
            "\tSerial Number (hex): 02\n"
            "\tSubject: CN=bob\n"
            "\t\tNot Before: Tue Feb 02 00:00:00 UTC 2024\n"
            "\t\tNot After: Thu Feb 02 00:00:00 UTC 2025\n"
        ),
    }

    class Runner(CommandRunner):
        def run(
            self,
            argv: Sequence[str],
            *,
            timeout: int = 30,
            input_text: str | None = None,
            env: Mapping[str, str] | None = None,
            check: bool = True,
            dry_run: bool = False,
            extra_secrets: Sequence[str] | None = None,
            **_kwargs: Any,
        ) -> CommandResult:
            del timeout, env, check, dry_run, extra_secrets
            assert input_text is not None
            who = "alice" if "alice" in input_text else "bob"
            return CommandResult(tuple(argv), 0, certtool_info[who], "")

    config = _config(tmp_path)
    revoked = tmp_path / "data" / "certs" / "revoked.pem"
    revoked.parent.mkdir(parents=True)
    revoked.write_text(
        "-----BEGIN CERTIFICATE-----\nalice\n-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\nbob\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    service = CertificateService(config, runner=Runner())

    entries = service.list_revoked_certificates()

    assert entries == [
        {
            "serial": "01",
            "subject": "CN=alice",
            "issuer": "",
            "not_before": "Mon Jan 01 00:00:00 UTC 2024",
            "not_after": "Wed Jan 01 00:00:00 UTC 2025",
        },
        {
            "serial": "02",
            "subject": "CN=bob",
            "issuer": "",
            "not_before": "Tue Feb 02 00:00:00 UTC 2024",
            "not_after": "Thu Feb 02 00:00:00 UTC 2025",
        },
    ]


def test_certificate_info_parses_subject_issuer_and_sans(tmp_path: Path) -> None:
    certtool_output = (
        "\tSerial Number (hex): 0a\n"
        "\tIssuer: CN=Korvus Node CA\n"
        "\tSubject: CN=vpn.example.com\n"
        "\t\tNot Before: Mon Jan 01 00:00:00 UTC 2024\n"
        "\t\tNot After: Wed Jan 01 00:00:00 UTC 2025\n"
        "\t\tX509v3 Subject Alternative Name (not critical):\n"
        "\t\t\tDNSname: vpn.example.com\n"
        "\t\t\tIPAddress: 10.100.1.1\n"
    )

    class Runner(CommandRunner):
        def run(
            self,
            argv: Sequence[str],
            *,
            timeout: int = 30,
            input_text: str | None = None,
            env: Mapping[str, str] | None = None,
            check: bool = True,
            dry_run: bool = False,
            extra_secrets: Sequence[str] | None = None,
            **_kwargs: Any,
        ) -> CommandResult:
            del timeout, env, check, dry_run, extra_secrets
            assert input_text is not None
            return CommandResult(tuple(argv), 0, certtool_output, "")

    service = CertificateService(_config(tmp_path), runner=Runner())

    info = service.certificate_info("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n")

    assert info == {
        "serial": "0a",
        "subject": "CN=vpn.example.com",
        "issuer": "CN=Korvus Node CA",
        "not_before": "Mon Jan 01 00:00:00 UTC 2024",
        "not_after": "Wed Jan 01 00:00:00 UTC 2025",
        "sans": ["vpn.example.com", "10.100.1.1"],
    }


def test_certificate_info_from_path_returns_none_when_missing(tmp_path: Path) -> None:
    service = CertificateService(_config(tmp_path), runner=RecordingRunner())

    assert service.certificate_info_from_path(tmp_path / "missing.crt") is None


def test_server_certificate_reuses_an_existing_key(tmp_path: Path) -> None:
    # Remote openconnect clients pin this server by its public key, so
    # re-issuing the certificate must keep the key.
    config = _config(tmp_path)
    key = config.cert_path("server.key")
    key.parent.mkdir(parents=True, exist_ok=True)
    original_key = _key_bytes(ec.generate_private_key(ec.SECP256R1()))
    key.write_bytes(original_key)
    runner = WritingRunner()
    service = CertificateService(config, runner=runner)
    service.init_ca()
    runner.calls.clear()
    service.create_server_certificate()

    commands = [call["argv"] for call in runner.calls]
    assert not any("--generate-privkey" in argv for argv in commands)
    assert any("--generate-certificate" in argv for argv in commands)
    assert key.read_bytes() == original_key


def test_server_certificate_generates_a_key_when_missing(tmp_path: Path) -> None:
    runner = RecordingRunner()

    CertificateService(_config(tmp_path), runner=runner).create_server_certificate(dry_run=True)

    assert any("--generate-privkey" in call["argv"] for call in runner.calls)


@pytest.mark.parametrize("existing", ["ca.key", "ca.crt"])
def test_init_ca_refuses_partial_material(tmp_path: Path, existing: str) -> None:
    config = _config(tmp_path)
    path = config.cert_path(existing)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"original")
    runner = RecordingRunner()
    with pytest.raises(ValueError, match="incomplete CA state"):
        CertificateService(config, runner=runner).init_ca()
    assert path.read_bytes() == b"original"
    assert runner.calls == []


def test_init_ca_is_idempotent_and_validates_existing_pair(tmp_path: Path) -> None:
    config = _config(tmp_path)
    runner = WritingRunner()
    service = CertificateService(config, runner=runner)
    service.init_ca()
    original = config.cert_path("ca.key").read_bytes()
    runner.calls.clear()
    assert service.init_ca() == []
    assert not runner.calls
    assert config.cert_path("ca.key").read_bytes() == original
    config.cert_path("ca.crt").write_text("invalid")
    with pytest.raises(ValueError, match="invalid certificate/private key pair"):
        service.init_ca()
    assert config.cert_path("ca.key").read_bytes() == original


@pytest.mark.parametrize(
    "operation,stem",
    [
        ("ca", "ca"),
        ("server", "server"),
        ("user", "users/alice"),
        ("control", "control"),
        ("interlink", "interlink"),
    ],
)
@pytest.mark.parametrize("failure", ["key", "certificate", "invalid", "publish"])
def test_generation_failures_preserve_original_pairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    stem: str,
    failure: str,
) -> None:
    import os

    from kornode.services.command import CommandError

    config = _config(tmp_path)
    runner = WritingRunner()
    service = CertificateService(config, runner=runner)
    service.init_ca()

    def issue() -> object:
        if operation == "ca":
            return service.regenerate_ca()
        if operation == "server":
            return service.create_server_certificate()
        if operation == "user":
            return service.create_user_certificate("alice")
        if operation == "control":
            return service.ensure_control_certificate("10.100.1.1")
        return service.ensure_interlink_certificate()

    issue()
    key, crt = config.cert_path(stem + ".key"), config.cert_path(stem + ".crt")
    # Key generation is skipped for pinned listener keys; exercise a partial
    # original state there too, without deleting the surviving certificate.
    if failure == "key" and operation in {"server", "control", "interlink"}:
        key.unlink()
    original = {path: path.read_bytes() if path.exists() else None for path in (key, crt)}
    run = runner.run

    def fail_run(argv: Sequence[str], **kwargs: Any) -> CommandResult:
        target = (
            "--generate-privkey"
            if failure == "key"
            else ("--generate-self-signed" if operation == "ca" else "--generate-certificate")
        )
        if target in argv and failure in {"key", "certificate", "invalid"}:
            out = Path(argv[argv.index("--outfile") + 1])
            out.write_text("partial-invalid-output")
            if failure == "invalid":
                return CommandResult(tuple(argv), 0, "", "")
            raise CommandError(CommandResult(tuple(argv), 1, "", "injected failure"))
        return run(argv, **kwargs)

    monkeypatch.setattr(runner, "run", fail_run)
    replace = os.replace

    def fail_replace(src: Path, dst: Path) -> None:
        if Path(dst) == crt:
            raise OSError("injected publish failure")
        replace(src, dst)

    if failure == "publish":
        monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises((CommandError, ValueError, OSError)):
        issue()
    for path, data in original.items():
        assert (path.read_bytes() if path.exists() else None) == data
    assert not list(key.parent.glob(".issue-*"))
    assert not list(key.parent.glob(".publish-*"))


def test_ca_upload_rejects_mismatched_pair_without_writing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    service = CertificateService(config, runner=WritingRunner())
    service.init_ca()
    before = {name: config.cert_path(name).read_bytes() for name in ("ca.key", "ca.crt")}
    key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError, match="invalid certificate/private key pair"):
        service.save_ca_material(ca_key=_key_bytes(key), ca_cert=_certificate(other_key))
    assert {name: config.cert_path(name).read_bytes() for name in before} == before


def test_only_explicit_regeneration_rotates_an_existing_ca(tmp_path: Path) -> None:
    config = _config(tmp_path)
    service = CertificateService(config, runner=WritingRunner())
    service.init_ca()
    original = config.cert_path("ca.key").read_bytes()
    service.regenerate_ca()
    assert config.cert_path("ca.key").read_bytes() != original
    CertificateService._validate_pair(
        config.cert_path("ca.key").read_bytes(),
        config.cert_path("ca.crt").read_bytes(),
        ca=True,
    )


@pytest.mark.parametrize("failure", ["none", "command", "invalid", "publish"])
def test_p12_export_is_validated_and_atomic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    from cryptography.hazmat.primitives.serialization import pkcs12

    from kornode.services.command import CommandError
    from kornode.services.files import FileManager

    config = _config(tmp_path)
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = x509.load_pem_x509_certificate(_certificate(key, ca=False))
    data = pkcs12.serialize_key_and_certificates(
        b"alice",
        key,
        certificate,
        None,
        serialization.BestAvailableEncryption(b"bundle-secret"),
    )

    class ExportRunner(CommandRunner):
        def run(self, argv: Sequence[str], **_kwargs: Any) -> CommandResult:
            out = Path(argv[argv.index("--outfile") + 1])
            assert out.stat().st_mode & 0o777 == 0o600
            out.write_bytes(b"invalid" if failure == "invalid" else data)
            result = CommandResult(("export",), 1 if failure == "command" else 0, "", "")
            if not result.ok:
                raise CommandError(result)
            return result

    service = CertificateService(config, runner=ExportRunner())
    out = service.user_p12_path("alice")
    out.parent.mkdir(parents=True)
    out.write_bytes(b"original")
    write = FileManager.atomic_write_bytes

    def fail_publish(self: FileManager, path: Path, data: bytes, mode: int = 0o600) -> None:
        if path == out:
            raise OSError("publish failed")
        write(self, path, data, mode)

    if failure == "publish":
        monkeypatch.setattr(FileManager, "atomic_write_bytes", fail_publish)
    if failure == "none":
        assert service.create_p12("alice", "bundle-secret").ok
        assert out.read_bytes() == data
        assert out.stat().st_mode & 0o777 == 0o600
    else:
        with pytest.raises((CommandError, ValueError, OSError)):
            service.create_p12("alice", "bundle-secret")
        assert out.read_bytes() == b"original"
    assert not list(out.parent.glob(".p12-*"))
