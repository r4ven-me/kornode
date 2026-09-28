from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.server_certificates import ServerCertificateService


class RecordingRunner(CommandRunner):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, ...]] = []

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
    ) -> CommandResult:
        del timeout, cwd, input_text, env, check, extra_secrets
        call = tuple(argv)
        self.calls.append(call)
        return CommandResult(call, 0, "", "", dry_run=dry_run)


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


def test_external_certificate_upload_writes_private_files(tmp_path: Path) -> None:
    service = ServerCertificateService(_config(tmp_path))

    paths = service.save_external_material(
        server_cert=b"server cert\n",
        server_key=b"server key\n",
        ca_cert=b"ca cert\n",
    )

    assert paths.server_cert.read_text(encoding="utf-8") == "server cert\n"
    assert paths.server_key.read_text(encoding="utf-8") == "server key\n"
    assert paths.ca_cert.read_text(encoding="utf-8") == "ca cert\n"
    assert paths.server_key.stat().st_mode & 0o777 == 0o600


def test_letsencrypt_issue_uses_persistent_certbot_dirs(tmp_path: Path) -> None:
    runner = RecordingRunner()
    config = _config(tmp_path)

    result = ServerCertificateService(config, runner=runner).issue_letsencrypt(
        email="admin@example.com",
        domains=["vpn.example.com", "vpn2.example.com"],
        staging=True,
        dry_run=True,
    )

    assert result.dry_run is True
    argv = runner.calls[0]
    assert argv[:7] == (
        "certbot",
        "--config-dir",
        str(tmp_path / "data" / "certbot" / "config"),
        "--work-dir",
        str(tmp_path / "data" / "certbot" / "work"),
        "--logs-dir",
        str(tmp_path / "logs" / "certbot"),
    )
    assert "--standalone" in argv
    assert "--test-cert" in argv
    assert (argv[-4], argv[-3]) == ("-d", "vpn.example.com")
    assert (argv[-2], argv[-1]) == ("-d", "vpn2.example.com")


def test_letsencrypt_issue_defaults_http01_address_to_server_listen(tmp_path: Path) -> None:
    runner = RecordingRunner()
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "log_dir": tmp_path / "logs",
                "secrets_dir": tmp_path / "secrets",
            },
            "server": {"listen": "192.0.2.10"},
        }
    )

    ServerCertificateService(config, runner=runner).issue_letsencrypt(
        email="admin@example.com",
        domains=["vpn.example.com"],
        dry_run=True,
    )

    argv = runner.calls[0]
    address_index = argv.index("--http-01-address")
    assert argv[address_index + 1] == "192.0.2.10"
    port_index = argv.index("--http-01-port")
    assert argv[port_index + 1] == "80"


def test_letsencrypt_issue_and_renew_use_custom_http01_address_and_port(tmp_path: Path) -> None:
    runner = RecordingRunner()
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "log_dir": tmp_path / "logs",
                "secrets_dir": tmp_path / "secrets",
            },
            "certificates": {
                "letsencrypt": {"http01_address": "203.0.113.5", "http01_port": 8080},
            },
        }
    )
    service = ServerCertificateService(config, runner=runner)

    service.issue_letsencrypt(email="admin@example.com", domains=["vpn.example.com"], dry_run=True)
    issue_argv = runner.calls[0]
    assert issue_argv[issue_argv.index("--http-01-address") + 1] == "203.0.113.5"
    assert issue_argv[issue_argv.index("--http-01-port") + 1] == "8080"

    service.renew_letsencrypt(dry_run=True)
    renew_argv = runner.calls[1]
    assert renew_argv[renew_argv.index("--http-01-address") + 1] == "203.0.113.5"
    assert renew_argv[renew_argv.index("--http-01-port") + 1] == "8080"
    assert "renew" in renew_argv
    # Keeping the key keeps this server's openconnect pin stable across renewals.
    assert "--reuse-key" in issue_argv
    assert "--reuse-key" in renew_argv
