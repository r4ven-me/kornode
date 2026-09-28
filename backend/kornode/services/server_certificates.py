from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.cert_pin import certificate_file_pin
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.files import FileManager


@dataclass(frozen=True)
class ServerCertificatePaths:
    server_cert: Path
    server_key: Path
    ca_cert: Path


class ServerCertificateService:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()

    def external_paths(self) -> ServerCertificatePaths:
        base = self.config.system.data_dir / "certs" / "external"
        return ServerCertificatePaths(base / "server.crt", base / "server.key", base / "ca.crt")

    def letsencrypt_paths(self, primary_domain: str | None = None) -> ServerCertificatePaths:
        domain = primary_domain or self._primary_letsencrypt_domain()
        live = self._certbot_config_dir() / "live" / domain
        return ServerCertificatePaths(
            live / "fullchain.pem",
            live / "privkey.pem",
            live / "chain.pem",
        )

    def status(self) -> dict[str, object]:
        active = self.active_paths()
        le = self.config.certificates.letsencrypt
        return {
            "mode": self.config.certificates.mode,
            "ca_name": self.config.certificates.ca_name,
            "active": self._path_status(active),
            "authority": self._authority_status(),
            "external": self._path_status(self.external_paths()),
            "letsencrypt": {
                "enabled": le.enabled,
                "email": le.email,
                "domains": le.domains,
                "renew_reload": le.renew_reload,
                "auto_renew_enabled": le.auto_renew_enabled,
                "auto_renew_interval": le.auto_renew_interval,
                "auto_renew_interval_unit": le.auto_renew_interval_unit,
                "http01_address": le.http01_address,
                "http01_port": le.http01_port,
                "paths": self._path_status(
                    self.letsencrypt_paths(le.domains[0] if le.domains else None)
                )
                if le.domains
                else None,
            },
            "certbot_available": shutil.which("certbot") is not None,
        }

    def server_pin(self) -> dict[str, str]:
        """Pin of the certificate ocserv serves, for other openconnect clients.

        What a remote kornode (or any openconnect) puts in its upstream
        profile's server_cert_pin / --servercert to trust this server.
        """
        path = self.active_paths().server_cert
        if not path.exists():
            raise ValueError(f"server certificate not found: {path}")
        return {"path": str(path), **certificate_file_pin(path).as_dict()}

    def active_paths(self) -> ServerCertificatePaths:
        certs = self.config.certificates
        if certs.mode == "external" and certs.server_cert and certs.server_key and certs.ca_cert:
            return ServerCertificatePaths(certs.server_cert, certs.server_key, certs.ca_cert)
        return ServerCertificatePaths(
            self.config.cert_path("server.crt"),
            self.config.cert_path("server.key"),
            self.config.cert_path("ca.crt"),
        )

    def save_external_material(
        self,
        *,
        server_cert: bytes,
        server_key: bytes,
        ca_cert: bytes,
    ) -> ServerCertificatePaths:
        if not server_cert.strip() or not server_key.strip() or not ca_cert.strip():
            raise ValueError("server certificate, server key and CA certificate must be non-empty")
        paths = self.external_paths()
        self.files.ensure_dir(paths.server_cert.parent, mode=0o700)
        self.files.atomic_write_text(paths.server_cert, server_cert.decode("utf-8"), mode=0o600)
        self.files.atomic_write_text(paths.server_key, server_key.decode("utf-8"), mode=0o600)
        self.files.atomic_write_text(paths.ca_cert, ca_cert.decode("utf-8"), mode=0o600)
        return paths

    def issue_letsencrypt(
        self,
        *,
        email: str,
        domains: list[str],
        staging: bool = False,
        dry_run: bool = False,
    ) -> CommandResult:
        if not email:
            raise ValueError("email is required for Let's Encrypt")
        if not domains:
            raise ValueError("at least one domain is required for Let's Encrypt")
        le = self.config.certificates.letsencrypt
        argv = self._certbot_base_argv()
        argv.extend(
            [
                "certonly",
                "--standalone",
                "--non-interactive",
                "--agree-tos",
                "--email",
                email,
                "--cert-name",
                domains[0],
                "--keep-until-expiring",
                # Keep the key across renewals so pins of this server
                # (openconnect --servercert pin-sha256:...) stay valid.
                "--reuse-key",
                "--http-01-address",
                le.http01_address or self.config.server.listen,
                "--http-01-port",
                str(le.http01_port),
            ]
        )
        if staging:
            argv.append("--test-cert")
        for domain in domains:
            argv.extend(["-d", domain])
        return self.runner.run(argv, timeout=300, dry_run=dry_run, extra_secrets=[email])

    def renew_letsencrypt(self, *, dry_run: bool = False) -> CommandResult:
        le = self.config.certificates.letsencrypt
        argv = [
            *self._certbot_base_argv(),
            "renew",
            "--reuse-key",
            "--http-01-address",
            le.http01_address or self.config.server.listen,
            "--http-01-port",
            str(le.http01_port),
        ]
        return self.runner.run(argv, timeout=300, dry_run=dry_run)

    def _certbot_base_argv(self) -> list[str]:
        return [
            "certbot",
            "--config-dir",
            str(self._certbot_config_dir()),
            "--work-dir",
            str(self.config.system.data_dir / "certbot" / "work"),
            "--logs-dir",
            str(self.config.system.log_dir / "certbot"),
        ]

    def _certbot_config_dir(self) -> Path:
        return self.config.system.data_dir / "certbot" / "config"

    def _primary_letsencrypt_domain(self) -> str:
        domains = self.config.certificates.letsencrypt.domains
        if not domains:
            raise ValueError("certificates.letsencrypt.domains is empty")
        return domains[0]

    def _path_status(self, paths: ServerCertificatePaths) -> dict[str, object]:
        return {
            "server_cert": str(paths.server_cert),
            "server_key": str(paths.server_key),
            "ca_cert": str(paths.ca_cert),
            "server_cert_exists": paths.server_cert.exists(),
            "server_key_exists": paths.server_key.exists(),
            "ca_cert_exists": paths.ca_cert.exists(),
        }

    def _authority_status(self) -> dict[str, object]:
        ca_cert = self.config.cert_path("ca.crt")
        ca_key = self.config.cert_path("ca.key")
        return {
            "ca_cert": str(ca_cert),
            "ca_key": str(ca_key),
            "ca_cert_exists": ca_cert.exists(),
            "ca_key_exists": ca_key.exists(),
        }
