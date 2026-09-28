from __future__ import annotations

import ipaddress
import re
import threading
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.files import FileManager
from kornode.services.users import UserService

_CERT_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)

# Serializes the read-modify-write cycle on revoked.pem, the same hazard
# users.py's _PASSWD_REWRITE_LOCK protects against for ocpasswd: two
# concurrent revocations (e.g. two admin browser tabs) would otherwise each
# read the same original file and the last write would silently discard the
# other's revocation -- generate_crl() would then produce a CRL that doesn't
# actually revoke the certificate that was "lost".
_REVOKED_REWRITE_LOCK = threading.Lock()
_CERT_INFO_FIELDS = {
    "serial": re.compile(r"Serial Number \(hex\):\s*(\S+)"),
    "subject": re.compile(r"Subject:\s*(.+)"),
    "issuer": re.compile(r"Issuer:\s*(.+)"),
    "not_before": re.compile(r"Not Before:\s*(.+)"),
    "not_after": re.compile(r"Not After:\s*(.+)"),
}
_SAN_RE = re.compile(r"(?:DNSname|IPAddress|Email|URI):\s*(\S+)")


class CertificateService:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.users = UserService(config, runner=self.runner, files=self.files)
        self.cert_dir = config.system.data_dir / "certs"

    def user_p12_path(self, username: str) -> Path:
        self.users.validate_username(username)
        return self.cert_dir / "users" / f"{username}.p12"

    def user_cert_path(self, username: str) -> Path:
        self.users.validate_username(username)
        return self.cert_dir / "users" / f"{username}.crt"

    def user_key_path(self, username: str) -> Path:
        self.users.validate_username(username)
        return self.cert_dir / "users" / f"{username}.key"

    def _template_path(self, name: str) -> Path:
        return self.config.system.generated_dir / name

    def _write_template(self, path: Path, content: str) -> Path:
        self.files.ensure_dir(self.config.system.generated_dir)
        self.files.atomic_write_text(path, content, mode=0o600)
        return path

    def _chmod_private_key(self, path: Path, *, dry_run: bool) -> None:
        """certtool writes the key file itself with whatever the process's
        ambient umask allows (e.g. world-readable under a common 022 umask)
        -- protection would otherwise rely entirely on cert_dir's own 0o700
        mode, with no defense-in-depth at the individual file level (e.g. if
        the key is later copied or bind-mounted out of cert_dir)."""
        if not dry_run:
            path.chmod(0o600)

    def init_ca(self, *, dry_run: bool = False) -> list[CommandResult]:
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        ca_key = self.config.cert_path("ca.key")
        ca_crt = self.config.cert_path("ca.crt")
        ca_template = self._write_template(
            self._template_path("ca.tmpl"),
            "\n".join(
                [
                    f"cn = {self.config.certificates.ca_name}",
                    "ca",
                    "cert_signing_key",
                    "expiration_days = 3650",
                    "",
                ]
            ),
        )
        privkey_result = self.runner.run(
            ["certtool", "--generate-privkey", "--outfile", str(ca_key)],
            timeout=60,
            dry_run=dry_run,
        )
        self._chmod_private_key(ca_key, dry_run=dry_run)
        return [
            privkey_result,
            self.runner.run(
                [
                    "certtool",
                    "--generate-self-signed",
                    "--load-privkey",
                    str(ca_key),
                    "--template",
                    str(ca_template),
                    "--outfile",
                    str(ca_crt),
                ],
                timeout=60,
                dry_run=dry_run,
            ),
        ]

    def save_ca_material(self, *, ca_cert: bytes, ca_key: bytes) -> CommandResult:
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        ca_crt_path = self.config.cert_path("ca.crt")
        ca_key_path = self.config.cert_path("ca.key")
        ca_cert_text = ca_cert.decode("utf-8")
        ca_key_text = ca_key.decode("utf-8")
        if "BEGIN CERTIFICATE" not in ca_cert_text:
            raise ValueError("CA certificate must be PEM encoded")
        if "BEGIN" not in ca_key_text or "PRIVATE KEY" not in ca_key_text:
            raise ValueError("CA private key must be PEM encoded")
        self.files.atomic_write_private_text(ca_crt_path, ca_cert_text)
        self.files.atomic_write_private_text(ca_key_path, ca_key_text)
        return CommandResult(
            ("korctl", "certificates", "ca", "upload"),
            0,
            f"written {ca_crt_path}\nwritten {ca_key_path}\n",
            "",
        )

    def regenerate_ca(self, *, dry_run: bool = False) -> list[CommandResult]:
        return self.init_ca(dry_run=dry_run)

    def create_server_certificate(self, *, dry_run: bool = False) -> list[CommandResult]:
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        key = self.config.cert_path("server.key")
        crt = self.config.cert_path("server.crt")
        ca_key = self.config.cert_path("ca.key")
        ca_crt = self.config.cert_path("ca.crt")
        identities = _certificate_identities(self.config.server.cn)
        template = self._write_template(
            self._template_path("server.tmpl"),
            "\n".join(
                [
                    f"cn = {self.config.server.cn}",
                    "tls_www_server",
                    "encryption_key",
                    "signing_key",
                    *identities,
                    "expiration_days = 825",
                    "",
                ]
            ),
        )
        results: list[CommandResult] = []
        # Keep an existing key: remote openconnect clients pin this server by
        # its public key (--servercert pin-sha256:...), so re-issuing the
        # certificate must not rotate the key underneath them. Delete
        # server.key to rotate it deliberately.
        if not key.exists():
            results.append(
                self.runner.run(
                    ["certtool", "--generate-privkey", "--outfile", str(key)],
                    timeout=60,
                    dry_run=dry_run,
                )
            )
            self._chmod_private_key(key, dry_run=dry_run)
        return [
            *results,
            self.runner.run(
                [
                    "certtool",
                    "--generate-certificate",
                    "--load-privkey",
                    str(key),
                    "--load-ca-certificate",
                    str(ca_crt),
                    "--load-ca-privkey",
                    str(ca_key),
                    "--template",
                    str(template),
                    "--outfile",
                    str(crt),
                ],
                timeout=60,
                dry_run=dry_run,
            ),
        ]

    def create_user_certificate(
        self,
        username: str,
        *,
        dry_run: bool = False,
    ) -> list[CommandResult]:
        self.users.validate_username(username)
        self.files.ensure_dir(self.cert_dir / "users", mode=0o700)
        key = self.cert_dir / "users" / f"{username}.key"
        crt = self.cert_dir / "users" / f"{username}.crt"
        ca_key = self.config.cert_path("ca.key")
        ca_crt = self.config.cert_path("ca.crt")
        template = self._write_template(
            self._template_path(f"{username}.tmpl"),
            "\n".join(
                [
                    f"cn = {username}",
                    "tls_www_client",
                    "signing_key",
                    "expiration_days = 825",
                    "",
                ]
            ),
        )
        privkey_result = self.runner.run(
            ["certtool", "--generate-privkey", "--outfile", str(key)],
            timeout=60,
            dry_run=dry_run,
        )
        self._chmod_private_key(key, dry_run=dry_run)
        return [
            privkey_result,
            self.runner.run(
                [
                    "certtool",
                    "--generate-certificate",
                    "--load-privkey",
                    str(key),
                    "--load-ca-certificate",
                    str(ca_crt),
                    "--load-ca-privkey",
                    str(ca_key),
                    "--template",
                    str(template),
                    "--outfile",
                    str(crt),
                ],
                timeout=60,
                dry_run=dry_run,
            ),
        ]

    def create_p12(
        self,
        username: str,
        passphrase: str | None = None,
        *,
        apple_compatible: bool = False,
        dry_run: bool = False,
    ) -> CommandResult:
        self.users.validate_username(username)
        key = self.cert_dir / "users" / f"{username}.key"
        crt = self.cert_dir / "users" / f"{username}.crt"
        out = self.user_p12_path(username)
        argv = [
            "certtool",
            "--to-p12",
            "--outder",
            "--p12-name",
            username,
            "--load-certificate",
            str(crt),
            "--load-privkey",
            str(key),
            "--outfile",
            str(out),
        ]
        if apple_compatible:
            argv.extend(["--pkcs-cipher", "3des-pkcs12", "--hash", "SHA1"])
        else:
            argv.extend(["--pkcs-cipher", "aes-256"])
        if passphrase:
            argv.extend(["--password", passphrase])
        else:
            argv.append("--empty-password")
        return self.runner.run(
            argv,
            timeout=60,
            dry_run=dry_run,
            extra_secrets=[passphrase or ""],
        )

    def revoke_user_certificate(self, username: str, *, dry_run: bool = False) -> CommandResult:
        self.users.validate_username(username)
        cert = self.cert_dir / "users" / f"{username}.crt"
        marker = cert.read_text(encoding="utf-8") if cert.exists() else ""
        if marker:
            self.append_revoked_certificate(marker, dry_run=dry_run)
        return self.generate_crl(dry_run=dry_run)

    def revoke_certificate_pem(
        self,
        certificate: bytes | str,
        *,
        dry_run: bool = False,
    ) -> CommandResult:
        text = certificate.decode("utf-8") if isinstance(certificate, bytes) else certificate
        if "BEGIN CERTIFICATE" not in text or "END CERTIFICATE" not in text:
            raise ValueError("revoked certificate must be PEM encoded")
        self.append_revoked_certificate(text, dry_run=dry_run)
        return self.generate_crl(dry_run=dry_run)

    def append_revoked_certificate(self, certificate_pem: str, *, dry_run: bool = False) -> None:
        revoked = self.cert_dir / "revoked.pem"
        marker = certificate_pem.strip() + "\n"
        with _REVOKED_REWRITE_LOCK:
            existing = revoked.read_text(encoding="utf-8") if revoked.exists() else ""
            if marker and marker not in existing and not dry_run:
                self.files.ensure_dir(revoked.parent, mode=0o700)
                self.files.atomic_write_text(revoked, existing + marker, mode=0o600)

    def list_revoked_certificates(self) -> list[dict[str, str]]:
        revoked = self.cert_dir / "revoked.pem"
        if not revoked.exists():
            return []
        content = revoked.read_text(encoding="utf-8")
        entries = []
        for cert_pem in _CERT_PEM_RE.findall(content):
            result = self.runner.run(
                ["certtool", "--certificate-info"],
                input_text=cert_pem,
                timeout=10,
                check=False,
            )
            entries.append(_parse_certificate_info(result.stdout))
        return entries

    def certificate_info(self, pem: str) -> dict[str, object]:
        result = self.runner.run(
            ["certtool", "--certificate-info"],
            input_text=pem,
            timeout=10,
            check=False,
        )
        info: dict[str, object] = dict(_parse_certificate_info(result.stdout))
        info["sans"] = _SAN_RE.findall(result.stdout)
        return info

    def certificate_info_from_path(self, path: Path) -> dict[str, object] | None:
        if not path.exists():
            return None
        return self.certificate_info(path.read_text(encoding="utf-8"))

    def generate_crl(self, *, dry_run: bool = False) -> CommandResult:
        ca_key = self.config.cert_path("ca.key")
        ca_crt = self.config.cert_path("ca.crt")
        revoked = self.cert_dir / "revoked.pem"
        crl = self.cert_dir / "crl.pem"
        # Without --template, certtool falls back to its interactive prompts
        # ("The next CRL will be issued in (days):" among them) -- with no
        # TTY/stdin feeding an answer, it just hangs until CommandRunner's
        # timeout kills it. crl_next_update supplies that answer up front.
        template = self._write_template(
            self._template_path("crl.tmpl"),
            "crl_next_update = 30\n",
        )
        return self.runner.run(
            [
                "certtool",
                "--generate-crl",
                "--load-ca-privkey",
                str(ca_key),
                "--load-ca-certificate",
                str(ca_crt),
                "--load-certificate",
                str(revoked),
                "--template",
                str(template),
                "--outfile",
                str(crl),
            ],
            timeout=60,
            dry_run=dry_run,
        )


def _certificate_identities(value: str) -> list[str]:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return [f"dns_name = {value}"]
    return [f"ip_address = {value}"]


def _parse_certificate_info(output: str) -> dict[str, str]:
    entry = {field: "" for field in _CERT_INFO_FIELDS}
    for field, pattern in _CERT_INFO_FIELDS.items():
        match = pattern.search(output)
        if match:
            entry[field] = match.group(1).strip()
    return entry
