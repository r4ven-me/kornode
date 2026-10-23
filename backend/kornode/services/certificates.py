from __future__ import annotations

import fcntl
import ipaddress
import os
import re
import secrets
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.files import FileManager
from kornode.services.users import UserService

_CERT_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

# Serializes the read-modify-write cycle on revoked.pem, the same hazard
# users.py's _PASSWD_REWRITE_LOCK protects against for ocpasswd: two
# concurrent revocations (e.g. two admin browser tabs) would otherwise each
# read the same original file and the last write would silently discard the
# other's revocation -- generate_crl() would then produce a CRL that doesn't
# actually revoke the certificate that was "lost".
_REVOKED_REWRITE_LOCK = threading.Lock()
_CERT_MATERIAL_LOCK = threading.RLock()
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

    @contextmanager
    def _material_lock(self) -> Iterator[None]:
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        with _CERT_MATERIAL_LOCK, (self.cert_dir / ".material.lock").open("a") as lock:
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    @staticmethod
    def _validate_pair(key_data: bytes, cert_data: bytes, *, ca: bool = False) -> x509.Certificate:
        try:
            key = serialization.load_pem_private_key(key_data, password=None)
            certificate = x509.load_pem_x509_certificate(cert_data)
            encoding = serialization.Encoding.DER
            fmt = serialization.PublicFormat.SubjectPublicKeyInfo
            if key.public_key().public_bytes(
                encoding, fmt
            ) != certificate.public_key().public_bytes(encoding, fmt):
                raise ValueError("key mismatch")
            if (
                ca
                and not certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value.ca
            ):
                raise ValueError("not a CA")
        except (ValueError, TypeError, x509.ExtensionNotFound):
            # Parser errors may include material supplied by a caller; do not expose them.
            raise ValueError("invalid certificate/private key pair") from None
        return certificate

    def _publish_pair(self, key: Path, crt: Path, key_data: bytes, cert_data: bytes) -> None:
        """Per-file atomic publication with rollback on a failed second replace.

        Fixed legacy filenames cannot provide crash-atomic two-file replacement.
        Keep recovery copies if rollback itself fails; never truncate live material.
        """
        import shutil

        work = Path(tempfile.mkdtemp(prefix=".publish-", dir=key.parent))
        cleanup = True
        replaced: list[Path] = []
        originals: dict[Path, Path | None] = {}
        try:
            for path, data in ((key, key_data), (crt, cert_data)):
                backup = work / (path.name + ".original")
                originals[path] = backup if path.exists() else None
                if path.exists():
                    self.files.atomic_write_bytes(backup, path.read_bytes())
                self.files.atomic_write_bytes(work / path.name, data)
            try:
                for path in (key, crt):
                    os.replace(work / path.name, path)
                    replaced.append(path)
            except OSError:
                try:
                    for path in reversed(replaced):
                        recovery = originals[path]
                        if recovery is None:
                            path.unlink()
                        else:
                            os.replace(recovery, path)
                except OSError:
                    cleanup = False
                    raise RuntimeError(
                        f"certificate rollback failed; recovery files: {work}"
                    ) from None
                raise
        finally:
            if cleanup:
                shutil.rmtree(work)

    def _generate_pair(
        self,
        key: Path,
        crt: Path,
        template: Path,
        *,
        reuse_key: bool = False,
        self_signed: bool = False,
        ecc: bool = False,
        replace: bool = True,
        dry_run: bool = False,
    ) -> list[CommandResult]:
        # Serialize API requests AND independent CLI processes sharing the certificate directory.
        self.files.ensure_dir(key.parent, mode=0o700)
        with self._material_lock():
            if not replace and (key.exists() or crt.exists()):
                if not key.exists() or not crt.exists():
                    raise ValueError(
                        "incomplete CA state; restore the missing file "
                        "or explicitly regenerate the CA"
                    )
                self._validate_pair(key.read_bytes(), crt.read_bytes(), ca=True)
                return []
            with tempfile.TemporaryDirectory(prefix=".issue-", dir=key.parent) as directory:
                stage_key = key if dry_run else Path(directory) / key.name
                stage_crt = crt if dry_run else Path(directory) / crt.name
                keep_key = reuse_key and key.exists()
                results: list[CommandResult] = []
                if not dry_run:
                    self.files.atomic_write_bytes(stage_key, key.read_bytes() if keep_key else b"")
                    self.files.atomic_write_bytes(stage_crt, b"")
                if not keep_key:
                    argv = ["certtool", "--generate-privkey"]
                    if ecc:
                        argv.append("--ecc")
                    results.append(
                        self.runner.run(
                            [*argv, "--outfile", str(stage_key)],
                            timeout=60,
                            dry_run=dry_run,
                        )
                    )
                argv = [
                    "certtool",
                    "--generate-self-signed" if self_signed else "--generate-certificate",
                    "--load-privkey",
                    str(stage_key),
                ]
                if not self_signed:
                    argv.extend(
                        [
                            "--load-ca-certificate",
                            str(self.config.cert_path("ca.crt")),
                            "--load-ca-privkey",
                            str(self.config.cert_path("ca.key")),
                        ]
                    )
                results.append(
                    self.runner.run(
                        [*argv, "--template", str(template), "--outfile", str(stage_crt)],
                        timeout=60,
                        dry_run=dry_run,
                    )
                )
                if not dry_run:
                    key_data, cert_data = stage_key.read_bytes(), stage_crt.read_bytes()
                    certificate = self._validate_pair(key_data, cert_data, ca=self_signed)
                    issuer = (
                        certificate
                        if self_signed
                        else x509.load_pem_x509_certificate(
                            self.config.cert_path("ca.crt").read_bytes()
                        )
                    )
                    try:
                        certificate.verify_directly_issued_by(issuer)
                    except (ValueError, TypeError, InvalidSignature):
                        raise ValueError("generated certificate failed issuer validation") from None
                    self._publish_pair(key, crt, key_data, cert_data)
                return results

    def init_ca(self, *, dry_run: bool = False, _replace: bool = False) -> list[CommandResult]:
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
                    "crl_signing_key",
                    "expiration_days = 3650",
                    "",
                ]
            ),
        )
        return self._generate_pair(
            ca_key,
            ca_crt,
            ca_template,
            self_signed=True,
            replace=_replace,
            dry_run=dry_run,
        )

    def save_ca_material(self, *, ca_cert: bytes, ca_key: bytes) -> CommandResult:
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        ca_crt_path = self.config.cert_path("ca.crt")
        ca_key_path = self.config.cert_path("ca.key")
        self._validate_pair(ca_key, ca_cert, ca=True)
        with self._material_lock():
            self._publish_pair(ca_key_path, ca_crt_path, ca_key, ca_cert)
        return CommandResult(
            ("korctl", "certificates", "ca", "upload"),
            0,
            f"written {ca_crt_path}\nwritten {ca_key_path}\n",
            "",
        )

    def regenerate_ca(self, *, dry_run: bool = False) -> list[CommandResult]:
        return self.init_ca(dry_run=dry_run, _replace=True)

    def create_server_certificate(self, *, dry_run: bool = False) -> list[CommandResult]:
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        key = self.config.cert_path("server.key")
        crt = self.config.cert_path("server.crt")
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
        # Keep the public-key pin stable when reissuing the server certificate.
        return self._generate_pair(key, crt, template, reuse_key=True, dry_run=dry_run)

    def ensure_control_certificate(self, address: str, *, dry_run: bool = False) -> bool:
        """Server certificate of the control API listener, IP SAN = the hub fabric
        address (agents pin the kornode CA and verify this address). Renewed
        when it has under 30 days left. True when a certificate was issued."""
        crt = self.config.cert_path("control.crt")
        key = self.config.cert_path("control.key")
        if crt.exists() and key.exists() and not dry_run:
            parsed = self._validate_pair(key.read_bytes(), crt.read_bytes())
            left = parsed.not_valid_after_utc - datetime.now(UTC)
            if left > timedelta(days=30):
                return False
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        template = self._write_template(
            self._template_path("control.tmpl"),
            "\n".join(
                [
                    "cn = kornode-control",
                    "tls_www_server",
                    "encryption_key",
                    "signing_key",
                    f"ip_address = {address}",
                    "expiration_days = 825",
                    "",
                ]
            ),
        )
        try:
            self._generate_pair(key, crt, template, reuse_key=True, ecc=True, dry_run=dry_run)
        finally:
            template.unlink(missing_ok=True)
        return True

    def ensure_fabric_certificate(self, *, dry_run: bool = False) -> bool:
        """Server certificate of the fabric virtual host (S-07, D-71), signed by the hub
        CA with the vhost name as SAN. Agents pin its public key, so an existing key is
        kept when the certificate is renewed (under 30 days left). True when issued."""
        crt = self.config.cert_path("fabric.crt")
        key = self.config.cert_path("fabric.key")
        name = self.config.fabric.server_name
        if crt.exists() and key.exists() and not dry_run:
            parsed = self._validate_pair(key.read_bytes(), crt.read_bytes())
            left = parsed.not_valid_after_utc - datetime.now(UTC)
            if left > timedelta(days=30) and name in _certificate_dns_names(parsed):
                return False
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        template = self._write_template(
            self._template_path("fabric.tmpl"),
            "\n".join(
                [
                    f"cn = {name}",
                    "tls_www_server",
                    "encryption_key",
                    "signing_key",
                    f"dns_name = {name}",
                    "expiration_days = 825",
                    "",
                ]
            ),
        )
        try:
            self._generate_pair(key, crt, template, reuse_key=True, ecc=True, dry_run=dry_run)
        finally:
            template.unlink(missing_ok=True)
        return True

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
        return self._generate_pair(key, crt, template, dry_run=dry_run)

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
        if dry_run:
            return self.runner.run(argv, timeout=60, dry_run=True, extra_secrets=[passphrase or ""])
        from cryptography.hazmat.primitives.serialization import pkcs12

        self.files.ensure_dir(out.parent, mode=0o700)
        with (
            self._material_lock(),
            tempfile.TemporaryDirectory(prefix=".p12-", dir=out.parent) as directory,
        ):
            staged = Path(directory) / out.name
            self.files.atomic_write_bytes(staged, b"")
            argv[argv.index("--outfile") + 1] = str(staged)
            result = self.runner.run(argv, timeout=60, extra_secrets=[passphrase or ""])
            data = staged.read_bytes()
            try:
                bundle_key, bundle_cert, _ = pkcs12.load_key_and_certificates(
                    data,
                    passphrase.encode() if passphrase else None,
                )
                if bundle_key is None or bundle_cert is None:
                    raise ValueError("missing key/certificate")
            except (ValueError, TypeError):
                raise ValueError("invalid generated PKCS#12 bundle") from None
            self.files.atomic_write_bytes(out, data)
            return result

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

    def sign_agent_public_key(
        self,
        node_id: int,
        public_key_pem: str,
        *,
        lifetime_days: int,
        dry_run: bool = False,
    ) -> Path:
        """Issue CN=agent-<id>, OU=agents from a bare public key (D-45).

        The subject comes only from the template: certtool would copy it from
        a CSR, and the CSR is attacker-controlled. Proof of possession is
        checked by the caller before the key gets here.
        """
        name = f"agent-{node_id}"
        agents_dir = self.cert_dir / "agents"
        self.files.ensure_dir(agents_dir, mode=0o700)
        pubkey = agents_dir / f"{name}.pub.tmp"
        out = agents_dir / f"{name}.crt.tmp"
        self.files.atomic_write_text(pubkey, public_key_pem, mode=0o600)
        template = self._write_template(
            self._template_path(f"{name}.tmpl"),
            "\n".join(
                [
                    f"cn = {name}",
                    "unit = agents",
                    "tls_www_client",
                    "signing_key",
                    f"expiration_days = {lifetime_days}",
                    "",
                ]
            ),
        )
        try:
            self.runner.run(
                [
                    "certtool",
                    "--generate-certificate",
                    "--load-pubkey",
                    str(pubkey),
                    "--load-ca-certificate",
                    str(self.config.cert_path("ca.crt")),
                    "--load-ca-privkey",
                    str(self.config.cert_path("ca.key")),
                    "--template",
                    str(template),
                    "--outfile",
                    str(out),
                ],
                timeout=60,
                dry_run=dry_run,
            )
        finally:
            pubkey.unlink(missing_ok=True)
            template.unlink(missing_ok=True)
        return out

    def issue_access_server_certificate(
        self, node_id: int, hostname: str, *, lifetime_days: int
    ) -> tuple[str, str]:
        """Server certificate of an agent's access listener (P4-04, D-67).

        Signed by the hub CA for `hostname` (DNS name or IP address), with no
        OU: the hub's certificate login refuses OU-less certificates, so this
        certificate can never authenticate to the hub. The key is generated
        here and returned with the certificate; the caller seals it to the
        agent and stores it encrypted, never in plain text on disk.
        """
        import ipaddress

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        try:
            ipaddress.ip_address(hostname)
            san = f"ip_address = {hostname}"
        except ValueError:
            san = f'dns_name = "{hostname}"'
        # Unique per call: two concurrent issues for one node must not share files.
        name = f"access-{node_id}-{secrets.token_hex(4)}"
        work = self.cert_dir / "agents"
        self.files.ensure_dir(work, mode=0o700)
        key_path = work / f"{name}.key.tmp"
        out = work / f"{name}.crt.tmp"
        self.files.atomic_write_text(key_path, key_pem, mode=0o600)
        template = self._write_template(
            self._template_path(f"{name}.tmpl"),
            "\n".join(
                [
                    f'cn = "{hostname}"',
                    san,
                    "tls_www_server",
                    "signing_key",
                    "encryption_key",
                    f"expiration_days = {lifetime_days}",
                    "",
                ]
            ),
        )
        try:
            self.runner.run(
                [
                    "certtool",
                    "--generate-certificate",
                    "--load-privkey",
                    str(key_path),
                    "--load-ca-certificate",
                    str(self.config.cert_path("ca.crt")),
                    "--load-ca-privkey",
                    str(self.config.cert_path("ca.key")),
                    "--template",
                    str(template),
                    "--outfile",
                    str(out),
                ],
                timeout=60,
            )
            cert_pem = out.read_text(encoding="utf-8")
        finally:
            key_path.unlink(missing_ok=True)
            out.unlink(missing_ok=True)
            template.unlink(missing_ok=True)
        return cert_pem, key_pem

    def ensure_crl(self, *, dry_run: bool = False) -> bool:
        """Create the CRL if absent; ocserv refuses to start with `crl =` pointing nowhere."""
        if (self.cert_dir / "crl.pem").exists():
            return False
        self.files.ensure_dir(self.cert_dir, mode=0o700)
        self.generate_crl(dry_run=dry_run)
        return True

    def crl_age_seconds(self) -> float | None:
        crl = self.cert_dir / "crl.pem"
        if not crl.exists():
            return None
        return max(0.0, time.time() - crl.stat().st_mtime)

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
        argv = [
            "certtool",
            "--generate-crl",
            "--load-ca-privkey",
            str(ca_key),
            "--load-ca-certificate",
            str(ca_crt),
        ]
        # No revocations yet: certtool still emits a valid empty CRL.
        if revoked.exists() and revoked.stat().st_size > 0:
            argv.extend(["--load-certificate", str(revoked)])
        argv.extend(["--template", str(template), "--outfile", str(crl)])
        return self.runner.run(argv, timeout=60, dry_run=dry_run)


def _certificate_identities(value: str) -> list[str]:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return [f"dns_name = {value}"]
    return [f"ip_address = {value}"]


def _certificate_dns_names(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return extension.value.get_values_for_type(x509.DNSName)


def _parse_certificate_info(output: str) -> dict[str, str]:
    entry = {field: "" for field in _CERT_INFO_FIELDS}
    for field, pattern in _CERT_INFO_FIELDS.items():
        match = pattern.search(output)
        if match:
            entry[field] = match.group(1).strip()
    return entry
