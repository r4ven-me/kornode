from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from kornode.bundle.errors import BundleError
from kornode.config.models import AppConfig
from kornode.registry.db import migrate, open_registry, transaction
from kornode.registry.models import EnrollToken, Node
from kornode.registry.repository import Registry, RegistryNotFound
from kornode.services.audit import AuditService
from kornode.services.bundle import BundleService
from kornode.services.certificates import CertificateService
from kornode.services.command import CommandRunner
from kornode.services.files import FileManager
from kornode.services.interlink_groups import InterlinkGroupsService
from kornode.services.sessions import SessionService
from kornode.services.users import UserService
from kornode.tunnels.pin import certificate_file_pin

RENEW_AFTER_FRACTION = 2 / 3
RENEW_WARNING_DAYS = 14
CRL_REFRESH_AFTER_SECONDS = 10 * 24 * 3600  # crl_next_update is 30 days
SEAL_PUBKEY_LEN = 32
MAX_CSR_BYTES = 8192
TOKEN_ID_RE = re.compile(r"[0-9a-f]{1,16}")


class EnrollmentError(Exception):
    """Failure with an HTTP-like status; P3-05 maps it onto the Control API errors."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class EnrollmentService:
    """Issue enrollment tokens, sign agent CSRs, renew and revoke agents (spec 05).

    The registry is opened per call: it is shared with other processes and
    SQLite is the only channel between them.
    """

    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
        *,
        reload_ocserv: Callable[[], None] | None = None,
        hub: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.certificates = CertificateService(config, runner=self.runner, files=self.files)
        self.users = UserService(config, runner=self.runner, files=self.files)
        self.groups = InterlinkGroupsService(config, self.files)
        self.sessions = SessionService(config, runner=self.runner)
        self.audit = AuditService(config)
        self._reload_ocserv = reload_ocserv
        self.hub = hub or f"{config.server.cn}:{config.server.port}"
        self._clock = clock or (lambda: datetime.now(UTC))
        self.bundles = BundleService(config, clock=self._clock)

    # ------------------------------------------------------------------ tokens

    def issue_token(self, node_id: int, *, camouflage: str | None = None) -> str:
        """Create a one-shot token for a pending node; the previous one is revoked."""
        now = self._clock()
        secret = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        token_id = secrets.token_hex(4)
        username = f"enroll-{node_id}-{token_id}"
        expires = now + timedelta(minutes=self.config.control.enroll_token_ttl_minutes)
        with self._registry() as registry:
            node = self._node(registry, node_id)
            if node.state != "pending":
                raise EnrollmentError(409, "conflict", f"node {node_id} is {node.state}")
            self.certificates.ensure_crl()
            self._create_enroll_user(username, secret)
            try:
                with transaction(registry.conn):
                    old = registry.list_enroll_tokens(node_id)
                    registry.delete_enroll_tokens([item.id for item in old])
                    registry.create_enroll_token(
                        id=token_id,
                        node_id=node_id,
                        ocserv_user=username,
                        secret_hash=hash_secret(secret),
                        expires_at=_iso(expires),
                    )
            except BaseException:
                self.users.delete_enroll_user(username)
                raise
            for item in old:
                self._drop_enroll_user_quietly(item.ocserv_user)
        pin = certificate_file_pin(self.config.cert_path("interlink.crt")).pin
        document: dict[str, Any] = {
            "v": 1,
            "hub": self.hub,
            "pin": pin,
            "sni": self.config.interlink.server_name,
            "id": token_id,
            "user": username,
            "secret": secret,
            "exp": _iso(expires),
            "control": self.bundles.control_url(),
        }
        if camouflage:
            document["camouflage"] = camouflage
        self.audit.record(
            actor="operator",
            action="agent.token.issue",
            outcome="success",
            details={"node_id": node_id, "token_id": token_id},
        )
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def revoke_token(self, node_id: int) -> int:
        with self._registry() as registry:
            tokens = registry.list_enroll_tokens(node_id)
            registry.delete_enroll_tokens([item.id for item in tokens])
        for item in tokens:
            self._drop_enroll_user(item.ocserv_user)
        if tokens:
            self.audit.record(
                actor="operator",
                action="agent.token.revoke",
                outcome="success",
                details={"node_id": node_id},
            )
        return len(tokens)

    def purge_expired(self) -> int:
        """Drop expired and used tokens together with their ocpasswd users."""
        now = self._clock()
        with self._registry() as registry:
            stale = [
                item
                for item in registry.list_enroll_tokens()
                if item.used_at is not None or _parse_time(item.expires_at) <= now
            ]
            registry.delete_enroll_tokens([item.id for item in stale])
        for item in stale:
            self._drop_enroll_user(item.ocserv_user)
        return len(stale)

    # ------------------------------------------------------------------ enroll

    def enroll(
        self,
        *,
        token_id: str,
        secret: str,
        csr_pem: str,
        seal_pubkey_b64: str,
        facts: Mapping[str, Any] | None = None,
        source_ip: str | None = None,
        end_session: bool = True,
    ) -> dict[str, Any]:
        """`end_session=False` leaves the enroll VPN session up: the Control API
        answers through it, so it calls `end_enroll_session` once the answer
        has been delivered (cutting it here would lose the certificate)."""
        now = self._clock()
        with self._registry() as registry:
            token = self._authenticate(registry, token_id, secret, source_ip)
            if token.used_at is not None or _parse_time(token.expires_at) <= now:
                raise EnrollmentError(410, "gone", "enrollment token expired or already used")
            node = self._node(registry, token.node_id)
            if node.state != "pending":
                raise EnrollmentError(409, "conflict", f"node {node.id} is {node.state}")
            public_key_pem = _validated_public_key(csr_pem)
            seal_pubkey = _validated_seal_key(seal_pubkey_b64)
            with transaction(registry.conn):
                # State is re-read under the write lock: a revoke that
                # committed since the check above must not be undone.
                node = self._node(registry, token.node_id)
                if node.state != "pending":
                    raise EnrollmentError(409, "conflict", f"node {node.id} is {node.state}")
                if not registry.mark_enroll_token_used(token.id, _iso(now)):
                    raise EnrollmentError(410, "gone", "enrollment token already used")
                issued = self._issue_certificate(node.id, public_key_pem)
                registry.update_node(
                    node.id,
                    state="active",
                    cert_serial=issued["serial"],
                    cert_not_after=issued["not_after"],
                    seal_pubkey=seal_pubkey,
                    last_seen=_iso(now),
                )
                try:
                    # Its prefixes now reach every other active agent too.
                    bundles = self.bundles.compile_all(registry, f"enroll node {node.id}")
                    first_bundle = bundles[node.id]
                except BundleError as exc:
                    raise EnrollmentError(500, "internal", f"bundle: {exc.message}") from exc
        # The registry is already committed and the token spent, so a failure
        # below must not turn into a 500 the agent cannot retry. The group
        # files are re-synced by maintain(); the enroll user expires anyway.
        problems = [
            step
            for step, action in (
                (
                    "enroll user",
                    partial(self._drop_enroll_user, token.ocserv_user, disconnect=end_session),
                ),
                ("sync groups", self.groups.sync),
            )
            if not self._attempt(action)
        ]
        self.audit.record(
            actor=f"enroll:{token.id}",
            action="agent.enroll",
            outcome="success",
            source_ip=source_ip,
            details={"node_id": node.id, "serial": issued["serial"], "pending_cleanup": problems},
        )
        return {
            "cert_pem": issued["cert_pem"],
            "ca_pem": self.config.cert_path("ca.crt").read_text(encoding="utf-8"),
            "node_id": node.id,
            "signing_keys": self.bundles.signing_keys(),
            "bundle": {
                "version": first_bundle.version,
                "body_b64": base64.b64encode(first_bundle.body).decode("ascii"),
                "signature": first_bundle.signature,
            },
        }

    def renew(self, node_id: int, csr_pem: str) -> dict[str, Any]:
        now = self._clock()
        with self._registry() as registry:
            node = self._node(registry, node_id)
            if node.state != "active" or node.cert_not_after is None:
                raise EnrollmentError(409, "conflict", f"node {node_id} is {node.state}")
            earliest = _parse_time(node.cert_not_after) - timedelta(
                days=self.config.control.cert_lifetime_days * (1 - RENEW_AFTER_FRACTION)
            )
            if now < earliest:
                raise EnrollmentError(409, "conflict", f"renewal opens at {_iso(earliest)}")
            public_key_pem = _validated_public_key(csr_pem)
            with transaction(registry.conn):
                if self._node(registry, node_id).state != "active":
                    raise EnrollmentError(409, "conflict", f"node {node_id} is not active")
                # The old certificate stays valid until it expires: the agent
                # may have to fall back to it if the new one fails to connect.
                issued = self._issue_certificate(node_id, public_key_pem)
                registry.update_node(
                    node_id,
                    cert_serial=issued["serial"],
                    cert_not_after=issued["not_after"],
                )
        self.audit.record(
            actor=f"agent-{node_id}",
            action="agent.renew",
            outcome="success",
            details={"node_id": node_id, "serial": issued["serial"]},
        )
        return {"cert_pem": issued["cert_pem"]}

    def renewal_warning(self, node: Node) -> bool:
        if node.state != "active" or node.cert_not_after is None:
            return False
        left = _parse_time(node.cert_not_after) - self._clock()
        return left <= timedelta(days=RENEW_WARNING_DAYS)

    # ------------------------------------------------------------------ revoke

    def revoke_node(self, node_id: int) -> dict[str, Any]:
        """Revoke an agent: fail closed first, then cut the live session off."""
        with self._registry() as registry:
            self._node(registry, node_id)
            tokens = registry.list_enroll_tokens(node_id)
            with transaction(registry.conn):
                registry.update_node(node_id, state="revoked")
                registry.set_prefixes(node_id, [])
                registry.delete_enroll_tokens([item.id for item in tokens])
        failures: list[str] = []

        def attempt(step: str, action: Callable[[], object]) -> None:
            try:
                action()
            except Exception as exc:  # every step must run; failures are reported below
                failures.append(f"{step}: {exc}")

        def recompile() -> None:
            # Released prefixes change other agents' bundles. A refused bundle
            # must never block the revocation itself, so this is a late step.
            # One transaction per node: a refused bundle leaves the others fresh.
            problems: list[str] = []
            with self._registry() as fresh:
                for other in fresh.list_nodes():
                    if other.state != "active" or other.seal_pubkey is None:
                        continue
                    try:
                        with transaction(fresh.conn):
                            self.bundles.compile_node(fresh, other.id, f"revoke node {node_id}")
                    except BundleError as exc:
                        problems.append(f"node {other.id}: {exc.message}")
            if problems:
                raise RuntimeError("; ".join(problems))

        attempt("recompile bundles", recompile)
        for item in tokens:
            attempt("enroll user", partial(self._drop_enroll_user, item.ocserv_user))
        certs = sorted((self.certificates.cert_dir / "agents").glob(f"agent-{node_id}-*.crt"))
        for path in certs:
            attempt(
                "revoke certificate",
                partial(
                    self.certificates.append_revoked_certificate,
                    path.read_text(encoding="utf-8"),
                ),
            )
        attempt("crl", self.certificates.generate_crl)
        attempt("sync groups", self.groups.sync)
        if self._reload_ocserv is not None:
            attempt("reload ocserv", self._reload_ocserv)
        # CRL is checked on the handshake only: a live session has to be cut.
        attempt(
            "disconnect",
            partial(self.sessions.disconnect_if_present, f"agent-{node_id}"),
        )
        self.audit.record(
            actor="operator",
            action="agent.revoke",
            outcome="failure" if failures else "success",
            details={"node_id": node_id, "certificates": len(certs), "failures": failures},
        )
        if failures:
            raise EnrollmentError(500, "internal", "; ".join(failures))
        return {"node_id": node_id, "certificates": len(certs)}

    def maintain(self) -> dict[str, int]:
        """Periodic housekeeping: expired tokens and a CRL ocserv would reject as stale."""
        purged = self.purge_expired()
        self._attempt(self.groups.sync)  # heals a sync that failed after an enroll
        self._attempt(self._sync_dns)  # heals a hub dnsmasq restart that failed (D-66)
        refreshed = 0
        created = self.certificates.ensure_crl()
        age = self.certificates.crl_age_seconds()
        if created or (age is not None and age > CRL_REFRESH_AFTER_SECONDS):
            if not created:
                self.certificates.generate_crl()
            refreshed = 1
            if self._reload_ocserv is not None:
                self._reload_ocserv()
        return {"purged_tokens": purged, "crl_refreshed": refreshed}

    # ---------------------------------------------------------------- internals

    def _authenticate(
        self, registry: Registry, token_id: str, secret: str, source_ip: str | None
    ) -> EnrollToken:
        # Unknown id and wrong secret are indistinguishable to the caller.
        token: EnrollToken | None = None
        if TOKEN_ID_RE.fullmatch(token_id):
            try:
                token = registry.get_enroll_token(token_id)
            except RegistryNotFound:
                token = None
        expected = token.secret_hash if token is not None else hash_secret(secrets.token_hex(16))
        if not hmac.compare_digest(expected, hash_secret(secret)) or token is None:
            self.audit.record(
                actor=f"enroll:{token_id[:16]}",
                action="agent.enroll",
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "bad token or secret"},
            )
            raise EnrollmentError(403, "unauthorized", "invalid enrollment token")
        return token

    def _issue_certificate(self, node_id: int, public_key_pem: str) -> dict[str, str]:
        tmp = self.certificates.sign_agent_public_key(
            node_id, public_key_pem, lifetime_days=self.config.control.cert_lifetime_days
        )
        try:
            pem = tmp.read_text(encoding="utf-8")
            cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
            serial = format(cert.serial_number, "x")
            final = tmp.with_name(f"agent-{node_id}-{serial}.crt")
            tmp.replace(final)
        finally:
            tmp.unlink(missing_ok=True)
        return {
            "cert_pem": pem,
            "serial": serial,
            "not_after": _iso(cert.not_valid_after_utc),
        }

    def _create_enroll_user(self, username: str, password: str) -> None:
        result = self.users.create_enroll_user(username, password)
        if not result.ok:
            raise EnrollmentError(500, "internal", "failed to create the enrollment user")

    def _sync_dns(self) -> None:
        from kornode.services.interlink_dns import InterlinkDnsService

        InterlinkDnsService(self.config).sync()

    @staticmethod
    def _attempt(action: Callable[[], object]) -> bool:
        try:
            action()
        except Exception:  # best effort; the caller reports it
            return False
        return True

    def _drop_enroll_user_quietly(self, username: str) -> None:
        self._attempt(partial(self._drop_enroll_user, username))

    def _drop_enroll_user(self, username: str, *, disconnect: bool = True) -> None:
        self.users.delete_enroll_user(username)
        if disconnect:
            self._disconnect_user(username)

    def _disconnect_user(self, username: str) -> None:
        self.runner.run(
            self.sessions.occtl_argv("disconnect", "user", username),
            timeout=15,
            check=False,
        )

    def end_enroll_session(self, token_id: str) -> None:
        """Cut the enroll VPN session of a spent token (best effort; the user
        is already gone from ocpasswd and expiry/maintain() heal the rest)."""
        with self._registry() as registry:
            try:
                token = registry.get_enroll_token(token_id)
            except RegistryNotFound:
                return
        if token.used_at is not None:
            self._attempt(partial(self._disconnect_user, token.ocserv_user))

    def _node(self, registry: Registry, node_id: int) -> Node:
        try:
            return registry.get_node(node_id)
        except RegistryNotFound as exc:
            raise EnrollmentError(404, "not_found", f"node {node_id} not found") from exc

    @contextmanager
    def _registry(self) -> Iterator[Registry]:
        path: Path = self.config.system.data_dir / "registry.db"
        conn = open_registry(path)
        try:
            migrate(conn)
            yield Registry(conn)
        finally:
            conn.close()


def _validated_public_key(csr_pem: str) -> str:
    """Check the CSR (size, signature, ECDSA P-256) and return only its public key.

    Everything else in the CSR — subject, extensions — is discarded: the hub
    sets CN/OU itself.
    """
    if len(csr_pem) > MAX_CSR_BYTES:
        raise EnrollmentError(400, "invalid", "CSR is too large")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise EnrollmentError(400, "invalid", "CSR is not valid PEM") from exc
    if not csr.is_signature_valid:
        raise EnrollmentError(400, "invalid", "CSR signature does not verify")
    key = csr.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise EnrollmentError(400, "invalid", "CSR key must be ECDSA P-256")
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def _validated_seal_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise EnrollmentError(400, "invalid", "seal_pubkey is not base64") from exc
    if len(raw) != SEAL_PUBKEY_LEN:
        raise EnrollmentError(400, "invalid", "seal_pubkey must be 32 bytes (X25519)")
    return raw
