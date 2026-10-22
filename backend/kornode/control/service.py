"""Synchronous core of the control API (the ASGI handlers stay thin).

Every method opens its own short-lived registry connection: the registry is
shared with the admin API, `korctl` and the reconciler, and SQLite is the only
channel between those processes.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
)

from kornode.bundle.errors import BundleError
from kornode.config.models import AppConfig
from kornode.control.auth import RateLimiter, RevocationList, agent_identity
from kornode.control.errors import ControlError
from kornode.net.lists import parse_gateway_sets, report_gateway_sets
from kornode.registry.db import migrate, open_registry, transaction
from kornode.registry.models import Command, StoredBundle
from kornode.registry.repository import Registry, RegistryNotFound
from kornode.services.audit import AuditService
from kornode.services.bundle import BundleService
from kornode.services.enrollment import EnrollmentError, EnrollmentService
from kornode.services.net import NetService

MAX_REPORT_BYTES = 256 * 1024
MAX_RESULT_BYTES = 8 * 1024 * 1024  # 5 MB artefact, base64-encoded, plus the envelope
MAX_ENROLL_BYTES = 64 * 1024
MAX_VERSION = 2**31 - 1
REPORTS_KEPT = 500
ENROLL_ATTEMPTS_PER_MINUTE = 5
POLL_INTERVAL_SECONDS = 0.5


class ReportBody(BaseModel):
    """The fields the hub acts on; the rest of the report is stored as sent."""

    model_config = ConfigDict(extra="allow")

    node_id: StrictInt | None = None
    agent_version: StrictStr = Field(max_length=64)
    applied_version: StrictInt = Field(ge=0, le=MAX_VERSION)
    pending_version: StrictInt | None = Field(default=None, ge=0, le=MAX_VERSION)
    high_water_version: StrictInt | None = Field(default=None, ge=0, le=MAX_VERSION)
    # Addresses the agent resolved for the destinations of its `node:<n>` rules (D-79);
    # agents before D-84 send them as `exit_sets`.
    gateway_sets: dict[str, list[str]] | None = None
    exit_sets: dict[str, list[str]] | None = None

    @field_validator("gateway_sets", "exit_sets")
    @classmethod
    def _valid_gateway_sets(
        cls, value: dict[str, list[str]] | None
    ) -> dict[str, list[str]] | None:
        parse_gateway_sets(value, strict=True)
        return value


class CommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: StrictBool
    output: StrictStr = Field(default="", max_length=1024 * 1024)
    artefact_b64: StrictStr | None = None


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token_id: StrictStr = Field(max_length=64)
    secret: StrictStr = Field(max_length=256)
    csr_pem: StrictStr = Field(max_length=16 * 1024)
    seal_pubkey_b64: StrictStr = Field(max_length=256)
    facts: dict[str, Any] = Field(default_factory=dict)


class RenewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    csr_pem: StrictStr = Field(max_length=16 * 1024)


def parse_model[ModelT: BaseModel](model: type[ModelT], data: Any) -> ModelT:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        fields = ", ".join(".".join(str(part) for part in err["loc"]) for err in exc.errors())
        raise ControlError("invalid", f"invalid request: {fields}") from exc


class ControlService:
    def __init__(
        self,
        config: AppConfig,
        *,
        clock: Callable[[], datetime] | None = None,
        enrollment: EnrollmentService | None = None,
        revocations: RevocationList | None = None,
        enroll_limiter: RateLimiter | None = None,
    ) -> None:
        self.config = config
        self._clock = clock or (lambda: datetime.now(UTC))
        self.enrollment = enrollment or EnrollmentService(config, clock=self._clock)
        self.bundles = BundleService(config, clock=self._clock)
        self.audit = AuditService(config)
        self.revocations = revocations or RevocationList(
            config.cert_path("crl.pem"), config.cert_path("ca.crt"), self._clock
        )
        self.enroll_limiter = enroll_limiter or RateLimiter(ENROLL_ATTEMPTS_PER_MINUTE, 60.0)

    @contextmanager
    def registry(self) -> Iterator[Registry]:
        conn = open_registry(self.config.system.data_dir / "registry.db")
        try:
            migrate(conn)
            yield Registry(conn)
        finally:
            conn.close()

    # ------------------------------------------------------------------ auth

    def authenticate(self, der: bytes | None, source_ip: str | None = None) -> int:
        """Node id behind a client certificate, or ControlError."""
        try:
            node_id, serial = agent_identity(der)
            if self.revocations.is_revoked(serial):
                raise ControlError("revoked", "certificate has been revoked")
            with self.registry() as registry:
                node = registry.get_node(node_id)
                if node.state == "revoked":
                    raise ControlError("revoked", f"agent {node_id} has been revoked")
                if node.state != "active":
                    raise ControlError("unauthorized", f"agent {node_id} is not enrolled")
        except RegistryNotFound as exc:
            self._denied("unknown agent", source_ip)
            raise ControlError("unauthorized", "unknown agent") from exc
        except ControlError as exc:
            if exc.status != 503:
                self._denied(exc.message, source_ip)
            raise
        return node_id

    def _denied(self, reason: str, source_ip: str | None) -> None:
        self.audit.record(
            actor="unknown",
            action="control.auth",
            outcome="denied",
            source_ip=source_ip,
            details={"reason": reason},
        )

    # ---------------------------------------------------------------- bundle

    def latest_for(self, node_id: int, since: int) -> StoredBundle | None:
        """The stored bundle newer than `since`, recovering when the agent is ahead (D-37)."""
        check_version(since)
        with self.registry() as registry:
            node = registry.get_node(node_id)
            if node.state == "active":
                self.bundles.refresh_rotation(registry, node_id)
            latest = registry.latest_bundle(node_id)
            if latest is not None and latest.version > since:
                return latest
            if since <= (latest.version if latest else 0) or node.state != "active":
                return None
            # The hub is behind the agent (restored from a backup): remember
            # what the agent has accepted and mint a version above it.
            try:
                with transaction(registry.conn):
                    registry.raise_high_water(node_id, since)
                    return self.bundles.compile_node(
                        registry, node_id, "recovery: agent ahead of hub", force=True
                    )
            except BundleError as exc:
                raise ControlError("internal", f"cannot compile bundle: {exc.code}") from exc

    def pending_commands(self, node_id: int) -> list[Command]:
        with self.registry() as registry:
            return registry.claim_commands(node_id, now=self._clock())

    def has_commands(self, node_id: int) -> bool:
        with self.registry() as registry:
            return registry.has_queued_commands(node_id, now=self._clock())

    def touch(self, node_id: int) -> None:
        with self.registry() as registry:
            registry.touch_node(node_id)

    # --------------------------------------------------------------- reports

    def store_report(self, node_id: int, data: Any) -> None:
        report = parse_model(ReportBody, data)
        if report.node_id is not None and report.node_id != node_id:
            raise ControlError("invalid", "report node_id does not match the certificate")
        changed = False
        with self.registry() as registry, transaction(registry.conn):
            previous = registry.list_reports(node_id, 1)
            changed = parse_gateway_sets(
                report_gateway_sets(report.model_dump(exclude_none=True))
            ) != parse_gateway_sets(report_gateway_sets(previous[0].body) if previous else None)
            registry.add_report(node_id, data, keep=REPORTS_KEPT)
            registry.update_node(node_id, applied_version=report.applied_version)
            if report.high_water_version is not None:
                registry.raise_high_water(node_id, report.high_water_version)
            registry.touch_node(node_id)
        if changed:
            # The hub marks transit traffic of set exits by these addresses (D-79).
            NetService(self.config).wake()

    def finish_command(self, node_id: int, command_id: str, data: Any) -> None:
        result = parse_model(CommandResult, data)
        if result.artefact_b64 is not None:
            try:
                base64.b64decode(result.artefact_b64, validate=True)
            except ValueError as exc:
                raise ControlError("invalid", "artefact_b64 is not base64") from exc
        payload = result.model_dump(exclude_none=True)
        with self.registry() as registry:
            try:
                registry.finish_command(
                    node_id, command_id, ok=result.ok, result=payload, now=self._clock()
                )
            except RegistryNotFound as exc:
                raise ControlError("not_found", "no such delivered command") from exc

    # ------------------------------------------------------ enroll and renew

    def enroll(self, data: Any, source_ip: str | None) -> tuple[dict[str, Any], str]:
        """(result, token id). The enroll session stays up: the answer travels
        through it, and the caller ends it afterwards (`end_enroll_session`)."""
        if not self.enroll_limiter.allow(source_ip or "-"):
            raise ControlError("rate_limited", "too many enrollment attempts")
        request = parse_model(EnrollRequest, data)
        try:
            result = self.enrollment.enroll(
                token_id=request.token_id,
                secret=request.secret,
                csr_pem=request.csr_pem,
                seal_pubkey_b64=request.seal_pubkey_b64,
                facts=request.facts,
                source_ip=source_ip,
                end_session=False,
            )
            return result, request.token_id
        except EnrollmentError as exc:
            raise ControlError(exc.code, exc.message, exc.status) from exc

    def end_enroll_session(self, token_id: str) -> None:
        self.enrollment.end_enroll_session(token_id)

    def renew(self, node_id: int, data: Any) -> dict[str, Any]:
        request = parse_model(RenewRequest, data)
        try:
            return self.enrollment.renew(node_id, request.csr_pem)
        except EnrollmentError as exc:
            raise ControlError(exc.code, exc.message, exc.status) from exc

    # ---------------------------------------------------------------- startup

    def compile_all(self, reason: str) -> int:
        """Recompile every active agent (control API start, hub YAML save)."""
        with self.registry() as registry, transaction(registry.conn):
            try:
                return len(self.bundles.compile_all(registry, reason))
            except BundleError as exc:
                raise ControlError("internal", f"cannot compile bundles: {exc.code}") from exc


def check_version(value: int) -> int:
    if not 0 <= value <= MAX_VERSION:
        raise ControlError("invalid", "version is out of range")
    return value
