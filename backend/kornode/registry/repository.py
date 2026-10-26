from __future__ import annotations

import json
import secrets
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from kornode.registry.db import RegistryError, transaction
from kornode.registry.models import (
    Command,
    CommandState,
    DnsRecord,
    DnsRecordType,
    EnrollToken,
    External,
    Node,
    NodePrefix,
    NodeState,
    PrefixKind,
    Report,
    StoredBundle,
    decode_json_array,
    decode_json_object,
    encode_json,
    iso_time,
    utc_now_iso,
)

# A delivered command whose result never arrives (the agent restarted, crashed or
# lost the batch) is expired after the delivery TTL plus the longest confirm
# window a rollback command may legitimately wait (bundle settings allow 600 s).
COMMAND_TTL_SECONDS = 600
MAX_CONFIRM_WINDOW_SECONDS = 600
DELIVERED_TTL_SECONDS = COMMAND_TTL_SECONDS + MAX_CONFIRM_WINDOW_SECONDS


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class RegistryConflict(RegistryError):
    pass


class RegistryNotFound(RegistryError):
    pass


class Registry:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def create_node(
        self,
        *,
        id: int,
        name: str,
        description: str = "",
        roles: Sequence[str] | None = None,
        state: NodeState = "pending",
        cert_serial: str | None = None,
        cert_not_after: str | None = None,
        seal_pubkey: bytes | None = None,
        policy: Mapping[str, Any] | None = None,
        transport: Mapping[str, Any] | None = None,
        last_seen: str | None = None,
    ) -> Node:
        now = utc_now_iso()
        try:
            with self._write():
                self.conn.execute(
                    """
                    INSERT INTO nodes (
                      id, name, description, roles, state, cert_serial, cert_not_after,
                      seal_pubkey, policy, transport, last_seen, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        id,
                        name,
                        description,
                        encode_json(list(roles or [])),
                        state,
                        cert_serial,
                        cert_not_after,
                        seal_pubkey,
                        encode_json(dict(policy or {})),
                        encode_json(dict(transport or {})),
                        last_seen,
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RegistryConflict(str(exc)) from exc
        return self.get_node(id)

    def get_node(self, node_id: int) -> Node:
        row = self.conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if row is None:
            raise RegistryNotFound(f"node {node_id} not found")
        return _node_from_row(row)

    def get_node_by_name(self, name: str) -> Node:
        row = self.conn.execute("SELECT * FROM nodes WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise RegistryNotFound(f"node {name!r} not found")
        return _node_from_row(row)

    def list_nodes(self) -> list[Node]:
        rows = self.conn.execute("SELECT * FROM nodes ORDER BY id").fetchall()
        return [_node_from_row(row) for row in rows]

    def update_node(self, node_id: int, **fields: Any) -> Node:
        allowed = {
            "name",
            "description",
            "roles",
            "state",
            "cert_serial",
            "cert_not_after",
            "seal_pubkey",
            "policy",
            "transport",
            "access",
            "desired_version",
            "applied_version",
            "high_water_version",
            "last_seen",
        }
        unknown = sorted(set(fields) - allowed)
        if unknown:
            raise ValueError(f"unsupported node fields: {', '.join(unknown)}")
        if not fields:
            return self.get_node(node_id)
        values: list[Any] = []
        assignments: list[str] = []
        for key, value in fields.items():
            assignments.append(f"{key} = ?")
            if key in {"roles", "policy", "transport", "access"}:
                values.append(encode_json(value))
            else:
                values.append(value)
        assignments.append("updated_at = ?")
        values.append(utc_now_iso())
        values.append(node_id)
        try:
            with self._write():
                cursor = self.conn.execute(
                    f"UPDATE nodes SET {', '.join(assignments)} WHERE id = ?",
                    tuple(values),
                )
        except sqlite3.IntegrityError as exc:
            raise RegistryConflict(str(exc)) from exc
        if cursor.rowcount == 0:
            raise RegistryNotFound(f"node {node_id} not found")
        return self.get_node(node_id)

    def set_state(self, node_id: int, state: NodeState) -> Node:
        return self.update_node(node_id, state=state)

    def delete_node(self, node_id: int) -> None:
        with self._write():
            cursor = self.conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        if cursor.rowcount == 0:
            raise RegistryNotFound(f"node {node_id} not found")

    def set_prefixes(
        self,
        node_id: int,
        prefixes: Sequence[NodePrefix | Mapping[str, Any]],
    ) -> list[NodePrefix]:
        self.get_node(node_id)
        normalized = [_normalize_prefix(node_id, prefix) for prefix in prefixes]
        try:
            with self._write():
                self.conn.execute("DELETE FROM node_prefixes WHERE node_id = ?", (node_id,))
                self.conn.executemany(
                    """
                    INSERT INTO node_prefixes (node_id, prefix, kind, export)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (prefix.node_id, prefix.prefix, prefix.kind, int(prefix.export))
                        for prefix in normalized
                    ],
                )
        except sqlite3.IntegrityError as exc:
            raise RegistryConflict(str(exc)) from exc
        return self.list_prefixes(node_id)

    def list_prefixes(self, node_id: int | None = None) -> list[NodePrefix]:
        if node_id is None:
            rows = self.conn.execute(
                "SELECT * FROM node_prefixes ORDER BY node_id, prefix"
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM node_prefixes WHERE node_id = ? ORDER BY prefix",
                (node_id,),
            ).fetchall()
        return [_prefix_from_row(row) for row in rows]

    def create_enroll_token(
        self,
        *,
        id: str,
        node_id: int,
        ocserv_user: str,
        secret_hash: str,
        expires_at: str,
    ) -> EnrollToken:
        try:
            with self._write():
                self.conn.execute(
                    """
                    INSERT INTO enroll_tokens (id, node_id, ocserv_user, secret_hash, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (id, node_id, ocserv_user, secret_hash, expires_at),
                )
        except sqlite3.IntegrityError as exc:
            raise RegistryConflict(str(exc)) from exc
        return self.get_enroll_token(id)

    def get_enroll_token(self, token_id: str) -> EnrollToken:
        row = self.conn.execute("SELECT * FROM enroll_tokens WHERE id = ?", (token_id,)).fetchone()
        if row is None:
            raise RegistryNotFound(f"enroll token {token_id!r} not found")
        return _token_from_row(row)

    def list_enroll_tokens(self, node_id: int | None = None) -> list[EnrollToken]:
        if node_id is None:
            rows = self.conn.execute("SELECT * FROM enroll_tokens ORDER BY expires_at").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM enroll_tokens WHERE node_id = ? ORDER BY expires_at", (node_id,)
            ).fetchall()
        return [_token_from_row(row) for row in rows]

    def mark_enroll_token_used(self, token_id: str, used_at: str) -> bool:
        """Atomic one-shot claim: True only for the caller that flipped it."""
        with self._write():
            cursor = self.conn.execute(
                "UPDATE enroll_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL",
                (used_at, token_id),
            )
        return cursor.rowcount == 1

    def delete_enroll_tokens(self, token_ids: Sequence[str]) -> None:
        with self._write():
            self.conn.executemany(
                "DELETE FROM enroll_tokens WHERE id = ?", [(item,) for item in token_ids]
            )

    def add_bundle(
        self,
        *,
        node_id: int,
        version: int,
        body: bytes,
        signature: str,
        sha256: str,
        content_hash: str,
        key_id: str,
        reason: str,
    ) -> StoredBundle:
        try:
            with self._write():
                self.conn.execute(
                    """
                    INSERT INTO bundles (
                      node_id, version, sha256, body, signature, content_hash,
                      key_id, created_at, reason
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        node_id,
                        version,
                        sha256,
                        body,
                        signature,
                        content_hash,
                        key_id,
                        utc_now_iso(),
                        reason,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RegistryConflict(str(exc)) from exc
        return self.get_bundle(node_id, version)

    def get_bundle(self, node_id: int, version: int) -> StoredBundle:
        row = self.conn.execute(
            "SELECT * FROM bundles WHERE node_id = ? AND version = ?", (node_id, version)
        ).fetchone()
        if row is None:
            raise RegistryNotFound(f"bundle {node_id}/{version} not found")
        return _bundle_from_row(row)

    def latest_bundle(self, node_id: int) -> StoredBundle | None:
        row = self.conn.execute(
            "SELECT * FROM bundles WHERE node_id = ? ORDER BY version DESC LIMIT 1", (node_id,)
        ).fetchone()
        return None if row is None else _bundle_from_row(row)

    def list_bundles(self, node_id: int) -> list[StoredBundle]:
        rows = self.conn.execute(
            "SELECT * FROM bundles WHERE node_id = ? ORDER BY version DESC", (node_id,)
        ).fetchall()
        return [_bundle_from_row(row) for row in rows]

    def prune_bundles(self, node_id: int, keep: int) -> int:
        with self._write():
            cursor = self.conn.execute(
                """
                DELETE FROM bundles WHERE node_id = ? AND version NOT IN (
                  SELECT version FROM bundles WHERE node_id = ? ORDER BY version DESC LIMIT ?
                )
                """,
                (node_id, node_id, keep),
            )
        return cursor.rowcount

    def set_external(
        self, node_id: int, name: str, spec: Mapping[str, Any], secrets: bytes | None = None
    ) -> External:
        self.get_node(node_id)
        with self._write():
            self.conn.execute(
                "INSERT OR REPLACE INTO externals (node_id, name, spec, secrets)"
                " VALUES (?, ?, ?, ?)",
                (node_id, name, encode_json(dict(spec)), secrets),
            )
        return next(item for item in self.list_externals(node_id) if item.name == name)

    def list_externals(self, node_id: int) -> list[External]:
        rows = self.conn.execute(
            "SELECT * FROM externals WHERE node_id = ? ORDER BY name", (node_id,)
        ).fetchall()
        return [
            External(
                node_id=int(row["node_id"]),
                name=str(row["name"]),
                spec=decode_json_object(str(row["spec"])),
                secrets=cast(bytes | None, row["secrets"]),
            )
            for row in rows
        ]

    # -- reports, liveness ---------------------------------------------------

    def add_report(
        self,
        node_id: int,
        body: Mapping[str, Any],
        *,
        keep: int = 500,
        received_at: str | None = None,
    ) -> Report:
        stamp = received_at or utc_now_iso()
        with self._write():
            self.conn.execute(
                "INSERT INTO reports (node_id, received_at, body) VALUES (?, ?, ?)",
                (node_id, stamp, encode_json(body)),
            )
            self.conn.execute(
                """
                DELETE FROM reports WHERE node_id = ? AND rowid NOT IN (
                  SELECT rowid FROM reports WHERE node_id = ? ORDER BY rowid DESC LIMIT ?
                )
                """,
                (node_id, node_id, keep),
            )
        return Report(node_id, stamp, dict(body))

    def list_reports(self, node_id: int, limit: int = 50) -> list[Report]:
        rows = self.conn.execute(
            "SELECT * FROM reports WHERE node_id = ? ORDER BY rowid DESC LIMIT ?",
            (node_id, limit),
        ).fetchall()
        return [
            Report(
                int(row["node_id"]), str(row["received_at"]), decode_json_object(str(row["body"]))
            )
            for row in rows
        ]

    def last_agent_versions(self) -> dict[int, str]:
        """`agent_version` of each node's newest report (spec 12 "upgrade required")."""
        rows = self.conn.execute(
            """
            SELECT node_id, json_extract(body, '$.agent_version') AS version FROM reports
            WHERE rowid IN (SELECT MAX(rowid) FROM reports GROUP BY node_id)
            """
        ).fetchall()
        return {
            int(row["node_id"]): row["version"] for row in rows if isinstance(row["version"], str)
        }

    def touch_node(self, node_id: int, *, seen_at: str | None = None) -> None:
        with self._write():
            self.conn.execute(
                "UPDATE nodes SET last_seen = ? WHERE id = ?", (seen_at or utc_now_iso(), node_id)
            )

    def raise_high_water(self, node_id: int, version: int) -> int:
        """Monotonic: a lower value never replaces a higher one (D-37)."""
        with self._write():
            self.conn.execute(
                "UPDATE nodes SET high_water_version = MAX(high_water_version, ?) WHERE id = ?",
                (version, node_id),
            )
        return self.get_node(node_id).high_water_version

    # -- commands ------------------------------------------------------------

    def enqueue_command(
        self,
        node_id: int,
        type_: str,
        args: Mapping[str, Any] | None = None,
        *,
        ttl_seconds: int = COMMAND_TTL_SECONDS,
        now: datetime | None = None,
    ) -> Command:
        moment = now or datetime.now(UTC)
        command_id = secrets.token_hex(8)
        try:
            with self._write():
                self.conn.execute(
                    """
                    INSERT INTO commands (id, node_id, type, args, state, created_at, expires_at)
                    VALUES (?, ?, ?, ?, 'queued', ?, ?)
                    """,
                    (
                        command_id,
                        node_id,
                        type_,
                        encode_json(dict(args or {})),
                        iso_time(moment),
                        iso_time(moment + timedelta(seconds=ttl_seconds)),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RegistryConflict(str(exc)) from exc
        return self.get_command(command_id)

    def get_command(self, command_id: str) -> Command:
        row = self.conn.execute("SELECT * FROM commands WHERE id = ?", (command_id,)).fetchone()
        if row is None:
            raise RegistryNotFound(f"command {command_id} not found")
        return _command_from_row(row)

    def list_commands(self, node_id: int, state: CommandState | None = None) -> list[Command]:
        if state is None:
            rows = self.conn.execute(
                "SELECT * FROM commands WHERE node_id = ? ORDER BY created_at, id", (node_id,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM commands WHERE node_id = ? AND state = ? ORDER BY created_at, id",
                (node_id, state),
            ).fetchall()
        return [_command_from_row(row) for row in rows]

    def claim_commands(self, node_id: int, *, now: datetime | None = None) -> list[Command]:
        """Expire stale queued commands, then mark the rest delivered (at most once)."""
        moment = now or datetime.now(UTC)
        stamp = iso_time(moment)
        with self._write():
            self._expire(node_id, moment)
            rows = self.conn.execute(
                "SELECT id FROM commands WHERE node_id = ? AND state = 'queued' "
                "ORDER BY created_at, id",
                (node_id,),
            ).fetchall()
            ids = [str(row["id"]) for row in rows]
            self.conn.executemany(
                "UPDATE commands SET state = 'delivered', delivered_at = ? WHERE id = ?",
                [(stamp, item) for item in ids],
            )
        return [self.get_command(item) for item in ids]

    def has_queued_commands(self, node_id: int, *, now: datetime | None = None) -> bool:
        stamp = iso_time(now or datetime.now(UTC))
        row = self.conn.execute(
            "SELECT 1 FROM commands "
            "WHERE node_id = ? AND state = 'queued' AND expires_at > ? LIMIT 1",
            (node_id, stamp),
        ).fetchone()
        return row is not None

    def finish_command(
        self,
        node_id: int,
        command_id: str,
        *,
        ok: bool,
        result: Mapping[str, Any],
        now: datetime | None = None,
    ) -> Command:
        """Only the addressed node can finish its own delivered command."""
        with self._write():
            cursor = self.conn.execute(
                "UPDATE commands SET state = ?, finished_at = ?, result = ? "
                "WHERE id = ? AND node_id = ? AND state = 'delivered'",
                (
                    "done" if ok else "failed",
                    iso_time(now or datetime.now(UTC)),
                    encode_json(dict(result)),
                    command_id,
                    node_id,
                ),
            )
        if cursor.rowcount == 0:
            raise RegistryNotFound(f"no delivered command {command_id} for node {node_id}")
        return self.get_command(command_id)

    def expire_commands(self, node_id: int, now: str | datetime) -> None:
        moment = now if isinstance(now, datetime) else _parse_iso(now)
        with self._write():
            self._expire(node_id, moment)

    def _expire(self, node_id: int, now: datetime) -> None:
        """Queued entries past `expires_at`, and delivered entries whose result never
        arrived within DELIVERED_TTL_SECONDS (the agent restarted or lost the batch),
        become `expired`: neither is pending any more nor counts toward the queue cap."""
        stamp = iso_time(now)
        self.conn.execute(
            "UPDATE commands SET state = 'expired', finished_at = ? "
            "WHERE node_id = ? AND state = 'queued' AND expires_at <= ?",
            (stamp, node_id, stamp),
        )
        self.conn.execute(
            "UPDATE commands SET state = 'expired', finished_at = ? "
            "WHERE node_id = ? AND state = 'delivered' AND delivered_at <= ?",
            (stamp, node_id, iso_time(now - timedelta(seconds=DELIVERED_TTL_SECONDS))),
        )

    def quarantine_id(self, node_id: int, until_at: str) -> None:
        with self._write():
            self.conn.execute(
                "INSERT OR REPLACE INTO node_id_quarantine VALUES (?, ?)", (node_id, until_at)
            )

    def quarantined_ids(self, now: str) -> set[int]:
        return {
            int(row[0])
            for row in self.conn.execute(
                "SELECT node_id FROM node_id_quarantine WHERE until_at > ?", (now,)
            )
        }

    def delete_external(self, node_id: int, name: str) -> None:
        with self._write():
            cursor = self.conn.execute(
                "DELETE FROM externals WHERE node_id = ? AND name = ?", (node_id, name)
            )
        if cursor.rowcount == 0:
            raise RegistryNotFound("upstream not found")

    def access_users(self, node_id: int) -> list[dict[str, Any]]:
        return [
            {
                "username": str(row["username"]),
                "pw_hash": row["pw_hash"],
                "groups": json.loads(row["groups"]),
                "enabled": bool(row["enabled"]),
            }
            for row in self.conn.execute(
                "SELECT * FROM access_users WHERE node_id = ? ORDER BY username", (node_id,)
            )
        ]

    def set_access_user(
        self, node_id: int, username: str, pw_hash: str | None, groups: list[str], enabled: bool
    ) -> None:
        with self._write():
            self.conn.execute(
                "INSERT OR REPLACE INTO access_users VALUES (?, ?, ?, ?, ?)",
                (node_id, username, pw_hash, encode_json(groups), int(enabled)),
            )

    def delete_access_user(self, node_id: int, username: str) -> None:
        with self._write():
            cursor = self.conn.execute(
                "DELETE FROM access_users WHERE node_id = ? AND username = ?", (node_id, username)
            )
        if cursor.rowcount == 0:
            raise RegistryNotFound("user not found")

    def dns_records(self) -> list[DnsRecord]:
        return [
            DnsRecord(
                name=str(row["name"]),
                type=cast(DnsRecordType, row["type"]),
                value=str(row["value"]),
                node_id=None if row["node_id"] is None else int(row["node_id"]),
            )
            for row in self.conn.execute("SELECT * FROM dns_records ORDER BY name, type, value")
        ]

    def add_dns_record(self, record: DnsRecord) -> None:
        with self._write():
            try:
                self.conn.execute(
                    "INSERT INTO dns_records (name, type, value, node_id) VALUES (?, ?, ?, ?)",
                    (record.name, record.type, record.value, record.node_id),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistryConflict(str(exc)) from exc

    def delete_dns_record(self, name: str, type_: str, value: str) -> None:
        with self._write():
            cursor = self.conn.execute(
                "DELETE FROM dns_records WHERE name = ? AND type = ? AND value = ?",
                (name, type_, value),
            )
        if cursor.rowcount == 0:
            raise RegistryNotFound("dns record not found")

    def rotation(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM control_rotation WHERE singleton = 1").fetchone()
        return dict(row) if row else None

    def set_rotation(self, active_path: str, next_path: str, started_at: str) -> None:
        with self._write():
            self.conn.execute(
                "INSERT OR REPLACE INTO control_rotation VALUES (1, ?, ?, ?)",
                (active_path, next_path, started_at),
            )

    @contextmanager
    def _write(self) -> Iterator[None]:
        context = nullcontext() if self.conn.in_transaction else transaction(self.conn)
        with context:
            yield


def _node_from_row(row: sqlite3.Row) -> Node:
    state = cast(NodeState, row["state"])
    return Node(
        id=int(row["id"]),
        name=str(row["name"]),
        description=str(row["description"]),
        roles=decode_json_array(str(row["roles"])),
        state=state,
        cert_serial=cast(str | None, row["cert_serial"]),
        cert_not_after=cast(str | None, row["cert_not_after"]),
        seal_pubkey=cast(bytes | None, row["seal_pubkey"]),
        policy=decode_json_object(str(row["policy"])),
        transport=decode_json_object(str(row["transport"])),
        access=decode_json_object(str(row["access"])),
        desired_version=int(row["desired_version"]),
        applied_version=int(row["applied_version"]),
        high_water_version=int(row["high_water_version"]),
        last_seen=cast(str | None, row["last_seen"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _bundle_from_row(row: sqlite3.Row) -> StoredBundle:
    return StoredBundle(
        node_id=int(row["node_id"]),
        version=int(row["version"]),
        sha256=str(row["sha256"]),
        body=bytes(row["body"]),
        signature=str(row["signature"]),
        content_hash=str(row["content_hash"]),
        key_id=str(row["key_id"]),
        created_at=str(row["created_at"]),
        reason=str(row["reason"]),
    )


def _command_from_row(row: sqlite3.Row) -> Command:
    result = cast(str | None, row["result"])
    return Command(
        id=str(row["id"]),
        node_id=int(row["node_id"]),
        type=str(row["type"]),
        args=decode_json_object(str(row["args"])),
        state=cast(CommandState, row["state"]),
        created_at=str(row["created_at"]),
        delivered_at=cast(str | None, row["delivered_at"]),
        finished_at=cast(str | None, row["finished_at"]),
        result=None if result is None else decode_json_object(result),
        expires_at=str(row["expires_at"]),
    )


def _token_from_row(row: sqlite3.Row) -> EnrollToken:
    return EnrollToken(
        id=str(row["id"]),
        node_id=int(row["node_id"]),
        ocserv_user=str(row["ocserv_user"]),
        secret_hash=str(row["secret_hash"]),
        expires_at=str(row["expires_at"]),
        used_at=cast(str | None, row["used_at"]),
    )


def _prefix_from_row(row: sqlite3.Row) -> NodePrefix:
    return NodePrefix(
        node_id=int(row["node_id"]),
        prefix=str(row["prefix"]),
        kind=cast(PrefixKind, row["kind"]),
        export=bool(row["export"]),
    )


def _normalize_prefix(node_id: int, prefix: NodePrefix | Mapping[str, Any]) -> NodePrefix:
    if isinstance(prefix, NodePrefix):
        return replace(prefix, node_id=node_id)
    return NodePrefix(
        node_id=node_id,
        prefix=str(prefix["prefix"]),
        kind=cast(PrefixKind, prefix["kind"]),
        export=bool(prefix.get("export", True)),
    )
