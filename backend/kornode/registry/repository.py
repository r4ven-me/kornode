from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from typing import Any, cast

from kornode.registry.db import RegistryError, transaction
from kornode.registry.models import (
    Node,
    NodePrefix,
    NodeState,
    PrefixKind,
    decode_json_array,
    decode_json_object,
    encode_json,
    utc_now_iso,
)


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
            if key in {"roles", "policy", "transport"}:
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
        desired_version=int(row["desired_version"]),
        applied_version=int(row["applied_version"]),
        high_water_version=int(row["high_water_version"]),
        last_seen=cast(str | None, row["last_seen"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
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
