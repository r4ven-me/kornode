from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

type NodeState = Literal["pending", "active", "revoked"]
type PrefixKind = Literal["pool", "source", "lan"]


@dataclass(frozen=True)
class Node:
    id: int
    name: str
    description: str
    roles: list[str]
    state: NodeState
    cert_serial: str | None
    cert_not_after: str | None
    seal_pubkey: bytes | None
    policy: dict[str, Any]
    transport: dict[str, Any]
    desired_version: int
    applied_version: int
    high_water_version: int
    last_seen: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class NodePrefix:
    node_id: int
    prefix: str
    kind: PrefixKind
    export: bool


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def encode_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def decode_json_array(value: str) -> list[str]:
    data = json.loads(value)
    if not isinstance(data, list):
        raise ValueError("expected JSON array")
    return [str(item) for item in data]


def decode_json_object(value: str) -> dict[str, Any]:
    data = json.loads(value)
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    return data
