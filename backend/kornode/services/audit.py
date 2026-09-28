from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

from kornode.config.models import AppConfig


class AuditService:
    def __init__(self, config: AppConfig) -> None:
        self.path = config.system.log_dir / "audit.jsonl"

    def record(
        self,
        *,
        actor: str,
        action: str,
        outcome: str,
        source_ip: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "actor": actor,
            "action": action,
            "outcome": outcome,
            "source_ip": source_ip,
            "details": details or {},
        }
        line = json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n"
        # No fsync: this runs synchronously in the request path on every
        # mutating API call, and the audit trail doesn't need durability
        # guarantees strong enough to justify a forced disk flush there.
        fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
