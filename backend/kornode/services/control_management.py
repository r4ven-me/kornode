"""Operator control-plane status and durable, staged signing-key rotation."""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from kornode.bundle.signing import key_id, load_or_create_signing_key
from kornode.config.models import AppConfig
from kornode.registry.db import transaction
from kornode.services.agent_models import ManagementError
from kornode.services.agents import AgentService
from kornode.services.bundle import BundleService


class ControlManagement:
    def __init__(
        self,
        config: AppConfig,
        *,
        bundles: BundleService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self.clock = clock or (lambda: datetime.now(UTC))
        self.bundles = bundles or BundleService(config, clock=self.clock)
        self.agents = AgentService(config, bundles=self.bundles, clock=self.clock)

    def status(self) -> dict[str, Any]:
        if not self.config.fabric.enabled:
            return {
                "enabled": self.config.control.enabled,
                "fabric_enabled": False,
                "agents": 0,
                "rotation": None,
                "signing_key_id": None,
            }
        with self.agents.registry() as registry:
            nodes = [n for n in registry.list_nodes() if n.id != 1]
            rotation = registry.rotation()
            view = None
            if rotation:
                deadline = datetime.fromisoformat(
                    rotation["started_at"].replace("Z", "+00:00")
                ) + timedelta(days=7)
                # Promotion is time-based (spec 05); the operator must still see
                # which active agents have not applied a bundle carrying the
                # announcement, as they would be locked out on promotion.
                unconfirmed: list[str] = []
                for node in nodes:
                    if node.state != "active":
                        continue
                    latest = registry.latest_bundle(node.id)
                    announced = bool(latest and json.loads(latest.body).get("next_signing_pubkey"))
                    if latest is None or not announced or node.applied_version < latest.version:
                        unconfirmed.append(node.name)
                view = {
                    "unconfirmed_agents": unconfirmed,
                    "started_at": rotation["started_at"],
                    "promotes_at": deadline.isoformat(),
                    "phase": "announcing" if self.clock() < deadline else "promoted",
                    "warning": "Agents offline during announcement may need re-enrollment.",
                }
            path, _ = self.bundles.key_plan(registry)
            signer = (
                key_id(load_or_create_signing_key(path).public_key()) if path.exists() else None
            )
            return {
                "enabled": self.config.control.enabled,
                "fabric_enabled": True,
                "control_url": self.bundles.control_url(),
                "agents": len(nodes),
                "active": sum(n.state == "active" for n in nodes),
                "signing_key_id": signer,
                "rotation": view,
                "offline_after_seconds": self.config.control.offline_after_seconds,
            }

    def rotate(self, *, dry_run: bool = False) -> dict[str, Any]:
        with self.agents.exclusive():
            with self.agents.registry() as registry, transaction(registry.conn):
                existing = registry.rotation()
                if existing:
                    deadline = datetime.fromisoformat(
                        existing["started_at"].replace("Z", "+00:00")
                    ) + timedelta(days=7)
                    if self.clock() < deadline:
                        raise ManagementError(
                            409,
                            "rotation_in_progress",
                            "a signing-key announcement is already in progress",
                        )
                if dry_run:
                    return {
                        "dry_run": True,
                        "announcement_days": 7,
                        "agents": len([n for n in registry.list_nodes() if n.id != 1]),
                    }
                active, _ = self.bundles.key_plan(registry)
                load_or_create_signing_key(active)
                upcoming = self.bundles.control_dir / f"rotation-{secrets.token_hex(12)}.ed25519"
                load_or_create_signing_key(upcoming)
                # Key creation is publish-once; the transaction is the only
                # authoritative pointer. A rolled-back attempt leaves a harmless
                # unreferenced key, never a half-published signing identity.
                registry.set_rotation(str(active), str(upcoming), self.clock().isoformat())
                self.bundles.compile_all(registry, "announce signing key")
            self.agents._audit("control.rotate_signing_key", "hub")
            return self.status()
