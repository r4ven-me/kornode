"""Checks of the hub egress policy that need more than the config file: the registry
(`node:<n>` targets, D-69, D-84) and the configured upstream profiles. Pure; kernel state is
never touched here."""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from kornode.config.loader import load_config, load_yaml_file
from kornode.config.models import AppConfig, profile_slug
from kornode.net.compile import dead_rules
from kornode.net.model import EgressPolicy, InlineDest, SetRef, Source
from kornode.registry.db import migrate, open_registry
from kornode.registry.models import Node
from kornode.registry.repository import Registry
from kornode.services.agent_models import ManagementError
from kornode.services.config import ConfigService
from kornode.services.files import FileManager
from kornode.services.net import NetService


class HubEgressError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_hub_policy(
    policy: EgressPolicy, nodes: Iterable[Node], upstreams: Iterable[str]
) -> None:
    by_id = {node.id: node for node in nodes}
    known_upstreams = set(upstreams)
    for index, rule in enumerate(policy.egress):
        via = rule.parsed_via
        if via.kind == "upstream" and via.target not in known_upstreams:
            raise HubEgressError(
                "unknown_upstream", f"egress[{index}]: upstream {via.target!r} is not configured"
            )
        if via.kind != "node":
            continue
        target = int(via.target or 0)
        node = by_id.get(target)
        if target == 1 or node is None or node.state != "active":
            raise HubEgressError(
                "gateway_node",
                f"egress[{index}]: node:{target} needs an active agent with role gateway",
            )
        if "gateway" not in node.roles:
            raise HubEgressError(
                "role_required", f"egress[{index}]: agent {node.name} lacks role gateway"
            )
        if not (rule.to == "any" or isinstance(rule.to, SetRef | InlineDest)):
            raise HubEgressError(
                "runtime_unsupported",
                f"egress[{index}]: leaving through another node supports `to: any`, a set or an "
                "inline destination, not `interlink` or a node",
            )


def check_hub_policy(config: AppConfig, nodes: Iterable[Node]) -> None:
    slugs = [profile_slug(profile.name) for profile in config.upstream.profiles]
    validate_hub_policy(config.egress_policy(), nodes, slugs)


def _warning_fields(policy: EgressPolicy) -> dict[str, Any]:
    """Dead-rule findings as text (CLI) and as indices (the panel marks rows with them)."""
    dead = dead_rules(policy)
    return {
        "warnings": [f"rule {rule} is shadowed by rule {by}" for rule, by in dead],
        "dead_rules": [{"rule": rule, "shadowed_by": by} for rule, by in dead],
    }


def _dump(policy: EgressPolicy) -> dict[str, Any]:
    dumped: dict[str, Any] = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    return {
        "sources": dumped.get("sources", []),
        "sets": dumped.get("sets", {}),
        "egress": dumped.get("egress", []),
    }


class HubEgressService:
    """The hub's `egress`/`sources`/`sets` (P4-06 part 2): one writer of those config keys
    for CLI, API and panel. A change is validated as a whole config, written atomically,
    rendered (bundles, per-user routes) and handed to the reconciler -- never applied to
    the kernel here."""

    def __init__(
        self,
        config: AppConfig,
        path: Path,
        *,
        saved: Callable[[AppConfig], None] | None = None,
        sync: Callable[[AppConfig], None] | None = None,
    ) -> None:
        self.config = config
        self.path = path
        self.saved = saved
        self.sync = sync or self._sync

    def policy(self) -> dict[str, Any]:
        policy = self.config.egress_policy()
        return {
            "policy": _dump(policy),
            **_warning_fields(policy),
        }

    def sources(self) -> dict[str, Any]:
        return {"sources": _dump(self.config.egress_policy())["sources"]}

    def check(self, data: dict[str, Any]) -> dict[str, Any]:
        candidate = self._candidate(data)
        return {"valid": True, **_warning_fields(candidate.egress_policy())}

    def set_policy(self, data: dict[str, Any]) -> dict[str, Any]:
        candidate = self._candidate(data)
        self._commit(data)
        policy = candidate.egress_policy()
        return {"policy": _dump(policy), **_warning_fields(policy)}

    def set_source(self, name: str, data: dict[str, Any] | None) -> dict[str, Any]:
        current = _dump(self.config.egress_policy())
        old = current["sources"]
        if data is None and not any(item["name"] == name for item in old):
            raise ManagementError(404, "not_found", "source not found")
        current["sources"] = [item for item in old if item["name"] != name]
        if data is not None:
            try:
                source = Source.model_validate({**data, "name": name})
            except ValidationError as exc:
                raise _invalid(exc) from None
            current["sources"].append(source.model_dump(mode="json", exclude_defaults=True))
        return self.set_policy(current) | {"sources": current["sources"]}

    def _raw(self, data: dict[str, Any]) -> dict[str, Any]:
        try:
            policy = EgressPolicy.model_validate(data)
        except ValidationError as exc:
            raise _invalid(exc) from None
        raw = load_yaml_file(self.path)
        dumped = _dump(policy)
        raw["sources"] = dumped["sources"]
        raw["egress"] = dumped["egress"]  # `egress: []` must stay explicit: absent means default
        if dumped["sets"]:
            raw["sets"] = dumped["sets"]
        else:
            raw.pop("sets", None)
        if not dumped["sources"]:
            raw.pop("sources", None)
        return raw

    def _candidate(self, data: dict[str, Any]) -> AppConfig:
        raw = self._raw(data)
        # The loader validates the whole file (env overrides, secret refs, address checks)
        # exactly as a restart would, so it reads a sibling copy and never the live file.
        with tempfile.NamedTemporaryFile(
            "w", dir=self.path.parent, prefix=".egress-check-", suffix=".yaml", delete=False
        ) as handle:
            temp = Path(handle.name)
            handle.write(yaml.safe_dump(raw, sort_keys=False))
        try:
            candidate = load_config(temp)
        except ValidationError as exc:
            raise _invalid(exc) from None
        except ValueError as exc:
            raise ManagementError(422, "invalid", str(exc)) from None
        finally:
            temp.unlink(missing_ok=True)
        try:
            check_hub_policy(candidate, self._nodes(candidate))
        except HubEgressError as exc:
            raise ManagementError(409, exc.code, str(exc)) from None
        return candidate

    def _commit(self, data: dict[str, Any]) -> None:
        raw = self._raw(data)
        FileManager().atomic_write_text(self.path, yaml.safe_dump(raw, sort_keys=False), mode=0o600)
        loaded = load_config(self.path)
        self.config = loaded
        if self.saved is not None:
            self.saved(loaded)
        self.sync(loaded)

    @staticmethod
    def _nodes(config: AppConfig) -> list[Node]:
        db = config.system.data_dir / "registry.db"
        if not db.exists():
            return []
        conn = open_registry(db)
        try:
            migrate(conn)
            return Registry(conn).list_nodes()
        finally:
            conn.close()

    @staticmethod
    def _sync(config: AppConfig) -> None:
        ConfigService().write_rendered_files(config)
        NetService(config).wake()


def _invalid(exc: ValidationError) -> ManagementError:
    fields = [".".join(str(part) for part in error["loc"]) for error in exc.errors()]
    messages = [str(error["msg"]) for error in exc.errors()]
    return ManagementError(422, "invalid", "; ".join(messages), fields)
