"""Checks of the hub egress policy that need more than the config file: the registry
(`node:<n>` targets, D-69, D-84) and the configured upstream profiles. Pure; kernel state is
never touched here."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from kornode.config.loader import load_yaml_file, validate_config_data
from kornode.config.models import AppConfig, profile_slug
from kornode.net.compile import dead_rules
from kornode.net.model import EgressPolicy, InlineDest, SetRef, Source
from kornode.registry.db import migrate, open_registry
from kornode.registry.models import Node
from kornode.registry.repository import Registry
from kornode.services.agent_models import ManagementError
from kornode.services.config_store import ConfigApplyError, ConfigPreflightError, mutate_config
from kornode.services.net import NetService
from kornode.services.secrets import sanitized_validation_errors


class HubEgressError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_hub_policy(
    policy: EgressPolicy, nodes: Iterable[Node], upstreams: Iterable[str]
) -> None:
    by_id = {node.id: node for node in nodes}
    known_upstreams = {*upstreams, "active"}
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
                "inline destination, not `fabric` or a node",
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
        candidate = self._commit(data)
        policy = candidate.egress_policy()
        return {"policy": _dump(policy), **_warning_fields(policy)}

    def set_source(self, name: str, data: dict[str, Any] | None) -> dict[str, Any]:
        def mutation(raw: dict[str, Any]) -> dict[str, Any]:
            current = _dump(self._validate_candidate(raw).egress_policy())
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
            return self._raw(current, raw)

        self._mutate(mutation)
        return self.policy() | self.sources()

    def _raw(self, data: dict[str, Any], base: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            policy = EgressPolicy.model_validate(data)
        except ValidationError as exc:
            raise _invalid(exc) from None
        raw = dict(load_yaml_file(self.path) if base is None else base)
        dumped = _dump(policy)
        # Empty values are explicit overrides, not permission to revive env policy.
        raw.update({key: dumped[key] for key in ("sources", "sets", "egress")})
        return raw

    def _candidate(self, data: dict[str, Any]) -> AppConfig:
        return self._validate_candidate(self._raw(data))

    def _validate_candidate(self, raw: dict[str, Any]) -> AppConfig:
        try:
            candidate = validate_config_data(raw, self.path)
        except ValidationError as exc:
            raise _invalid(exc) from None
        except ValueError:
            raise ManagementError(422, "invalid", "Invalid configuration") from None
        try:
            check_hub_policy(candidate, self._nodes(candidate))
        except HubEgressError as exc:
            raise ManagementError(409, exc.code, str(exc)) from None
        return candidate

    def _commit(self, data: dict[str, Any]) -> AppConfig:
        return self._mutate(lambda raw: self._raw(data, raw))

    def _mutate(self, mutation: Callable[[dict[str, Any]], dict[str, Any]]) -> AppConfig:
        def checked(current: dict[str, Any]) -> dict[str, Any]:
            raw = mutation(current)
            self._validate_candidate(raw)
            return raw

        def install(config: AppConfig) -> None:
            self.config = config
            if self.saved is not None:
                self.saved(config)

        try:
            loaded, _ = mutate_config(self.path, checked, on_commit=install, after_apply=self.sync)
        except ConfigPreflightError:
            raise ManagementError(
                500, "not_saved", "Render preflight failed; config not saved"
            ) from None
        except ConfigApplyError:
            raise ManagementError(
                500, "saved_but_not_applied", "Config saved; runtime application failed"
            ) from None
        return loaded

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
        NetService(config).wake()


def _invalid(exc: ValidationError) -> ManagementError:
    fields = [".".join(str(part) for part in error["loc"]) for error in exc.errors()]
    messages = [str(error["msg"]) for error in sanitized_validation_errors(exc.errors())]
    return ManagementError(422, "invalid", "; ".join(messages), fields)
