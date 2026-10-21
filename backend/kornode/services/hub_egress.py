"""Checks of the hub egress policy that need more than the config file: the registry
(`exit:<n>` targets, D-69) and the configured upstream profiles. Pure; kernel state is
never touched here."""

from __future__ import annotations

from collections.abc import Iterable

from kornode.config.legacy import profile_slug
from kornode.config.models import AppConfig
from kornode.net.model import EgressPolicy
from kornode.registry.models import Node


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
        if via.kind != "exit":
            continue
        target = int(via.target or 0)
        node = by_id.get(target)
        if target == 1 or node is None or node.state != "active":
            raise HubEgressError(
                "exit_node", f"egress[{index}]: exit:{target} needs an active agent with role exit"
            )
        if "exit" not in node.roles:
            raise HubEgressError("role_required", f"egress[{index}]: agent {node.name} lacks exit")
        if rule.to != "any":
            raise HubEgressError(
                "runtime_unsupported",
                f"egress[{index}]: exit via another node supports `to: any` only",
            )


def check_hub_policy(config: AppConfig, nodes: Iterable[Node]) -> None:
    slugs = [profile_slug(profile.name) for profile in config.upstream.profiles]
    validate_hub_policy(config.egress_policy(), nodes, slugs)
