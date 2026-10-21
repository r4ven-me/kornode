from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from kornode.config.models import AppConfig
from kornode.registry.models import Node
from kornode.services.hub_egress import HubEgressError, check_hub_policy


def cfg(**extra: Any) -> AppConfig:
    return AppConfig.model_validate(extra)


def node(id_: int, roles: list[str], state: str = "active") -> Node:
    return Node(
        id=id_, name=f"n{id_}", description="", roles=roles, state=state,  # type: ignore[arg-type]
        cert_serial=None, cert_not_after=None, seal_pubkey=None, policy={}, transport={},
        desired_version=0, applied_version=0, high_water_version=0, last_seen=None,
        created_at="", updated_at="",
    )  # fmt: skip


SRC = {"name": "wg", "interface": "wg0", "cidr": "10.8.1.0/24"}


def test_default_policy_lets_clients_out_locally() -> None:
    config = cfg()
    assert config.sources == () and config.sets == {}
    (rule,) = config.egress
    assert (rule.from_, rule.to, rule.via) == (("clients",), "any", "local")
    assert cfg(egress=[]).egress == ()


def test_valid_policy_parses() -> None:
    config = cfg(sources=[SRC], egress=[{"from": ["wg", "clients"], "to": "any", "via": "local"}])
    assert config.egress_policy().sources[0].name == "wg"


@pytest.mark.parametrize(
    "extra",
    [
        {"egress": [{"from": ["nope"], "to": "any", "via": "local"}]},
        {"egress": [{"from": ["clients"], "to": {"set": "x"}, "via": "local"}]},
        {"sources": [SRC, SRC]},
        {"sources": [{**SRC, "name": "clients"}]},
        {"sources": [{**SRC, "cidr": "192.168.9.0/24"}]},
        {"sources": [{**SRC, "cidr": "10.100.1.0/24", "allow_outside_pool": True}]},
        {"sources": [{**SRC, "cidr": "10.99.0.0/25", "allow_outside_pool": True}]},
        {"sources": [SRC, {**SRC, "name": "wg2", "cidr": "10.8.1.0/25"}]},
        {"sources": [SRC, {**SRC, "name": "wg2", "cidr": "10.8.1.0/24"}]},
        {"egress": [{"from": ["host"], "to": "any", "via": "exit:2"}]},
        {
            "sources": [{**SRC, "export": False}],
            "egress": [{"from": ["wg"], "to": "any", "via": "exit:2"}],
        },
    ],
)  # fmt: skip
def test_invalid_policy_rejected(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        cfg(**extra)


def test_outside_pool_allowed_when_requested() -> None:
    cfg(sources=[{**SRC, "cidr": "192.168.9.0/24", "allow_outside_pool": True}])


def test_old_policy_keys_are_unknown_at_top_level() -> None:
    with pytest.raises(ValidationError):
        cfg(client_policy="full")


EXIT = {"egress": [{"from": ["clients"], "to": "any", "via": "exit:2"}]}


def test_exit_target_must_be_active_exit_agent() -> None:
    check_hub_policy(cfg(**EXIT), [node(2, ["exit"])])
    for nodes, code in (
        ([], "exit_node"),
        ([node(2, ["exit"], "revoked")], "exit_node"),
        ([node(2, ["access"])], "role_required"),
    ):
        with pytest.raises(HubEgressError) as err:
            check_hub_policy(cfg(**EXIT), nodes)
        assert err.value.code == code


def test_exit_to_hub_or_set_is_rejected() -> None:
    with pytest.raises(HubEgressError):
        check_hub_policy(cfg(egress=[{"from": ["clients"], "to": "any", "via": "exit:1"}]), [])
    both = {
        "sets": {"s": {"routes": ["10.1.0.0/16"]}},
        "egress": [{"from": ["clients"], "to": {"set": "s"}, "via": "exit:2"}],
    }
    with pytest.raises(HubEgressError) as err:
        check_hub_policy(cfg(**both), [node(2, ["exit"])])
    assert err.value.code == "runtime_unsupported"


def test_unknown_upstream_rejected() -> None:
    with pytest.raises(HubEgressError) as err:
        check_hub_policy(cfg(egress=[{"from": ["clients"], "to": "any", "via": "upstream:x"}]), [])
    assert err.value.code == "unknown_upstream"
