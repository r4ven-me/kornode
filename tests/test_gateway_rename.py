"""D-84: the role `exit` is now `gateway` and `via: exit:<n>` is `via: node:<n>`. Data
written before the rename keeps working: config and registry policies, registry roles,
cached bundles and agent reports."""

from __future__ import annotations

import json
from pathlib import Path

from kornode.bundle.models import NodeInfo
from kornode.control.service import ReportBody
from kornode.net.lists import parse_gateway_sets, report_gateway_sets
from kornode.net.model import EgressPolicy, Via
from kornode.registry.db import _load_migrations, migrate, open_registry
from kornode.registry.repository import Registry
from kornode.services.bundle import policy_with_implicit_rules


def test_a_rule_written_as_exit_is_read_and_written_back_as_node() -> None:
    policy = EgressPolicy.model_validate(
        {"egress": [{"from": ["clients"], "to": "any", "via": "exit:3"}]}
    )

    assert policy.egress[0].parsed_via == Via("node", "3")
    assert policy.model_dump(by_alias=True)["egress"][0]["via"] == "node:3"


def test_a_stored_agent_policy_with_exit_reaches_the_bundle_as_node() -> None:
    stored = {"egress": [{"from": ["clients"], "to": "any", "via": "exit:3"}]}

    rules = policy_with_implicit_rules(stored, ["access"])["egress"]

    assert [rule["via"] for rule in rules if rule["from"] == ["clients"]] == ["node:3"]
    assert stored["egress"][0]["via"] == "exit:3"  # the registry copy is not mutated


def test_registry_migration_renames_the_exit_role(tmp_path: Path) -> None:
    before = [item for item in _load_migrations() if item[0] < 4]
    with open_registry(tmp_path / "registry.db") as conn:
        migrate(conn, migrations=before)
        Registry(conn).create_node(id=2, name="out", roles=["access", "exit"])
        Registry(conn).create_node(id=3, name="branch", roles=["access"])

        migrate(conn)

        assert Registry(conn).get_node(2).roles == ["access", "gateway"]
        assert Registry(conn).get_node(3).roles == ["access"]


def test_a_cached_bundle_with_the_exit_role_still_loads() -> None:
    info = NodeInfo.model_validate(
        {
            "name": "out",
            "roles": ["exit"],
            "interlink_address": "10.99.0.2",
            "service_address": "10.100.2.1",
            "client_pool": "10.100.2.0/24",
        }
    )

    assert info.roles == ("gateway",)


def test_a_report_with_exit_sets_is_accepted_and_read() -> None:
    sent = {"agent_version": "2.0.0", "applied_version": 1, "exit_sets": {"web": ["203.0.113.9"]}}

    ReportBody.model_validate(sent)

    assert parse_gateway_sets(report_gateway_sets(json.loads(json.dumps(sent)))) == {
        "web": frozenset({"203.0.113.9/32"})
    }
