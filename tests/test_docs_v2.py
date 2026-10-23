"""The user-facing docs describe v2 only: removed v1 routing keys and commands must not reappear."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from pydantic import ValidationError
from referencing import Registry, Resource
from tests.test_interlink_rename import _legacy_bundle

from kornode.bundle.models import Bundle
from kornode.net.model import EgressPolicy

ROOT = Path(__file__).resolve().parents[1]
DOCS = (
    "README.md",
    "docs/architecture.md",
    "docs/networking.md",
    "docs/features.md",
    "docs/configuration.md",
)
REMOVED_TERMS = (
    "client_policy",
    "host_policy",
    "host_split",
    r"routing\.fwmark",
    r"routing\.table_id",
    "korctl routes",
    "korctl nft",
    "korctl upstream sync",
    "upstream hook",
    "route_host_enabled",
    "accept_server_routes",
    "sync_url",
    "nft_prefix",
    "RoutingService",
    "external_lists",
    "upstream_pushed",
    r"\bfabric\b",
    r"exit:<",
    r"--role\s+exit\b",
    r"\bkornode\.internal\b",
)
REMOVED = re.compile("|".join(REMOVED_TERMS), re.IGNORECASE)


@pytest.mark.parametrize("name", DOCS)
def test_doc_has_no_removed_v1_terms(name: str) -> None:
    text = (ROOT / name).read_text(encoding="utf-8")
    assert REMOVED.findall(text) == []


def _schema(name: str) -> jsonschema.Draft202012Validator:
    directory = ROOT / "docs/spec/schemas"
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in directory.glob("*.schema.json")
    }
    registry = Registry()
    for filename, schema in schemas.items():
        jsonschema.Draft202012Validator.check_schema(schema)
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(filename, resource)
        registry = registry.with_resource(schema["$id"], resource)
    return jsonschema.Draft202012Validator(schemas[name], registry=registry)


@pytest.mark.parametrize("wire_format", ["v1", "v1_new_aliases", "v1_mixed", "v2"])
def test_runtime_bundle_schema_matches_accepted_rename_inputs(wire_format: str) -> None:
    if wire_format == "v2":
        doc = json.loads((ROOT / "docs/spec/examples/bundle.node3.example.json").read_text())
    else:
        doc = _legacy_bundle()
        if wire_format in {"v1_new_aliases", "v1_mixed"}:
            doc["interlink"] = doc.pop("fabric")
        if wire_format == "v1_new_aliases":
            doc["node"]["interlink_address"] = doc["node"].pop("fabric_address")
            doc["tunnels"]["interlink"] = doc["tunnels"].pop("fabric")
    _schema("bundle.runtime.schema.json").validate(doc)
    bundle = Bundle.model_validate(doc)
    normalized = bundle.model_dump(mode="json", by_alias=True, exclude_none=True)
    _schema("bundle.v2.schema.json").validate(normalized)
    assert normalized["format"] == "kornode.bundle/v2"
    assert "fabric" not in normalized and "fabric" not in normalized["tunnels"]
    assert "exit" not in normalized["node"]["roles"]


@pytest.mark.parametrize("location", ["root", "node", "tunnels"])
def test_schema_and_model_reject_conflicting_legacy_bundle_fields(location: str) -> None:
    doc = _legacy_bundle()
    target = doc if location == "root" else doc[location]
    old, new = (
        ("fabric_address", "interlink_address") if location == "node" else ("fabric", "interlink")
    )
    target[new] = copy.deepcopy(target[old])
    assert not _schema("bundle.runtime.schema.json").is_valid(doc)
    with pytest.raises(ValidationError, match="both"):
        Bundle.model_validate(doc)


@pytest.mark.parametrize("rename_location", ["root", "node", "tunnels"])
def test_v2_does_not_accept_old_bundle_field_names(rename_location: str) -> None:
    doc = json.loads((ROOT / "docs/spec/examples/bundle.node3.example.json").read_text())
    target = doc if rename_location == "root" else doc[rename_location]
    old, new = (
        ("fabric_address", "interlink_address")
        if rename_location == "node"
        else ("fabric", "interlink")
    )
    target[old] = target.pop(new)
    assert not _schema("bundle.runtime.schema.json").is_valid(doc)
    with pytest.raises(ValidationError):
        Bundle.model_validate(doc)


@pytest.mark.parametrize("via", ["fabric", "interlink", "exit:3", "node:3"])
def test_policy_schema_documents_accepted_d84_d85_aliases(via: str) -> None:
    doc = {"egress": [{"from": ["fabric"], "to": "fabric", "via": via}]}
    _schema("egress.v1.schema.json").validate(doc)
    policy = EgressPolicy.model_validate(doc)
    normalized = policy.model_dump(mode="json", by_alias=True, exclude_none=True)
    _schema("egress.v1.schema.json").validate(normalized)
    assert normalized["egress"][0]["from"] == ["interlink"]
    assert normalized["egress"][0]["to"] == "interlink"


@pytest.mark.parametrize(
    "doc",
    [
        {"egress": [{"from": ["fabric", "interlink"], "to": "any", "via": "local"}]},
        {"sources": [{"name": "fabric", "interface": "eth1", "cidr": "192.0.2.0/24"}]},
        {"sources": [{"name": "interlink", "interface": "eth1", "cidr": "192.0.2.0/24"}]},
    ],
)
def test_policy_schema_and_model_reject_alias_collisions(doc: dict[str, Any]) -> None:
    assert not _schema("egress.v1.schema.json").is_valid(doc)
    with pytest.raises(ValidationError):
        EgressPolicy.model_validate(doc)


def test_documented_v2_bundle_has_current_minimum_agent_version() -> None:
    example = json.loads((ROOT / "docs/spec/examples/bundle.node3.example.json").read_text())
    assert example["format"] == "kornode.bundle/v2"
    assert example["min_agent_version"] == "2.1.0"
