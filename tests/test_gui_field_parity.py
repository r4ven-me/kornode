"""Scoped field parity, not a claim that every AppConfig field is covered.

The same inventory drives rendered-control/payload tests in the frontend.
Model field-set equality fails if one of the covered models gains an unbound field.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, get_args

import yaml

from kornode.api.routes_web_config import ControlSettingsRequest
from kornode.config.models import ControlConfig, GroupPolicyConfig

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "frontend/src/configFieldInventory.json"


def test_scoped_inventory_covers_authoritative_model_fields_and_exact_capabilities() -> None:
    inventory = json.loads(INVENTORY.read_text())
    assert "not proof of complete AppConfig coverage" in inventory["scope"]
    assert {item["name"] for item in inventory["models"]} == {
        "ControlConfig",
        "Source",
        "DestSet",
        "GroupPolicyConfig",
    }
    capabilities = {
        item["id"]: item
        for item in yaml.safe_load((ROOT / "parity.yaml").read_text())["capabilities"]
    }
    for item in inventory["models"]:
        model = getattr(importlib.import_module(item["module"]), item["name"])
        fields: dict[str, Any] = model.model_fields
        if item["coverage"] == "all_fields":
            expected = set(fields)
        else:
            assert item["coverage"] == "nullable_boolean_fields"
            expected = {
                name
                for name, field in fields.items()
                if set(get_args(field.annotation)) == {bool, type(None)}
            }
        assert set(item["fields"]) == expected, item["name"]
        for surface in item["surfaces"]:
            capability = capabilities[surface["marker"]]
            assert capability["ui"] == surface["marker"]
            assert capability["api"] == surface["api"]
            assert (ROOT / "frontend/src" / surface["file"]).is_file()
            if "fields_file" in surface:
                assert (ROOT / "frontend/src" / surface["fields_file"]).is_file()
        for name, field in item["fields"].items():
            assert field["binding"]
            assert field["control"] in {"text", "number", "checkbox", "textarea", "select"}
            if "states" in field:
                for state in field["states"]:
                    group = GroupPolicyConfig.model_validate(
                        {"name": "test", name: state["model_value"]}
                    )
                    assert getattr(group, name) is state["model_value"]
                assert {state["value"] for state in field["states"]} == {"inherit", "true", "false"}


def test_control_settings_request_inherits_model_types_without_path_exception() -> None:
    assert set(ControlSettingsRequest.model_fields) == set(ControlConfig.model_fields)
    for name, field in ControlConfig.model_fields.items():
        assert ControlSettingsRequest.model_fields[name].annotation == field.annotation
    data = ControlSettingsRequest(signing_key=Path("/deployment/signing.pem"))
    assert isinstance(data.signing_key, Path)
    assert data.model_dump(mode="json", exclude_unset=True) == {
        "signing_key": "/deployment/signing.pem"
    }
    assert ControlSettingsRequest(signing_key=None).model_dump(exclude_unset=True) == {
        "signing_key": None
    }
    assert ControlSettingsRequest().model_dump(exclude_unset=True) == {}
