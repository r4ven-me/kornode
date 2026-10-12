from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from kornode.config.legacy import InlineLists, legacy_policy, profile_slug
from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.net.errors import PolicyError

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = sorted((ROOT / "examples").glob("*.yaml"))
GOLDEN = Path(__file__).resolve().parent / "golden" / "legacy"


def _dump(config: AppConfig) -> str:
    policy = legacy_policy(config, InlineLists(config))
    data = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _example_secrets(path: Path) -> dict[str, str]:
    # Examples reference ${SECRET:NAME}; routing doesn't care about values.
    names = re.findall(r"\$\{SECRET:([A-Z0-9_]+)\}", path.read_text(encoding="utf-8"))
    return {name: "example-secret" for name in names}


@pytest.mark.parametrize("path", EXAMPLES, ids=[path.stem for path in EXAMPLES])
def test_every_example_translates_to_golden(path: Path, update_golden: bool) -> None:
    config = load_config(path, environ=_example_secrets(path))
    text = _dump(config)
    golden = GOLDEN / f"{path.stem}.json"
    if update_golden:
        golden.write_text(text, encoding="utf-8")
    assert text == golden.read_text(encoding="utf-8")


def _config(**sections: Any) -> AppConfig:
    return AppConfig.model_validate(sections)


def _rules(config: AppConfig) -> list[tuple[str, tuple[str, ...], Any, str]]:
    policy = legacy_policy(config, InlineLists(config))
    return [
        (
            rule.id or "",
            rule.from_,
            rule.model_dump(mode="json", by_alias=True)["to"],
            rule.via,
        )
        for rule in policy.egress
    ]


PROFILE = {"name": "office", "server": "vpn.example.org", "username": "u"}


def test_upstream_disabled_gives_clients_plain_local() -> None:
    assert _rules(_config()) == [("clients-local", ("clients",), "any", "local")]


def test_client_full_and_host_full() -> None:
    config = _config(
        upstream={"enabled": True, "profiles": [PROFILE]},
        routing={"client_policy": "full", "host_policy": "full"},
    )

    assert _rules(config) == [
        ("clients-full", ("clients",), "any", "upstream:office"),
        ("host-full", ("host",), "any", "upstream:office"),
    ]


def test_client_split_falls_back_to_local() -> None:
    config = _config(
        upstream={"enabled": True, "profiles": [PROFILE]},
        routing={"client_policy": "split", "split": {"routes": ["10.20.0.0/16"],
                                                     "domains": ["corp.example.com"]}},
    )
    policy = legacy_policy(config, InlineLists(config))

    assert _rules(config) == [
        ("clients-split", ("clients",), {"set": "split"}, "upstream:office"),
        ("clients-local", ("clients",), "any", "local"),
    ]
    assert policy.sets["split"].routes == ("10.20.0.0/16",)
    assert policy.sets["split"].domains == ("corp.example.com",)


def test_named_profiles_come_before_defaults() -> None:
    config = _config(
        upstream={
            "enabled": True,
            "active_profile": "office",
            "profiles": [
                PROFILE,
                {**PROFILE, "name": "finance", "routes": ["10.50.0.0/16"],
                 "route_host_enabled": True, "host_routes": ["10.51.0.0/16"]},
            ],
        },
        routing={"client_policy": "full", "host_policy": "full"},
    )

    assert _rules(config) == [
        ("p-finance", ("clients",), {"set": "p_finance"}, "upstream:finance"),
        ("p-finance-host", ("host",), {"set": "p_finance_host"}, "upstream:finance"),
        ("clients-full", ("clients",), "any", "upstream:office"),
        ("host-full", ("host",), "any", "upstream:office"),
    ]


def test_empty_split_lists_produce_no_rule() -> None:
    config = _config(
        upstream={"enabled": True, "profiles": [PROFILE]},
        routing={"client_policy": "split", "host_policy": "split"},
    )

    assert _rules(config) == [("clients-local", ("clients",), "any", "local")]


def test_profile_names_become_valid_exit_names() -> None:
    assert profile_slug("Office-VPN") == "office_vpn"
    assert profile_slug("1st") == "p1st"
    assert len(profile_slug("x" * 60)) == 22


def test_colliding_slugs_are_rejected() -> None:
    config = _config(
        upstream={
            "enabled": True,
            "profiles": [{**PROFILE, "name": "1a"}, {**PROFILE, "name": "p1a"}],
        }
    )

    with pytest.raises(PolicyError, match="collide"):
        legacy_policy(config, InlineLists(config))
