from __future__ import annotations

import logging
from pathlib import Path

import pytest

from kornode.config.loader import load_config
from kornode.config.models import RoutingConfig


def test_legacy_mode_becomes_client_policy() -> None:
    config = RoutingConfig.model_validate({"mode": "split"})

    assert config.client_policy == "split"


def test_legacy_client_traffic_off_becomes_client_policy_off_whatever_mode() -> None:
    config = RoutingConfig.model_validate({"mode": "split", "client_traffic": False})

    assert config.client_policy == "off"


def test_legacy_client_traffic_string_off_is_off() -> None:
    # An env override can deliver the word, not a bool.
    config = RoutingConfig.model_validate({"client_traffic": "off"})

    assert config.client_policy == "off"


def test_legacy_defaults_keep_upgraded_clients_routed_full() -> None:
    # Before the policy keys, client traffic was on and mode full by default.
    config = RoutingConfig.model_validate({})

    assert config.client_policy == "full"
    assert config.host_policy == "off"


def test_legacy_host_traffic_on_uses_host_mode() -> None:
    config = RoutingConfig.model_validate({"host_traffic": True, "host_mode": "split"})

    assert config.host_policy == "split"


def test_legacy_host_mode_without_host_traffic_stays_off() -> None:
    # host_mode alone never enabled host traffic before the rewrite.
    config = RoutingConfig.model_validate({"host_mode": "split"})

    assert config.host_policy == "off"


def test_legacy_host_traffic_on_without_host_mode_is_full() -> None:
    config = RoutingConfig.model_validate({"host_traffic": True})

    assert config.host_policy == "full"


def test_new_policy_key_wins_over_leftover_legacy_key() -> None:
    # The panel writes the new keys, so an old mode line left in YAML must not
    # override them.
    config = RoutingConfig.model_validate({"client_policy": "full", "mode": "split"})

    assert config.client_policy == "full"


def test_migration_logs_a_warning_naming_the_legacy_keys(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="kornode.config.models"):
        RoutingConfig.model_validate({"mode": "split", "host_traffic": True})

    assert "mode" in caplog.text
    assert "host_traffic" in caplog.text


def test_new_keys_alone_do_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="kornode.config.models"):
        RoutingConfig.model_validate({"client_policy": "split"})

    assert caplog.text == ""


def test_yaml_boolean_off_means_the_literal_string(tmp_path: Path) -> None:
    # Regression test: YAML 1.1 (and parse_env_value()) turn the bare word
    # "off" into the boolean False before pydantic ever sees it -- exactly
    # like routing.host_dns already had to handle. config.example.yaml
    # writes `host_policy: off` unquoted; without this, loading it raised
    # "Input should be 'off', 'full' or 'split'" for a bool.
    config = RoutingConfig.model_validate({"client_policy": False, "host_policy": False})

    assert config.client_policy == "off"
    assert config.host_policy == "off"

    # The actual repro: a real YAML file with the word unquoted, like
    # config.example.yaml has.
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "routing:\n  client_policy: full\n  host_policy: off\n", encoding="utf-8"
    )
    loaded = load_config(config_path, environ={})
    assert loaded.routing.host_policy == "off"
