from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from kornode.config.loader import load_config
from kornode.config.models import profile_slug

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = sorted((ROOT / "examples").glob("config.*.yaml"))


def test_examples_exist() -> None:
    assert len(EXAMPLES) >= 4


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_example_is_a_valid_v2_config(path: Path) -> None:
    # `${SECRET:NAME}` references resolve from the environment; give every one a value.
    names = set(re.findall(r"\$\{SECRET:([A-Za-z0-9_]+)\}", path.read_text(encoding="utf-8")))
    environ = {name: "x" for name in names} | {f"KORNODE_SECRET_{name}": "x" for name in names}

    config = load_config(path, environ=environ)

    assert config.egress_policy() is not None


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_example_has_no_v1_routing_keys(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for key in ("client_policy", "host_policy", "host_split", "fwmark", "table_id", "split:"):
        assert key not in text, f"{path.name}: {key}"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_example_upstream_references_use_the_profile_slug(path: Path) -> None:
    """`via: upstream:<x>` takes the profile slug ("site-b" -> "site_b"); the kernel compiler
    rejects any other spelling (found by the netlab example suite)."""
    names = set(re.findall(r"\$\{SECRET:([A-Za-z0-9_]+)\}", path.read_text(encoding="utf-8")))
    environ = {name: "x" for name in names} | {f"KORNODE_SECRET_{name}": "x" for name in names}
    config = load_config(path, environ=environ)
    slugs = {profile_slug(profile.name) for profile in config.upstream.profiles}
    for rule in config.egress_policy().egress:
        via = rule.parsed_via
        if via.kind == "upstream":
            assert via.target in slugs, (path.name, via.target, sorted(slugs))


def test_config_example_loads_with_env_example() -> None:
    """`cp config.example.yaml config/config.yaml && cp .env.example .env` is the Quick
    Start; a key removed from the models must not survive in `.env.example`."""
    config = load_config(ROOT / "config.example.yaml", env_file=ROOT / ".env.example", environ={})

    assert config.egress_policy() is not None


def test_compose_web_override_enables_the_panel_of_the_example_config() -> None:
    """README "Web API and GUI": `compose.web.yaml` turns the panel on through the
    environment, which only works if the example does not pin those keys (YAML wins)."""
    compose = yaml.safe_load((ROOT / "compose.web.yaml").read_text(encoding="utf-8"))
    environ = {
        key: re.sub(r"\$\{[A-Z_]+:-([^}]*)\}", r"\1", str(value))
        for key, value in compose["services"]["kornode"]["environment"].items()
    }

    config = load_config(
        ROOT / "config.example.yaml", env_file=ROOT / ".env.example", environ=environ
    )

    assert config.web.enabled
    assert config.web.admin_password
