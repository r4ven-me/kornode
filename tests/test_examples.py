from __future__ import annotations

import re
from pathlib import Path

import pytest

from kornode.config.loader import load_config

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
