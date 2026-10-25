"""Phase 5 "done when": every example config compiles with the real hub inputs and
converges in a real kernel (second pass empty). The interfaces the config names (upstream
tunnels, sources) are dummies; no ocserv is needed for the policy to load."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from tests.netlab.lab import Lab

pytestmark = pytest.mark.netlab

ROOT = Path(__file__).resolve().parents[2]
DRIVER = Path(__file__).with_name("example_driver.py")
EXAMPLES = sorted((ROOT / "examples").glob("config.*.yaml"))


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_example_converges_in_a_real_kernel(lab: Lab, path: Path, tmp_path: Path) -> None:
    ns = lab.add_namespace("example")
    env = {**os.environ, "PYTHONPATH": f"{ROOT / 'backend'}:{ROOT}"}
    names = json.loads(
        ns.run([sys.executable, str(DRIVER), str(path), "--interfaces"], env=env).stdout
    )
    for name in ["uplink0", *names]:
        ns.run(["ip", "link", "add", name, "type", "dummy"])
        ns.run(["ip", "link", "set", name, "up"])
    ns.run(["ip", "addr", "add", "192.0.2.2/24", "dev", "uplink0"])
    ns.run(["ip", "route", "add", "default", "via", "192.0.2.1", "dev", "uplink0"])

    result = ns.run(
            [sys.executable, str(DRIVER), str(path), "--state-dir", str(tmp_path)],
            env=env, timeout=60,
        )

    assert json.loads(result.stdout)["after"] == [], result.stdout
