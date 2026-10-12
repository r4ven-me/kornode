from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from tests.netlab.lab import Lab, Namespace

DRIVER = Path(__file__).with_name("net_kernel_driver.py")
ROOT = Path(__file__).resolve().parents[2]


def drive(ns: Namespace, *args: str) -> dict[str, list[str]]:
    env = {**os.environ, "PYTHONPATH": f"{ROOT / 'backend'}:{ROOT}"}
    result = ns.run([sys.executable, str(DRIVER), *args], env=env, timeout=60)
    data: dict[str, list[str]] = json.loads(result.stdout)
    return data


@pytest.fixture
def node(lab: Lab) -> Namespace:
    ns = lab.add_namespace("knode")
    for name in ("ktun0", "ktun1", "kup0"):
        ns.run(["ip", "link", "add", name, "type", "dummy"])
        ns.run(["ip", "link", "set", name, "up"])
    ns.run(["ip", "addr", "add", "192.168.3.1/24", "dev", "kup0"])
    return ns


@pytest.mark.netlab
def test_converges_and_second_pass_is_empty(node: Namespace) -> None:
    first = drive(node, "converge")

    assert "NftLoad" in first["plan"] and "AddRule" in first["plan"]
    assert first["after"] == []
    # The pyroute2 trap: rule 90 must really carry suppress_prefixlength.
    rules = node.run(["ip", "rule"]).stdout
    assert "90:\tfrom all lookup main suppress_prefixlength 0" in rules
    assert "fwmark 0xc000200/0xffffff00 lookup 12002" in rules
    table = node.run(["ip", "route", "show", "table", "12002"]).stdout
    assert "default dev ktun1" in table and "unreachable default" in table
    nft = node.run(["nft", "list", "table", "inet", "kornode"]).stdout
    assert 'comment "kornode-schema:' in nft
    corp = node.run(["nft", "list", "set", "inet", "kornode", "corp_v4"]).stdout
    assert "10.60.0.0/16" in corp


@pytest.mark.netlab
def test_deleted_route_is_detected_and_restored(node: Namespace) -> None:
    drive(node, "converge")
    node.run(["ip", "route", "del", "default", "dev", "ktun1", "table", "12002"])

    plan = drive(node, "plan")["plan"]
    assert plan == ["ReplaceRoute"]
    assert drive(node, "converge")["after"] == []
    assert "default dev ktun1" in node.run(["ip", "route", "show", "table", "12002"]).stdout


@pytest.mark.netlab
def test_element_change_does_not_reload_the_ruleset(node: Namespace) -> None:
    drive(node, "converge")

    result = drive(node, "converge", "--corp", "10.60.0.0/24,10.60.1.0/24,10.70.0.5/32")

    assert result["plan"] == ["UpdateElements"]
    assert result["after"] == []
    corp = node.run(["nft", "list", "set", "inet", "kornode", "corp_v4"]).stdout
    assert "10.60.0.0/23" in corp and "10.70.0.5" in corp


@pytest.mark.netlab
def test_foreign_state_is_untouched_and_stale_owned_state_removed(node: Namespace) -> None:
    node.run(["ip", "route", "add", "10.9.0.0/16", "dev", "kup0", "table", "200"])
    node.run(["ip", "rule", "add", "priority", "300", "lookup", "200"])
    node.run(["ip", "route", "add", "10.8.0.0/16", "dev", "kup0", "table", "12050"])
    node.run(["ip", "rule", "add", "priority", "150", "lookup", "12050"])

    assert drive(node, "converge")["after"] == []

    assert "10.9.0.0/16" in node.run(["ip", "route", "show", "table", "200"]).stdout
    rules = node.run(["ip", "rule"]).stdout
    assert "300:" in rules and "150:" not in rules
    assert node.run(["ip", "route", "show", "table", "12050"]).stdout.strip() == ""


GOLDEN = Path(__file__).resolve().parents[1] / "golden"


@pytest.mark.netlab
@pytest.mark.parametrize("name", ["hub", "node3"])
def test_golden_rulesets_load_into_a_real_kernel(lab: Lab, name: str) -> None:
    # `nft -c` only checks syntax; it accepted `reject` in postrouting, which
    # the kernel refuses. Every golden must survive a real load.
    ns = lab.add_namespace(f"g{name}")
    result = ns.run(
        ["nft", "-f", str(GOLDEN / f"{name}.nft")], check=False, timeout=30
    )

    assert result.ok, result.stderr
