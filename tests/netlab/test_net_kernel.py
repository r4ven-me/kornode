from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from tests.netlab.lab import Lab, Namespace

from kornode.net.reconciler import control_request

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


@pytest.mark.netlab
def test_agent_prefix_route_in_main_is_owned_by_protocol_and_withdrawn(node: Namespace) -> None:
    """P4-01 / S-03 fallback: the reconciler installs an agent's prefix in main
    with the kornode protocol and removes only that route when it is withdrawn."""
    node.run(["ip", "route", "add", "10.7.0.0/16", "dev", "kup0"])  # foreign, no proto
    node.run(["ip", "route", "add", "10.6.0.0/16", "dev", "kup0", "proto", "static"])

    assert drive(node, "converge", "--session", "192.168.77.0/24=kup0")["after"] == []
    ours = node.run(["ip", "route", "show", "proto", "77"]).stdout
    assert "192.168.77.0/24 dev kup0" in ours
    assert "10.7.0.0/16" not in ours and "10.6.0.0/16" not in ours

    assert drive(node, "plan", "--session", "192.168.77.0/24=kup0")["plan"] == []
    assert drive(node, "converge")["after"] == []
    main = node.run(["ip", "route", "show", "table", "main"]).stdout
    assert "192.168.77.0/24" not in main
    assert "10.7.0.0/16" in main and "10.6.0.0/16" in main


GOLDEN = Path(__file__).resolve().parents[1] / "golden"


@pytest.mark.netlab
@pytest.mark.parametrize("name", ["hub", "node3"])
def test_golden_rulesets_load_into_a_real_kernel(lab: Lab, name: str) -> None:
    # `nft -c` only checks syntax; it accepted `reject` in postrouting, which
    # the kernel refuses. Every golden must survive a real load.
    ns = lab.add_namespace(f"g{name}")
    result = ns.run(["nft", "-f", str(GOLDEN / f"{name}.nft")], check=False, timeout=30)

    assert result.ok, result.stderr


def _start_reconciler(ns: Namespace, socket_path: Path) -> subprocess.Popen[bytes]:
    env = {**os.environ, "PYTHONPATH": f"{ROOT / 'backend'}:{ROOT}"}
    return subprocess.Popen(  # noqa: S603 - explicit argv
        ["ip", "netns", "exec", ns.full_name, sys.executable, str(DRIVER), "run", str(socket_path)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def _wait(predicate: Callable[[], bool], timeout: float) -> float:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if predicate():
            return time.monotonic() - started
        time.sleep(0.05)
    raise AssertionError(f"not reached within {timeout}s")


@pytest.mark.netlab
def test_nl10_deleted_policy_route_is_restored_within_2s(node: Namespace, tmp_path: Path) -> None:
    sock = tmp_path / "reconciler.sock"
    process = _start_reconciler(node, sock)

    def tunnel_route() -> bool:
        result = node.run(["ip", "route", "show", "table", "12002"], check=False)
        return "default dev ktun1" in result.stdout

    try:
        _wait(lambda: sock.exists() and tunnel_route(), timeout=15)

        node.run(["ip", "route", "del", "default", "dev", "ktun1", "table", "12002"])
        elapsed = _wait(tunnel_route, timeout=5)

        print(f"NL-10: policy route restored after {elapsed:.2f}s")
        assert elapsed <= 2.0, f"restored after {elapsed:.2f}s"
        status = control_request(sock, "status")["status"]
        assert status["drift"].get("ReplaceRoute", 0) >= 1
        assert status["last_error"] is None
    finally:
        process.terminate()
        process.wait(timeout=10)


@pytest.mark.netlab
def test_tunnel_link_bounce_reinstalls_its_route(node: Namespace, tmp_path: Path) -> None:
    sock = tmp_path / "reconciler.sock"
    process = _start_reconciler(node, sock)

    def tunnel_route() -> bool:
        result = node.run(["ip", "route", "show", "table", "12002"], check=False)
        return "default dev ktun1" in result.stdout

    try:
        _wait(lambda: sock.exists() and tunnel_route(), timeout=15)
        node.run(["ip", "link", "set", "ktun1", "down"])  # kernel drops the route
        _wait(lambda: not tunnel_route(), timeout=5)
        table = node.run(["ip", "route", "show", "table", "12002"]).stdout
        assert "unreachable default" in table  # kill-switch stays

        node.run(["ip", "link", "set", "ktun1", "up"])
        assert _wait(tunnel_route, timeout=5) <= 2.0
    finally:
        process.terminate()
        process.wait(timeout=10)


@pytest.mark.netlab
def test_explain_kernel_check_agrees_then_reports_drift(node: Namespace) -> None:
    drive(node, "converge")
    node.run(["ip", "route", "add", "default", "dev", "kup0"])  # uplink default in main

    agree = drive(node, "explain", "10.100.3.15", "10.60.1.5")
    assert agree["kernel_check"] == "ip route get 10.60.1.5 mark 0x0c000200 -> dev ktun1"
    assert agree["warnings"] == []

    node.run(["ip", "route", "del", "default", "dev", "ktun1", "table", "12002"])
    drift = drive(node, "explain", "10.100.3.15", "10.60.1.5")
    # Kill-switch holds (unreachable), and explain flags that the kernel no
    # longer matches the compiled policy.
    assert drift["kernel_check"] == "ip route get 10.60.1.5 mark 0x0c000200 -> unreachable"
    assert drift["warnings"] == ["kernel routes it via nothing, compiled policy expects ktun1"]


def _docker_user(ns: Namespace) -> str:
    return ns.run(["nft", "list", "chain", "ip", "filter", "DOCKER-USER"]).stdout


@pytest.mark.netlab
def test_docker_user_compat_rules_are_tagged_and_idempotent(node: Namespace) -> None:
    ns_script = (
        "table ip filter {\n"
        "  chain DOCKER-USER {\n"
        "    ip saddr 172.17.0.0/16 counter return\n"
        "  }\n"
        "}\n"
    )
    node.run(["nft", "-f", "-"], input_text=ns_script)

    result = drive(node, "converge")

    assert result["after"] == []
    chain = _docker_user(node)
    assert 'ip saddr 10.100.3.0/24 accept comment "kornode-compat"' in chain
    assert 'ip daddr 10.100.3.0/24 accept comment "kornode-compat"' in chain
    assert "ip saddr 172.17.0.0/16 counter" in chain  # Docker's own rule kept
    assert chain.count("kornode-compat") == 2
    assert drive(node, "plan")["plan"] == []


@pytest.mark.netlab
def test_no_docker_user_chain_means_no_compat_rules(node: Namespace) -> None:
    assert drive(node, "converge")["after"] == []
    assert not node.run(["nft", "list", "table", "ip", "filter"], check=False).ok
