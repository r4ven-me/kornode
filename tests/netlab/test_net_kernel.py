from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tests.netlab.lab import Lab, Namespace

from kornode.net.nftgen import label_bits
from kornode.net.reconciler import control_request

DRIVER = Path(__file__).with_name("net_kernel_driver.py")
ROOT = Path(__file__).resolve().parents[2]


def drive(ns: Namespace, *args: str) -> dict[str, list[str]]:
    env = {
        **os.environ,
        "PYTHONPATH": f"{ROOT / 'backend'}:{ROOT}",
        # Never inherit a production bind-mounted host sysctl root into a lab.
        "KORNODE_PROC_SYS": "/proc/sys",
    }
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
    assert "fwmark 0xcc63d00/0xffffff00 lookup 12002" in rules
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
    assert plan[0] == "NftLoad"  # routing barrier precedes repair
    assert "ReplaceRoute" in plan
    assert plan.count("NftLoad") == 2  # final transaction lifts the barrier
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
@pytest.mark.parametrize(
    "name",
    [
        "hub",
        "node3",
        "hub_transit",
        "hub_egress_gateway",
        "hub_transit_set",
        "agent_gateway",
        "gateway_node",
        "agent_peers",
    ],
)
def test_golden_rulesets_load_into_a_real_kernel(lab: Lab, name: str) -> None:
    # `nft -c` only checks syntax; it accepted `reject` in postrouting, which
    # the kernel refuses. Every golden must survive a real load.
    ns = lab.add_namespace(f"g{name}")
    result = ns.run(["nft", "-f", str(GOLDEN / f"{name}.nft")], check=False, timeout=30)

    assert result.ok, result.stderr


def _start_reconciler(ns: Namespace, socket_path: Path) -> subprocess.Popen[bytes]:
    env = {
        **os.environ,
        "PYTHONPATH": f"{ROOT / 'backend'}:{ROOT}",
        # Never inherit a production bind-mounted host sysctl root into a lab.
        "KORNODE_PROC_SYS": "/proc/sys",
    }
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
    assert agree["kernel_check"] == "ip route get 10.60.1.5 mark 0x0cc63d00 -> dev ktun1"
    assert agree["warnings"] == []

    node.run(["ip", "route", "del", "default", "dev", "ktun1", "table", "12002"])
    drift = drive(node, "explain", "10.100.3.15", "10.60.1.5")
    # Kill-switch holds (unreachable), and explain flags that the kernel no
    # longer matches the compiled policy.
    assert drift["kernel_check"] == "ip route get 10.60.1.5 mark 0x0cc63d00 -> unreachable"
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


@pytest.mark.netlab
def test_missing_nat_table_is_reloaded_even_with_an_unchanged_filter_hash(node: Namespace) -> None:
    assert drive(node, "converge")["after"] == []
    node.run(["nft", "delete", "table", "ip", "kornode_nat"])
    assert "NftLoad" in drive(node, "plan")["plan"]
    assert drive(node, "converge")["after"] == []
    assert node.run(["nft", "list", "table", "ip", "kornode_nat"]).ok


@pytest.mark.netlab
@pytest.mark.parametrize(
    "mark,label,accepted",
    [
        ("0x0c800000", "0x25bf8e1a2393f1108d37029b3df55932", True),
        ("0x0c800000", "0xe2353d59ad3bf127a8961d90df42f3e1", False),
        ("0x0c000100", None, False),
        ("0x0c7fff00", None, False),
        ("0x0c800000", "0x25bf8e1a2393f1108d37029b3df55933", False),
    ],
)
def test_kernel_checks_conntrack_identity_before_restoring_a_pinned_flow(
    node: Namespace, mark: str, label: str | None, accepted: bool
) -> None:
    """Test-owned pre-mangle injection simulates current, colliding and legacy CT.

    The observer runs after kornode's output hook, so only a valid mark+label
    can reach it. All packets and nft changes stay in the disposable namespace.
    """
    assert drive(node, "converge")["after"] == []
    set_label = f"ct label set {label_bits(label)}" if label else ""
    node.run(
        ["nft", "-f", "-"],
        input_text=(
            "table inet audit_probe {\n"
            " chain inject { type filter hook output priority -151; policy accept;\n"
            f"  udp dport 49999 ct mark set {mark} {set_label}\n"
            " }\n"
            " chain observe { type filter hook output priority filter; policy accept;\n"
            "  udp dport 49999 counter\n"
            " }\n"
            "}\n"
        ),
    )
    node.run(
        [
            sys.executable,
            "-c",
            (
                "import socket\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                "try: s.sendto(b'audit', ('192.168.3.2', 49999))\n"
                "except OSError: pass\n"
                "s.close()\n"
            ),
        ]
    )
    objects = json.loads(
        node.run(["nft", "-j", "list", "chain", "inet", "audit_probe", "observe"]).stdout
    )["nftables"]
    packets = sum(
        expr["counter"]["packets"]
        for item in objects
        for expr in item.get("rule", {}).get("expr", [])
        if "counter" in expr
    )
    assert packets == int(accepted)


@pytest.mark.netlab
@pytest.mark.parametrize(
    "label",
    [
        "0x1",
        "0x8000000000000000",
        "0x10000000000000000",
        "0x80000000000000000000000000000003",
        "0x25bf8e1a2393f1108d37029b3df55932",
        "0xffffffffffffffffffffffffffffffff",
    ],
)
def test_identity_label_expression_lowers_to_full_128_bit_register(
    node: Namespace, label: str
) -> None:
    expression = label_bits(label)
    script = (
        "table inet audit_label_lowering {\n"
        " chain output {\n"
        "  type filter hook output priority mangle; policy accept;\n"
        f"  ct label set {expression} ct label == {expression} counter\n"
        " }\n}\n"
    )
    result = node.run(["nft", "--check", "--debug=netlink", "-f", "-"], input_text=script)
    value = int(label, 16)
    words = " ".join(f"0x{(value >> shift) & 0xFFFFFFFF:08x}" for shift in (0, 32, 64, 96))
    assert f"immediate reg 1 {words}" in result.stdout
    assert "ct set label with reg 1" in result.stdout
    assert f"cmp eq reg 1 {words}" in result.stdout  # not flag-membership/nonzero testing


# These programs run only inside disposable lab namespaces, never at collection.
_AUDIT_APPLY_CODE = r"""
import dataclasses, ipaddress, json, re, sys
from kornode.net import compile as compiler
from kornode.net.compile import NodeFacts, SourceFact, TunnelFact, compile_policy
from kornode.net.diff import NftLoad, Plan, UpdateElements, diff
from kornode.net.kernel import Kernel
from kornode.net.model import EgressPolicy
from kornode.net.state import NftRuleset
p = json.loads(sys.argv[1])
mode = p['mode']
rules = [
    {'from': ['vpn'], 'to': {'routes': ['198.18.0.2/32']}, 'via': 'upstream:office'},
    {'from': ['vpn'], 'to': 'any', 'via': 'upstream:active'},
    {'from': ['host'], 'to': {'set': 'corp'}, 'via': 'upstream:office'},
]
if mode == 'reorder':
    rules.insert(0, {'from': ['host'], 'to': {'routes': ['198.19.0.0/24']}, 'via': 'local'})
elif mode == 'local':
    rules = [{'from': ['vpn'], 'to': 'any', 'via': 'local'}]
elif mode.startswith('collision-'):
    target = mode.removeprefix('collision-')
    rules = [{'from': ['vpn'], 'to': 'any', 'via': 'upstream:' + target}]
    compiler.exit_mark = lambda name: 0x0cffff00
elif mode == 'legacy':
    compiler.exit_mark = lambda name: 0x0c000100
policy = EgressPolicy.model_validate({
    'sources': [{'name': 'vpn', 'interface': p['source_if'], 'cidr': '10.8.1.0/24'}],
    'sets': {'corp': {'routes': ['198.18.0.1/32']}}, 'egress': rules,
})
facts = NodeFacts(node_id=1, client_pool=None, sources={'vpn': SourceFact(True)},
    upstreams=('office', 'backup'), active_upstream='backup' if mode == 'switch' else 'office',
    tunnels={'upstream:office': TunnelFact(p['office_if'], True),
             'upstream:backup': TunnelFact(p['backup_if'], True)}, uplink=p['uplink_if'])
compiled = compile_policy(policy, facts)
want = compiled.desired
if mode == 'legacy':
    # Test-only pre-upgrade producer: positional CT mark, no CT labels.
    script = re.sub(r'  chain validate_connection \{.*?\n  \}',
                    '  chain validate_connection {\n    return\n  }', compiled.script, flags=re.S)
    script = re.sub(r'ct label set \([0-9 |]+\) ?', '', script)
    want = dataclasses.replace(want, nft=NftRuleset(script))
kernel = Kernel()
plan = diff(kernel.read([s.key for s in want.sysctls]), want)
ops = plan.ops
if p.get('phase') == 'guard':
    end = next(i for i, op in enumerate(ops) if not isinstance(op, (NftLoad, UpdateElements)))
    ops = ops[:end]
elif p.get('phase') == 'routing':
    end = next(i for i, op in enumerate(ops) if isinstance(op, NftLoad) and not op.guard)
    ops = ops[:end]
kernel.apply(Plan(ops))
print(json.dumps({'exits': {e.name: [e.mark, e.identity_label] for e in compiled.exits},
                  'ops': [type(op).__name__ for op in ops]}))
"""

_AUDIT_ECHO_CODE = r"""
import json, socketserver
class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.wfile.write((json.dumps({'data': line.decode().strip(),
                'peer': self.client_address[0], 'port': self.client_address[1]}) + '\n').encode())
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
server = Server(('0.0.0.0', 19000), Echo)
print('READY', flush=True)
server.serve_forever()
"""

_AUDIT_CLIENT_CODE = r"""
import json, socket, sys
s = socket.socket()
s.settimeout(0.6)
s.bind(('10.8.1.2', int(sys.argv[2])))
s.connect((sys.argv[1], 19000))
print('READY', flush=True)
buffer = b''
for line in sys.stdin:
    nonce = line.strip()
    try:
        s.sendall((nonce + '\n').encode())
        while True:
            while b'\n' not in buffer:
                data = s.recv(4096)
                if not data:
                    raise OSError('connection closed')
                buffer += data
            raw, buffer = buffer.split(b'\n', 1)
            response = json.loads(raw)
            if response['data'] == nonce:
                print(json.dumps(response), flush=True)
                break
    except OSError:
        print(json.dumps({'blocked': True}), flush=True)
s.close()
"""


def _audit_readline(process: subprocess.Popen[str]) -> str:
    import select

    assert process.stdout is not None
    assert select.select([process.stdout], [], [], 5)[0], "namespace process did not answer"
    line = process.stdout.readline()
    assert line, f"namespace process exited: {process.poll()}"
    return line.strip()


def _audit_probe(process: subprocess.Popen[str], nonce: str) -> dict[str, object]:
    assert process.stdin is not None
    process.stdin.write(nonce + "\n")
    process.stdin.flush()
    return json.loads(_audit_readline(process))


def _audit_apply(
    ns: Namespace, params: dict[str, str], mode: str, phase: str = "full"
) -> dict[str, Any]:
    env = {
        **os.environ,
        "PYTHONPATH": f"{ROOT / 'backend'}:{ROOT}",
        # Never inherit a production bind-mounted host sysctl root into a lab.
        "KORNODE_PROC_SYS": "/proc/sys",
    }
    result = ns.run(
        [
            sys.executable,
            "-c",
            _AUDIT_APPLY_CODE,
            json.dumps({**params, "mode": mode, "phase": phase}),
        ],
        env=env,
        timeout=30,
    )
    return json.loads(result.stdout)


def _audit_counters(ns: Namespace) -> dict[str, int]:
    objects = json.loads(ns.run(["nft", "-j", "list", "table", "inet", "audit_observe"]).stdout)
    return {
        rule["comment"]: expr["counter"]["packets"]
        for item in objects["nftables"]
        if (rule := item.get("rule")) and "comment" in rule
        for expr in rule["expr"]
        if "counter" in expr
    }


@pytest.mark.netlab
@pytest.mark.parametrize("change", ["reorder", "switch", "local", "collision", "legacy", "barrier"])
def test_established_forwarded_tcp_never_adopts_a_reassigned_exit(lab: Lab, change: str) -> None:
    """Real source -> router -> two exits/uplink, with one persistent TCP tuple.

    No forged labels in the modern cases: the compiler stamps real connections.
    Every apply starts a fresh process (allocator restart); counters after all
    filters measure actual egress, not merely a route lookup or rejected skb.
    """
    import contextlib

    source = lab.add_namespace("audit-src")
    router = lab.add_namespace("audit-router")
    sink = lab.add_namespace("audit-sink")
    lab.add_veth(router, source, addr_a="10.8.1.1/24", addr_b="10.8.1.2/24")
    params = {"source_if": lab.veths[-1][0]}
    for index, name in enumerate(("office", "backup", "uplink"), 1):
        lab.add_veth(router, sink, addr_a=f"10.201.{index}.1/30", addr_b=f"10.201.{index}.2/30")
        params[name + "_if"] = lab.veths[-1][0]
        peer_if = lab.veths[-1][1]
        peer_mac = json.loads(sink.run(["ip", "-j", "link", "show", "dev", peer_if]).stdout)[0][
            "address"
        ]
        # Exit tables use `default dev` like a TUN. Static L2 neighbors make
        # these veth substitutes independent of host ARP-flux settings.
        for destination in ("198.18.0.1", "198.18.0.2"):
            router.run(
                [
                    "ip",
                    "neigh",
                    "replace",
                    destination,
                    "lladdr",
                    peer_mac,
                    "nud",
                    "permanent",
                    "dev",
                    params[name + "_if"],
                ]
            )
    source.run(["ip", "route", "add", "default", "via", "10.8.1.1"])
    router.run(["ip", "route", "add", "default", "via", "10.201.3.2"])
    for address in ("198.18.0.1/32", "198.18.0.2/32"):
        sink.run(["ip", "addr", "add", address, "dev", "lo"])
    router.run(
        ["nft", "-f", "-"],
        input_text=(
            "table inet audit_observe {\n"
            " chain forward { type filter hook forward priority 1; policy accept;\n"
            "  ct state established ct direction original tcp dport 19000 "
            'counter comment "established"\n'
            " }\n"
            " chain egress { type filter hook postrouting priority 101; policy accept;\n"
            + "".join(
                f'  ct direction original tcp dport 19000 oifname "{params[name + "_if"]}" '
                f'counter comment "{name}"\n'
                for name in ("office", "backup", "uplink")
            )
            + " }\n}\n"
        ),
    )
    initial_mode = (
        "collision-office"
        if change == "collision"
        else "legacy"
        if change == "legacy"
        else "office"
    )
    initial = _audit_apply(router, params, initial_mode)

    with contextlib.ExitStack() as stack:

        def start(ns: Namespace, code: str, *args: str) -> subprocess.Popen[str]:
            process = subprocess.Popen(
                ["ip", "netns", "exec", ns.full_name, sys.executable, "-u", "-c", code, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            def cleanup() -> None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)

            stack.callback(cleanup)
            assert _audit_readline(process) == "READY"
            return process

        start(sink, _AUDIT_ECHO_CODE)
        alias = start(source, _AUDIT_CLIENT_CODE, "198.18.0.1", "41001")
        named = start(source, _AUDIT_CLIENT_CODE, "198.18.0.2", "41002")
        assert _audit_probe(alias, "before-alias")["peer"] == "10.201.1.1"
        assert _audit_probe(named, "before-named")["peer"] == "10.201.1.1"
        assert _audit_counters(router)["established"] >= 2, "must test actual established TCP"

        target = (
            "collision-backup"
            if change == "collision"
            else "office"
            if change == "legacy"
            else change
        )
        if change == "barrier":
            _audit_apply(router, params, "switch", phase="guard")
            before = _audit_counters(router)
            assert _audit_probe(alias, "during-guard").get("blocked") is True
            # A new HOST split-set flow must not fall through unmarked when
            # the temporary ruleset replaces the original destination sets.
            router.run(
                [
                    sys.executable,
                    "-c",
                    "import socket\n"
                    "try: socket.create_connection(('198.18.0.1', 19000), timeout=0.4)\n"
                    "except OSError: pass",
                ]
            )
            guarded = _audit_counters(router)
            assert all(guarded[name] == before[name] for name in ("office", "backup", "uplink"))
            _audit_apply(router, params, "switch", phase="routing")
            assert _audit_probe(alias, "during-routing").get("blocked") is True
            target = "switch"
        applied = _audit_apply(router, params, target)
        before = _audit_counters(router)
        blocked = change in ("local", "collision", "legacy")
        alias_response = _audit_probe(alias, "after-alias")
        if change == "barrier" and alias_response.get("blocked"):
            # A deliberately dropped segment backs TCP's retransmission timer
            # off beyond the 600 ms negative-probe deadline. Keep the very same
            # socket/tuple and allow bounded recovery; never retry a wrong peer.
            print("TCP after barrier release:", source.run(["ss", "-tino"]).stdout)
            deadline = time.monotonic() + 8
            attempt = 0
            while alias_response.get("blocked") and time.monotonic() < deadline:
                attempt += 1
                alias_response = _audit_probe(alias, f"after-alias-retry-{attempt}")
        named_response = _audit_probe(named, "after-named")
        if change == "barrier":
            resumed = _audit_counters(router)
            assert resumed["backup"] == before["backup"]
            assert resumed["uplink"] == before["uplink"]
        if blocked:
            assert alias_response.get("blocked") is True
            assert named_response.get("blocked") is True
            after = _audit_counters(router)
            assert all(after[name] == before[name] for name in ("office", "backup", "uplink"))
        else:
            assert alias_response["peer"] == "10.201.1.1"  # never migrate a pinned connection
            assert named_response["peer"] == "10.201.1.1"
        if change == "collision":
            assert initial["exits"]["upstream:office"][0] == applied["exits"]["upstream:backup"][0]
            assert initial["exits"]["upstream:office"][1] != applied["exits"]["upstream:backup"][1]
        fresh = start(source, _AUDIT_CLIENT_CODE, "198.18.0.1", "41003")
        expected = (
            "10.201.3.1"
            if change == "local"
            else "10.201.2.1"
            if change in ("switch", "collision", "barrier")
            else "10.201.1.1"
        )
        assert _audit_probe(fresh, "fresh")["peer"] == expected
