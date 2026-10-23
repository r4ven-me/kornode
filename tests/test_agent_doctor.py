from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from kornode.net.compile import NodeFacts, SourceFact, TunnelFact, compile_policy
from kornode.net.model import EgressPolicy
from kornode.net.state import ActualState
from kornode_agent.doctor import inspect_state


def test_doctor_reports_real_mismatches_and_missing_source() -> None:
    policy = EgressPolicy.model_validate(
        {
            "sources": [{"name": "lan", "interface": "br-lan", "cidr": "10.8.3.0/24"}],
            "egress": [{"from": ["host"], "to": "any", "via": "interlink"}],
        }
    )
    facts = NodeFacts(
        node_id=3,
        client_pool=None,
        tunnels={"interlink": TunnelFact(interface="oc-hub0", up=False)},
        sources={"lan": SourceFact(present=False)},
    )
    compiled = compile_policy(policy, facts)
    findings = inspect_state(compiled, policy, facts, ActualState(), {"oc-hub0": 1200})
    codes = {f["code"] for f in findings}
    assert {
        "sysctl_mismatch",
        "exit_guard_missing",
        "carrier_exclusion_missing",
        "nft_drift",
        "missing_source",
        "low_mtu",
    } <= codes
    assert all(set(f) == {"severity", "code", "message", "hint"} for f in findings)


def test_matching_kernel_is_not_reported_as_broken() -> None:
    policy = EgressPolicy.model_validate(
        {"egress": [{"from": ["host"], "to": "any", "via": "interlink"}]}
    )
    facts = NodeFacts(
        node_id=3, client_pool=None, tunnels={"interlink": TunnelFact(interface="oc-hub0", up=True)}
    )
    c = compile_policy(policy, facts)
    d = c.desired
    actual = ActualState(
        sysctls=d.sysctls,
        rules=d.rules,
        routes=d.routes,
        nft_schema_hash=d.nft.schema_hash if d.nft else None,
        elements=d.elements,
    )
    findings = inspect_state(c, policy, facts, actual, {"oc-hub0": 1400})
    assert not [f for f in findings if f["severity"] == "error"]


def test_foreign_nat_is_warning_not_claim_of_proven_overlap() -> None:
    from kornode_agent.doctor import foreign_nat

    doc = {
        "nftables": [
            {
                "rule": {
                    "family": "ip",
                    "table": "kornode_nat",
                    "chain": "postrouting",
                    "expr": [{"masquerade": None}],
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "docker",
                    "chain": "postrouting",
                    "expr": [{"masquerade": None}],
                }
            },
        ]
    }
    findings = foreign_nat(doc)
    assert len(findings) == 1 and findings[0]["severity"] == "warning"
    assert "not proven" in findings[0]["hint"]


def test_unavailable_checks_are_not_reported_healthy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from kornode_agent.doctor import run_doctor

    def fail() -> None:
        raise PermissionError("unreadable")

    monkeypatch.setattr("kornode_agent.doctor._capture", lambda argv: (False, ""))
    findings = run_doctor(SimpleNamespace(policy=fail), tmp_path, None)
    codes = {f["code"] for f in findings}
    assert {
        "kernel_unavailable",
        "nft_unavailable",
        "foreign_nat_unchecked",
        "certificate_unavailable",
        "clock_skew_unchecked",
    } <= codes


def test_per_session_routes_of_access_clients_are_not_overlaps() -> None:
    """P4-04: ocserv puts a /32 per connected client on vpns*; they sit inside
    the node's own client pool and are expected."""
    policy = EgressPolicy.model_validate(
        {"egress": [{"from": ["host"], "to": "any", "via": "interlink"}]}
    )
    pool = ipaddress.IPv4Network("10.100.3.0/24")
    facts = NodeFacts(
        node_id=3,
        client_pool=pool,
        tunnels={"interlink": TunnelFact(interface="oc-hub0", up=True)},
        local_networks=(
            ipaddress.IPv4Network("10.100.3.15/32"),
            ipaddress.IPv4Network("10.100.3.0/24"),
        ),
    )
    compiled = compile_policy(policy, facts)
    codes = {f["code"] for f in inspect_state(compiled, policy, facts, ActualState(), {})}
    assert "overlapping_networks" not in codes
    foreign = NodeFacts(
        node_id=3,
        client_pool=pool,
        tunnels={"interlink": TunnelFact(interface="oc-hub0", up=True)},
        local_networks=(ipaddress.IPv4Network("10.100.3.0/25"),),
    )
    codes = {
        f["code"]
        for f in inspect_state(compile_policy(policy, foreign), policy, foreign, ActualState(), {})
    }
    assert "overlapping_networks" in codes


SOURCES = (("amnezia", "awg0", "10.8.3.0/24"),)


def _nat(*expr: dict, table: str = "wg-easy") -> dict:
    return {
        "nftables": [
            {"rule": {"family": "ip", "table": table, "chain": "postrouting", "expr": list(expr)}}
        ]
    }


def _match(field: str, right: object, op: str = "==", key: str = "") -> dict:
    left = {"meta": {"key": key}} if key else {"payload": {"protocol": "ip", "field": field}}
    return {"match": {"op": op, "left": left, "right": right}}


def test_foreign_nat_matching_a_source_is_an_error() -> None:
    from kornode_agent.doctor import foreign_nat

    prefix = {"prefix": {"addr": "10.8.3.0", "len": 24}}
    for expr in (
        [_match("saddr", prefix), {"masquerade": None}],
        [_match("saddr", "10.8.3.7"), {"snat": {"addr": "198.51.100.1"}}],
        [_match("saddr", {"set": [prefix]}), {"masquerade": None}],
        [_match("", "awg0", key="iifname"), {"masquerade": None}],
        [_match("", "awg0", key="oifname"), {"masquerade": None}],
        [_match("saddr", {"range": ["10.8.3.1", "10.8.3.200"]}), {"masquerade": None}],
    ):
        (found,) = foreign_nat(_nat(*expr), SOURCES)
        assert found["severity"] == "error" and found["code"] == "foreign_nat_on_source", expr
        assert "amnezia" in found["message"] and "PostUp" in found["hint"]


def test_foreign_nat_elsewhere_stays_a_warning() -> None:
    from kornode_agent.doctor import foreign_nat

    docker = [_match("saddr", {"prefix": {"addr": "172.17.0.0", "len": 16}}), {"masquerade": None}]
    elsewhere = [_match("", "eth9", key="oifname"), {"masquerade": None}]
    negated = [_match("", "awg0", op="!=", key="oifname"), {"masquerade": None}]
    for expr in (docker, elsewhere, negated):
        (found,) = foreign_nat(_nat(*expr, table="docker"), SOURCES)
        assert found["severity"] == "warning" and found["code"] == "foreign_nat"
    # No source configured: nothing is proven either way.
    (found,) = foreign_nat(_nat(*[_match("", "awg0", key="iifname"), {"masquerade": None}]))
    assert found["severity"] == "warning"


def test_legacy_iptables_nat_on_a_source_is_an_error() -> None:
    from kornode_agent.doctor import iptables_nat

    text = "\n".join(
        [
            "*nat",
            ":POSTROUTING ACCEPT [0:0]",
            "-A POSTROUTING -s 10.8.3.0/24 -o eth0 -j MASQUERADE",
            "-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE",
            "-A POSTROUTING ! -s 10.8.3.0/24 -o eth0 -j MASQUERADE",
            "-A POSTROUTING -o awg0 -j SNAT --to-source 10.8.3.1",
            "-A POSTROUTING -s 10.8.3.0/24 -j ACCEPT",
            "COMMIT",
        ]
    )
    found = iptables_nat(text, SOURCES)
    assert [f["code"] for f in found] == ["foreign_nat_on_source"] * 2
    assert all(f["severity"] == "error" for f in found)
    assert "-s 10.8.3.0/24 -o eth0" in found[0]["message"] and "awg0" in found[1]["message"]


def test_an_absent_source_interface_is_one_warning() -> None:
    policy = EgressPolicy.model_validate(
        {
            "sources": [{"name": "lan", "interface": "br-lan", "cidr": "10.8.3.0/24"}],
            "egress": [{"from": ["host"], "to": "any", "via": "interlink"}],
        }
    )
    facts = NodeFacts(
        node_id=3,
        client_pool=None,
        tunnels={"interlink": TunnelFact(interface="oc-hub0", up=True)},
        sources={"lan": SourceFact(present=False)},
    )
    findings = inspect_state(compile_policy(policy, facts), policy, facts, ActualState(), {})
    missing = [f for f in findings if "br-lan" in f["message"]]
    assert [(f["code"], f["severity"]) for f in missing] == [("missing_source", "warning")]


def test_nat_wildcards_and_the_in_operator_match_a_source() -> None:
    from kornode_agent.doctor import foreign_nat, iptables_nat

    (found,) = foreign_nat(
        _nat(_match("", {"set": ["awg*"]}, op="in", key="iifname"), {"masquerade": None}), SOURCES
    )
    assert found["code"] == "foreign_nat_on_source"
    text = "*nat\n-A POSTROUTING -o awg+ -j MASQUERADE\nCOMMIT\n"
    assert [f["code"] for f in iptables_nat(text, SOURCES)] == ["foreign_nat_on_source"]


def test_iptables_user_chains_are_followed_and_catch_all_nat_is_a_warning() -> None:
    from kornode_agent.doctor import iptables_nat

    text = "\n".join(
        [
            "*nat",
            ":WG_NAT - [0:0]",
            "-A POSTROUTING -j WG_NAT",
            '-A WG_NAT -s 10.8.3.0/24 -m comment --comment "wg -o eth0" -j MASQUERADE',
            "-A POSTROUTING -j MASQUERADE",
            "-A POSTROUTING ! -i awg0 -s 192.0.2.0/24 -j MASQUERADE",
            "-A UNUSED -s 10.8.3.0/24 -j MASQUERADE",
            "-A POSTROUTING -s",
            "-A POSTROUTING -j",
            "COMMIT",
        ]
    )
    found = iptables_nat(text, SOURCES)
    assert [(f["code"], f["severity"]) for f in found] == [
        ("foreign_nat", "warning"),
        ("foreign_nat_on_source", "error"),
    ]
    assert "WG_NAT" in found[1]["message"] or "10.8.3.0/24" in found[1]["message"]


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, loaded: bool, calls: list[list[str]]):
    from types import SimpleNamespace

    from kornode_agent import doctor

    policy = EgressPolicy.model_validate(
        {"sources": [{"name": "amnezia", "interface": "awg0", "cidr": "10.8.3.0/24"}]}
    )
    nat = "-A POSTROUTING -s 10.8.3.0/24 -o eth0 -j MASQUERADE\n"

    def capture(argv: list[str]) -> tuple[bool, str]:
        calls.append(argv)
        return (True, nat) if argv[0] == "iptables-legacy-save" else (False, "")

    monkeypatch.setattr(doctor, "_capture", capture)
    monkeypatch.setattr(doctor, "_legacy_nat_loaded", lambda: loaded)
    return doctor.run_doctor(SimpleNamespace(policy=lambda: policy), tmp_path, None)  # type: ignore[arg-type]


def test_legacy_iptables_is_only_read_when_its_nat_table_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Asking for `-t nat` would create an empty legacy table and could pre-empt nftables NAT."""
    calls: list[list[str]] = []
    findings = _run(monkeypatch, tmp_path, loaded=False, calls=calls)
    assert ["iptables-legacy-save", "-t", "nat"] not in calls
    assert "foreign_nat_on_source" not in {f["code"] for f in findings}
    calls.clear()
    findings = _run(monkeypatch, tmp_path, loaded=True, calls=calls)
    assert ["iptables-legacy-save", "-t", "nat"] in calls
    assert "foreign_nat_on_source" in {f["code"] for f in findings}


def test_legacy_nat_probe_reads_the_proc_table_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kornode_agent import doctor

    listing = tmp_path / "ip_tables_names"
    original = doctor.Path
    monkeypatch.setattr(
        doctor, "Path", lambda value: listing if "ip_tables_names" in value else original(value)
    )
    listing.write_text("filter\nnat\n")
    assert doctor._legacy_nat_loaded() is True
    listing.write_text("filter\n")
    assert doctor._legacy_nat_loaded() is False
    listing.unlink()
    assert doctor._legacy_nat_loaded() is False
