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
            "egress": [{"from": ["host"], "to": "any", "via": "fabric"}],
        }
    )
    facts = NodeFacts(
        node_id=3,
        client_pool=None,
        tunnels={"fabric": TunnelFact(interface="oc-hub0", up=False)},
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
        {"egress": [{"from": ["host"], "to": "any", "via": "fabric"}]}
    )
    facts = NodeFacts(
        node_id=3, client_pool=None, tunnels={"fabric": TunnelFact(interface="oc-hub0", up=True)}
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
        {"egress": [{"from": ["host"], "to": "any", "via": "fabric"}]}
    )
    pool = ipaddress.IPv4Network("10.100.3.0/24")
    facts = NodeFacts(
        node_id=3,
        client_pool=pool,
        tunnels={"fabric": TunnelFact(interface="oc-hub0", up=True)},
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
        tunnels={"fabric": TunnelFact(interface="oc-hub0", up=True)},
        local_networks=(ipaddress.IPv4Network("10.100.3.0/25"),),
    )
    codes = {
        f["code"]
        for f in inspect_state(compile_policy(policy, foreign), policy, foreign, ActualState(), {})
    }
    assert "overlapping_networks" in codes
