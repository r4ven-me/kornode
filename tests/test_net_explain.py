from __future__ import annotations

import dataclasses

from tests.test_net_compile import hub_case, node3_case

from kornode.net.compile import TunnelFact, compile_policy
from kornode.net.explain import explain


def _hub():  # type: ignore[no-untyped-def]
    policy, facts = hub_case()
    return compile_policy(policy, facts), policy, facts


def _node3():  # type: ignore[no-untyped-def]
    policy, facts = node3_case()
    return compile_policy(policy, facts), policy, facts


def test_client_to_corp_matches_the_spec_example() -> None:
    compiled, policy, facts = _hub()

    decision = explain(compiled, policy, facts, "10.100.1.15", "10.60.1.5").as_dict()

    assert decision["from_class"] == "clients"
    assert decision["matched_rule"] == {
        "index": 1,
        "id": "corp",
        "to": {"set": "corp"},
        "via": "upstream:office",
    }
    assert decision["mark"] == "0x0c000200"
    assert decision["table"] == 12002
    assert decision["route"] == "default dev oc-office0"
    assert decision["nat"] == "masquerade to oc-office0"
    assert decision["implicit"] is None and decision["warnings"] == []


def test_client_to_internet_goes_local_with_nat() -> None:
    compiled, policy, facts = _hub()

    decision = explain(compiled, policy, facts, "10.100.1.15", "1.1.1.1")

    assert decision.matched_rule is not None and decision.matched_rule["id"] == "internet"
    assert decision.table is None
    assert decision.route == "main table (uplink eth0)"
    assert decision.nat == "masquerade to eth0"


def test_connected_network_is_an_implicit_local_route() -> None:
    compiled, policy, facts = _hub()

    decision = explain(compiled, policy, facts, "10.100.1.15", "172.17.0.5")

    assert decision.implicit == "destination is a connected network of this node (main table)"
    assert decision.matched_rule is None and decision.mark is None


def test_carrier_address_is_never_tunneled() -> None:
    compiled, policy, facts = _hub()

    decision = explain(compiled, policy, facts, "host", "198.51.100.9")

    assert decision.implicit == "destination is a tunnel carrier address (main table)"


def test_host_without_a_matching_rule_uses_normal_routing() -> None:
    compiled, policy, facts = _hub()

    decision = explain(compiled, policy, facts, "host", "1.1.1.1")

    assert decision.from_class == "host"
    assert decision.implicit == "host default: normal routing (main table)"


def test_named_source_is_classified_by_its_subnet() -> None:
    compiled, policy, facts = _node3()

    decision = explain(compiled, policy, facts, "10.8.3.7", "10.200.0.1")

    assert decision.from_class == "amnezia"
    assert decision.matched_rule is not None and decision.matched_rule["id"] == "internet"


def test_unmatched_client_traffic_is_rejected() -> None:
    policy, facts = node3_case()
    policy = policy.model_copy(update={"egress": policy.egress[:1]})  # to-fabric only
    compiled = compile_policy(policy, facts)

    decision = explain(compiled, policy, facts, "10.100.3.15", "1.1.1.1")

    assert decision.implicit == "no rule matched: rejected (appended implicit drop)"
    assert decision.route == "reject (admin-prohibited)"


def test_fabric_destination_on_an_agent_uses_the_hub_tunnel() -> None:
    compiled, policy, facts = _node3()

    decision = explain(compiled, policy, facts, "10.100.3.15", "192.168.2.10")

    assert decision.matched_rule is not None and decision.matched_rule["id"] == "to-fabric"
    assert decision.route == "192.168.2.0/24 dev oc-hub0"
    assert decision.nat is None


def test_down_exit_reports_the_kill_switch() -> None:
    policy, facts = hub_case()
    facts = dataclasses.replace(
        facts, tunnels={"upstream:office": TunnelFact("oc-office0", False)}
    )
    compiled = compile_policy(policy, facts)

    decision = explain(compiled, policy, facts, "10.100.1.15", "10.60.1.5")

    assert decision.route == "unreachable default (kill-switch)"


def test_kernel_check_agreement_and_drift() -> None:
    compiled, policy, facts = _hub()
    calls = []

    def agree(dst: str, mark: int | None, src: str | None) -> str | None:
        calls.append((dst, mark, src))
        return "oc-office0"

    ok = explain(compiled, policy, facts, "10.100.1.15", "10.60.1.5", route_get=agree)
    assert calls == [("10.60.1.5", 0x0C000200, None)]
    assert ok.kernel_check == "ip route get 10.60.1.5 mark 0x0c000200 -> dev oc-office0"
    assert ok.warnings == []

    leak = explain(
        compiled, policy, facts, "10.100.1.15", "10.60.1.5", route_get=lambda *_: "eth0"
    )
    assert leak.warnings == ["kernel routes it via eth0, compiled policy expects oc-office0"]


def test_kernel_check_flags_traffic_escaping_a_down_exit() -> None:
    policy, facts = hub_case()
    facts = dataclasses.replace(
        facts, tunnels={"upstream:office": TunnelFact("oc-office0", False)}
    )
    compiled = compile_policy(policy, facts)

    escaping = explain(
        compiled, policy, facts, "10.100.1.15", "10.60.1.5", route_get=lambda *_: "eth0"
    )
    blocked = explain(
        compiled, policy, facts, "10.100.1.15", "10.60.1.5", route_get=lambda *_: None
    )

    assert escaping.warnings == [
        "kernel routes it via eth0 although exit upstream:office is down"
    ]
    assert blocked.warnings == []
