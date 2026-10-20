"""P4-03: the agent's node resolver from the bundle (D-66)."""

from __future__ import annotations

import dataclasses
import ipaddress
import threading
import time
from pathlib import Path

from tests.test_agent_inputs import CONFIG, FakeCarriers, FakeProbes, _validated

from kornode.net.compile import compile_policy
from kornode.net.state import Address
from kornode_agent.dns import NodeResolver, render
from kornode_agent.inputs import AgentNetInputs


class Control:
    def __init__(self, ok: bool = True) -> None:
        self.calls: list[str] = []
        self.ok = ok

    def __call__(self, action: str) -> bool:
        self.calls.append(action)
        return self.ok


def test_render_answers_own_zone_and_forwards_the_fabric_zone(tmp_path: Path) -> None:
    bundle = _validated(tmp_path).bundle
    conf = render(bundle)
    assert conf is not None
    lines = conf.splitlines()
    assert "listen-address=10.100.3.1" in lines
    assert "bind-dynamic" in lines and "bind-interfaces" not in lines
    assert "local=/node3.kornode.internal/" in lines
    assert "host-record=node3.kornode.internal,10.100.3.1" in lines
    assert "host-record=nas.node3.kornode.internal,192.168.3.10" in lines
    # Over the fabric with the fabric address as source (strict RPF on the hub).
    assert "server=/kornode.internal/10.100.1.1@10.99.0.3" in lines
    assert "server=/corp.example.com/10.60.0.53@10.99.0.3" in lines
    plain = [
        line
        for line in lines
        if line == "no-resolv" or (line.startswith("server=") and not line.startswith("server=/"))
    ]
    assert plain == ["no-resolv", "server=1.1.1.1", "server=8.8.8.8"]


def test_render_without_dns_section_is_none(tmp_path: Path) -> None:
    bundle = _validated(tmp_path).bundle.model_copy(update={"dns": None})
    assert render(bundle) is None


def test_resolver_restarts_only_on_change_and_stops_without_dns(tmp_path: Path) -> None:
    bundle = _validated(tmp_path).bundle
    control = Control()
    resolver = NodeResolver(tmp_path / "agent", control=control)

    resolver.apply(bundle)
    resolver.apply(bundle)
    assert control.calls == ["restart"]
    assert (tmp_path / "agent/run/dnsmasq.conf").read_text() == render(bundle)

    resolver.apply(bundle.model_copy(update={"dns": None}))
    assert control.calls == ["restart", "stop"]
    assert not (tmp_path / "agent/run/dnsmasq.conf").exists()
    resolver.apply(None)
    assert control.calls == ["restart", "stop"]
    assert resolver.error is None


def test_first_apply_after_restart_starts_an_unchanged_configuration(tmp_path: Path) -> None:
    bundle = _validated(tmp_path).bundle
    NodeResolver(tmp_path / "agent", control=Control()).apply(bundle)
    control = Control()
    NodeResolver(tmp_path / "agent", control=control).apply(bundle)
    assert control.calls == ["restart"]


def test_bootstrap_stops_a_resolver_left_from_a_previous_bundle(tmp_path: Path) -> None:
    control = Control()
    NodeResolver(tmp_path / "agent", control=control).apply(None)
    assert control.calls == ["stop"]


def test_supervisor_failure_is_kept_not_raised_and_retried(tmp_path: Path) -> None:
    bundle = _validated(tmp_path).bundle
    control = Control(ok=False)
    resolver = NodeResolver(tmp_path / "agent", control=control)
    assert resolver.apply(bundle) is False
    assert resolver.error == "supervisorctl restart dnsmasq failed"
    # Same bundle again: a failed restart is not "applied", so it is retried.
    control.ok = True
    assert resolver.apply(bundle) is True
    assert control.calls == ["restart", "restart"] and resolver.error is None


def test_failed_stop_keeps_the_configuration_for_a_retry(tmp_path: Path) -> None:
    bundle = _validated(tmp_path).bundle
    control = Control()
    resolver = NodeResolver(tmp_path / "agent", control=control)
    resolver.apply(bundle)
    control.ok = False
    assert resolver.apply(None) is False
    assert (tmp_path / "agent/run/dnsmasq.conf").exists()
    control.ok = True
    assert resolver.apply(None) is True
    assert not (tmp_path / "agent/run/dnsmasq.conf").exists()


def test_submit_never_blocks_and_retries_in_the_background(tmp_path: Path) -> None:
    bundle = _validated(tmp_path).bundle
    release = threading.Event()
    calls: list[str] = []

    def slow(action: str) -> bool:
        calls.append(action)
        release.wait(5)
        return len(calls) > 1  # the first attempt fails

    resolver = NodeResolver(tmp_path / "agent", control=slow, retry_seconds=0.05)
    started = time.monotonic()
    resolver.submit(bundle)
    assert time.monotonic() - started < 1
    release.set()
    deadline = time.monotonic() + 5
    while resolver._worker is not None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert calls == ["restart", "restart"] and resolver.error is None


def test_resolver_address_is_bound_to_lo_by_the_reconciler(tmp_path: Path) -> None:
    inputs = AgentNetInputs(CONFIG, FakeProbes({"oc-hub0": True}), FakeCarriers())
    inputs.set_bundle(_validated(tmp_path))
    facts = inputs.facts()
    assert facts.local_addresses == (ipaddress.IPv4Address("10.100.3.1"),)
    desired = compile_policy(inputs.policy(), facts).desired
    assert Address("lo", "10.100.3.1/32") in desired.addresses


def test_no_dns_section_binds_nothing(tmp_path: Path) -> None:
    validated = _validated(tmp_path)
    without = dataclasses.replace(
        validated, bundle=validated.bundle.model_copy(update={"dns": None})
    )
    inputs = AgentNetInputs(CONFIG, FakeProbes({"oc-hub0": True}), FakeCarriers())
    inputs.set_bundle(without)
    assert inputs.facts().local_addresses == ()
