"""Offline audit regressions: no host network reads, writes or subprocesses."""

from __future__ import annotations

import base64
import dataclasses
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from tests.test_net_kernel_apply import RecordingKernel, _NoNetlink
from tests.test_netinputs import UPSTREAM, FakeRunner, _config
from tests.test_upstream_service import FakeNet

from kornode.net import compile as compiler
from kornode.net import kernel as kernel_module
from kornode.net.compile import NodeFacts, TunnelFact, compile_policy
from kornode.net.diff import NftLoad, ReplaceRoute, SetSysctl, apply_to_state, diff
from kornode.net.errors import ApplyError, PolicyError
from kornode.net.explain import explain
from kornode.net.kernel import Kernel
from kornode.net.model import EgressPolicy
from kornode.net.state import ActualState, Sysctl
from kornode.services.netinputs import HubNetInputs, active_profile_file
from kornode.services.upstream import UpstreamService


def policy(*exits: str) -> EgressPolicy:
    return EgressPolicy.model_validate(
        {"egress": [{"from": ["host"], "to": "any", "via": name} for name in exits]}
    )


def facts() -> NodeFacts:
    return NodeFacts(
        node_id=1,
        client_pool=None,
        upstreams=("office", "backup"),
        active_upstream="office",
        tunnels={
            "upstream:office": TunnelFact("oc-office", True),
            "upstream:backup": TunnelFact("oc-backup", True),
        },
        uplink="eth0",
    )


def identities(compiled: Any) -> dict[str, tuple[int, str]]:
    return {item.name: (item.mark, item.identity_label) for item in compiled.exits}


def accepts_established(compiled: Any, mark: int, label: str) -> bool:
    """Evaluate the rendered early-hook identity allowlist and its terminal drop."""
    chain = compiled.script.split("chain validate_connection {", 1)[1].split("}", 1)[0]
    allowed = re.findall(
        r"ct mark & 0xffffff00 == (0x\w+) "
        r"ct label == \(([0-9 |]+)\) return",
        chain,
    )
    assert chain.strip().endswith("drop")
    assert compiled.script.count("meta mark set ct mark goto validate_connection") == 2
    return any(
        mark & 0xFFFFFF00 == int(m, 16)
        and int(label, 16) == sum(1 << int(bit) for bit in token.split("|"))
        for m, token in allowed
    )


def test_reorder_edit_delete_and_restart_never_adopt_another_exits_flows() -> None:
    before = compile_policy(policy("upstream:office", "local"), facts())
    old_mark, old_label = identities(before)["upstream:office"]
    reordered = compile_policy(policy("local", "upstream:backup", "upstream:office"), facts())
    assert identities(before)["upstream:office"] == identities(reordered)["upstream:office"]
    assert accepts_established(reordered, old_mark | 0x5A, old_label)
    assert identities(before)["local"] == identities(reordered)["local"]

    deleted = compile_policy(policy("local"), facts())
    assert identities(deleted)["local"][0] != old_mark
    assert not accepts_established(deleted, old_mark, old_label)
    # Nothing is kept in process-local allocation state; restart/re-add is identical.
    restarted = compile_policy(policy("upstream:office", "local"), facts())
    assert identities(before) == identities(restarted)
    assert accepts_established(restarted, old_mark, old_label)
    assert not accepts_established(restarted, 0x0C000100, "0x0")  # pre-upgrade conntrack
    assert not accepts_established(restarted, old_mark, "0x0")  # unlabeled cannot be adopted


def test_node_gateway_identities_stay_pinned_across_reorder_and_fail_closed_after_removal() -> None:
    from tests.test_net_transit import hub_facts

    node_facts = dataclasses.replace(
        hub_facts(guard=False),
        transit_exits=(),
        tunnels={"node:2": TunnelFact("vpns2", True), "node:3": TunnelFact("vpns3", True)},
    )
    before = compile_policy(policy("node:3", "local"), node_facts)
    reordered = compile_policy(policy("local", "node:2", "node:3"), node_facts)
    identity = identities(before)["node:3"]
    assert identities(reordered)["node:3"] == identity
    gateway = next(exit_ for exit_ in reordered.exits if exit_.name == "node:3")
    assert gateway.kind == "node" and gateway.interface == "vpns3" and not gateway.nat
    assert gateway.mark == compiler.exit_mark("node:3")
    assert accepts_established(reordered, *identity)
    assert not accepts_established(compile_policy(policy("local"), node_facts), *identity)


def test_active_mark_collision_is_an_error_and_deleted_collision_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = compiler.exit_mark
    monkeypatch.setattr(
        compiler,
        "exit_mark",
        lambda name: 0x0CFFFF00 if name.startswith("upstream:") else original(name),
    )
    with pytest.raises(PolicyError, match="mark collision"):
        compile_policy(policy("upstream:office", "upstream:backup"), facts())
    old = compile_policy(policy("upstream:office"), facts())
    replacement = compile_policy(policy("upstream:backup"), facts())
    old_mark, old_label = identities(old)["upstream:office"]
    new_mark, new_label = identities(replacement)["upstream:backup"]
    assert old_mark == new_mark and old_label != new_label
    assert not accepts_established(replacement, old_mark, old_label)
    assert accepts_established(replacement, new_mark, new_label)


def test_exit_count_respects_priority_and_table_ownership_bounds() -> None:
    names = tuple(f"p{i}" for i in range(100))
    many = dataclasses.replace(facts(), upstreams=names, active_upstream=None)
    with pytest.raises(PolicyError, match="at most 99"):
        compile_policy(policy(*(f"upstream:{name}" for name in names)), many)


def test_largest_supported_exit_set_stays_within_owned_ranges() -> None:
    names: list[str] = []
    seen: set[int] = set()
    for index in range(1000):
        name = f"p{index}"
        mark = compiler.exit_mark(f"upstream:{name}")
        if mark not in seen:
            names.append(name)
            seen.add(mark)
        if len(names) == 99:
            break
    compiled = compile_policy(
        policy(*(f"upstream:{name}" for name in names)),
        dataclasses.replace(facts(), upstreams=tuple(names), active_upstream=None),
    )
    assert max(rule.priority for rule in compiled.desired.rules) == 199
    assert max(route.table for route in compiled.desired.routes) == 12099
    assert all(
        0 <= exit_.mark <= 0xFFFFFFFF
        and exit_.mark & 0xFF == 0
        and exit_.mark & 0xFF000000 == 0x0C000000
        for exit_ in compiled.exits
    )
    new_marks = {exit_.mark for exit_ in compiled.exits}
    legacy_marks = {0x0C000000 | (index << 8) for index in range(1, 100)}
    assert not new_marks & legacy_marks


def test_alias_resolves_to_concrete_identity_and_named_rules_stay_pinned() -> None:
    cfg = policy("upstream:active", "upstream:office")
    before = compile_policy(cfg, facts())
    after_facts = dataclasses.replace(facts(), active_upstream="backup")
    after = compile_policy(cfg, after_facts)
    assert before.classify_host[0].exit.name == "upstream:office"
    assert after.classify_host[0].exit.name == "upstream:backup"
    assert before.classify_host[1].exit.mark == after.classify_host[1].exit.mark
    mark, label = identities(before)["upstream:office"]
    assert accepts_established(after, mark, label)
    decision = explain(after, cfg, after_facts, "host", "8.8.8.8")
    assert decision.route == "default dev oc-backup"
    assert decision.mark == f"0x{compiler.exit_mark('upstream:backup'):08x}"


def test_alias_with_no_selection_fails_closed_even_if_opt_out_was_requested() -> None:
    cfg = EgressPolicy.model_validate(
        {
            "egress": [
                {"from": ["host"], "to": "any", "via": "upstream:active", "kill_switch": False}
            ]
        }
    )
    compiled = compile_policy(cfg, dataclasses.replace(facts(), active_upstream=None))
    assert compiled.exits[0].kill_switch
    assert {route.type for route in compiled.desired.routes} == {"unreachable"}


@pytest.mark.parametrize("failover", [False, True])
def test_runtime_switch_and_failover_change_alias_dataplane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failover: bool
) -> None:
    config = _config(
        tmp_path,
        upstream={**UPSTREAM, "failover": True},
        egress=[
            {"from": ["host"], "to": "any", "via": "upstream:active"},
            {"from": ["clients"], "to": "any", "via": "upstream:main"},
        ],
    )
    inputs = HubNetInputs(config, runner=FakeRunner(), proc_sys=tmp_path / "proc")
    service = UpstreamService(config, runner=FakeRunner(), net=FakeNet())
    before = inputs.compiled()
    if failover:
        monkeypatch.setattr(service, "_profile_connected", lambda profile: profile.name == "backup")
        monkeypatch.setattr(
            service, "connect", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError())
        )
        monkeypatch.setattr(service, "_append_log", lambda *args: None)
        assert service.recover()
    else:
        service.switch_profile("backup")
    after = inputs.compiled()
    assert before.classify_host[0].exit.interface == "oc-middle0"
    assert after.classify_host[0].exit.interface == "oc-backup"
    pinned_before = next(rule.exit for rule in before.classify if rule.index == 1)
    pinned_after = next(rule.exit for rule in after.classify if rule.index == 1)
    assert pinned_before.mark == pinned_after.mark
    assert inputs.facts().active_upstream == "backup"


@pytest.mark.parametrize("global_enabled,profile_enabled", [(False, True), (True, False)])
def test_administrative_disablement_keeps_known_references_fail_closed(
    tmp_path: Path, global_enabled: bool, profile_enabled: bool
) -> None:
    upstream = {**UPSTREAM, "enabled": global_enabled}
    upstream["profiles"] = [{**UPSTREAM["profiles"][0], "enabled": profile_enabled}]
    config = _config(
        tmp_path,
        upstream=upstream,
        egress=[
            {"from": ["clients"], "to": "any", "via": "upstream:main", "kill_switch": False},
            {"from": ["host"], "to": "any", "via": "upstream:active"},
        ],
    )
    inputs = HubNetInputs(config, runner=FakeRunner(), proc_sys=tmp_path / "proc")
    compiled = inputs.compiled()
    assert "main" in inputs.facts().upstreams
    assert not inputs.facts().tunnels["upstream:main"].up
    assert {r.type for r in compiled.desired.routes} == {"unreachable"}
    assert all(e.kill_switch for e in compiled.exits)
    for exit_ in compiled.exits:
        assert f"meta mark & 0xffffff00 == 0x{exit_.mark:08x} drop" in compiled.script


def test_deleted_runtime_selection_does_not_silently_promote_default(tmp_path: Path) -> None:
    config = _config(tmp_path, upstream=UPSTREAM)
    marker = active_profile_file(config)
    marker.parent.mkdir(parents=True)
    marker.write_text("deleted-profile\n")
    inputs = HubNetInputs(config, runner=FakeRunner(), proc_sys=tmp_path / "proc")
    assert inputs.facts().active_upstream is None


@pytest.mark.parametrize("missing", [True, False])
def test_missing_nat_table_invalidates_schema_and_forces_reload(
    monkeypatch: pytest.MonkeyPatch, missing: bool
) -> None:
    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        family, name = argv[-2:]
        objects = [{"table": {"family": family, "name": name, "comment": "kornode-schema:ok"}}]
        if name == "kornode_nat":
            return subprocess.CompletedProcess(argv, 1 if missing else 0, '{"nftables": []}', "")
        return subprocess.CompletedProcess(argv, 0, json.dumps({"nftables": objects}), "")

    monkeypatch.setattr(kernel_module.subprocess, "run", run)
    schema, elements = Kernel()._read_nft()
    assert schema is None and not elements
    desired = compile_policy(policy("local"), facts()).desired
    plan = diff(ActualState(nft_schema_hash=schema, elements=elements), desired)
    assert any(isinstance(op, NftLoad) for op in plan.ops)


def test_dotted_interface_sysctl_read_and_write_use_literal_interface_directory(
    tmp_path: Path,
) -> None:
    target = tmp_path / "net" / "ipv4" / "conf" / "eth0.100" / "rp_filter"
    target.parent.mkdir(parents=True)
    target.write_text("1\n")
    sysctl = Sysctl("net.ipv4.conf.eth0.100.rp_filter", "2")
    kernel = Kernel(proc_sys=tmp_path)
    assert kernel._read_sysctls([sysctl.key]) == [dataclasses.replace(sysctl, value="1")]
    kernel._apply_one(None, SetSysctl(sysctl))
    assert target.read_text() == "2\n"
    assert not (target.parent.parent / "eth0").exists()


def test_route_slot_reassignment_is_guarded_and_failure_keeps_the_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = compile_policy(policy("upstream:office", "local"), facts()).desired
    after = compile_policy(policy("upstream:backup", "local"), facts()).desired
    actual = apply_to_state(ActualState(), diff(ActualState(), before))
    plan = diff(actual, after)
    assert isinstance(plan.ops[0], NftLoad) and plan.ops[0].guard
    assert plan.ops[0].ruleset.script.count("meta mark & 0xff000000 == 0x0c000000 drop") == 2
    final = next(op for op in plan.ops if isinstance(op, NftLoad) and not op.guard)
    assert final.ruleset == after.nft
    assert diff(apply_to_state(actual, plan), after).is_empty

    monkeypatch.setattr(kernel_module, "IPRoute", _NoNetlink)
    failing = next(op for op in plan.ops if isinstance(op, ReplaceRoute))
    kernel = RecordingKernel({failing})
    with pytest.raises(ApplyError):
        kernel.apply(plan)
    assert plan.ops[0] in kernel.applied
    assert final not in kernel.applied


def test_guard_failure_aborts_before_any_route_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    desired = compile_policy(policy("upstream:office"), facts()).desired
    plan = diff(ActualState(), desired)
    monkeypatch.setattr(kernel_module, "IPRoute", _NoNetlink)
    kernel = RecordingKernel(set())
    monkeypatch.setattr(
        kernel, "_apply_nft", lambda batch: (_ for _ in ()).throw(ApplyError("guard failed"))
    )
    with pytest.raises(ApplyError, match="guard failed"):
        kernel.apply(plan)
    assert kernel.applied == []


@pytest.mark.parametrize(
    "label",
    ["0x1", "0x80", "0x80000000000000000000000000000000", "0xffffffffffffffffffffffffffffffff"],
)
def test_nft_labels_are_bit_index_expressions_not_raw_hex_literals(label: str) -> None:
    from kornode.net.nftgen import label_bits

    expression = label_bits(label)
    assert expression.startswith("(") and expression.endswith(")") and "," not in expression
    bits = [int(bit) for bit in expression[1:-1].split("|")]
    assert all(0 <= bit <= 127 for bit in bits)
    assert sum(1 << bit for bit in bits) == int(label, 16)
    compiled = compile_policy(policy("upstream:office"), facts())
    assert not re.search(r"ct label (?:set|==|&) 0x", compiled.script)
    assignment = next(line for line in compiled.script.splitlines() if "ct label set" in line)
    assert assignment.endswith('goto validate_connection comment "egress rule 0"')
    identity = identities(compiled)["upstream:office"]
    extra_bit = next(bit for bit in range(128) if not int(identity[1], 16) & (1 << bit))
    assert not accepts_established(
        compiled, identity[0], hex(int(identity[1], 16) | (1 << extra_bit))
    )
    assert not accepts_established(
        compiled, identity[0], hex(int(identity[1], 16) & (int(identity[1], 16) - 1))
    )


def test_guard_populates_split_host_sets_in_the_same_transaction_before_routing() -> None:
    from kornode.net.diff import AddRule, UpdateElements

    cfg = EgressPolicy.model_validate(
        {
            "sets": {"corp": {"routes": ["198.18.0.1/32"]}},
            "egress": [{"from": ["host"], "to": {"set": "corp"}, "via": "upstream:office"}],
        }
    )
    desired = compile_policy(cfg, facts()).desired
    plan = diff(ActualState(), desired)
    first_route = next(
        i for i, op in enumerate(plan.ops) if isinstance(op, (ReplaceRoute, AddRule))
    )
    prefix = plan.ops[:first_route]
    assert isinstance(prefix[0], NftLoad) and prefix[0].guard
    populated = {op.set_name: op.target for op in prefix if isinstance(op, UpdateElements)}
    assert populated["corp_v4"] == {"198.18.0.1/32"}
    assert all(isinstance(op, (NftLoad, UpdateElements, SetSysctl)) for op in prefix)


@pytest.mark.parametrize("failure_kind", ["DelRoute", "DelRule", "ReplaceRoute"])
def test_stale_route_removal_and_all_routing_failures_precede_guard_release(
    monkeypatch: pytest.MonkeyPatch, failure_kind: str
) -> None:
    from kornode.net.diff import DelRoute, DelRule

    before = compile_policy(policy("upstream:office", "upstream:backup"), facts()).desired
    after = compile_policy(policy("upstream:backup"), facts()).desired
    actual = apply_to_state(ActualState(), diff(ActualState(), before))
    plan = diff(actual, after)
    final = next(op for op in plan.ops if isinstance(op, NftLoad) and not op.guard)
    final_index = plan.ops.index(final)
    deletions = [op for op in plan.ops if isinstance(op, (DelRoute, DelRule))]
    assert deletions and all(plan.ops.index(op) < final_index for op in deletions)
    failing = next(op for op in plan.ops if type(op).__name__ == failure_kind)
    monkeypatch.setattr(kernel_module, "IPRoute", _NoNetlink)
    kernel = RecordingKernel({failing})
    with pytest.raises(ApplyError):
        kernel.apply(plan)
    assert plan.ops[0] in kernel.applied and final not in kernel.applied


def test_deletion_only_repair_is_guarded_and_finishes_idempotently() -> None:
    from kornode.net.diff import DelRoute
    from kornode.net.state import Route

    desired = compile_policy(policy("upstream:office"), facts()).desired
    actual = apply_to_state(ActualState(), diff(ActualState(), desired))
    actual = dataclasses.replace(
        actual, routes=actual.routes | {Route(12099, "default", dev="old0")}
    )
    plan = diff(actual, desired)
    assert isinstance(plan.ops[0], NftLoad) and plan.ops[0].guard
    deletion = next(i for i, op in enumerate(plan.ops) if isinstance(op, DelRoute))
    final = next(i for i, op in enumerate(plan.ops) if isinstance(op, NftLoad) and not op.guard)
    assert deletion < final
    assert diff(apply_to_state(actual, plan), desired).is_empty


def test_prepared_netlab_programs_are_syntax_checked_without_running_them() -> None:
    import ast

    path = Path(__file__).parent / "netlab" / "test_net_kernel.py"
    tree = ast.parse(path.read_text())
    programs = {
        assignment.targets[0].id: ast.literal_eval(assignment.value)
        for assignment in tree.body
        if isinstance(assignment, ast.Assign)
        and isinstance(assignment.targets[0], ast.Name)
        and assignment.targets[0].id.startswith("_AUDIT_")
        and assignment.targets[0].id.endswith("_CODE")
    }
    assert len(programs) == 3
    for name, source in programs.items():
        compile(source, f"{path.name}:{name}", "exec")


def test_kernel_sends_guard_and_its_elements_in_one_batch_before_route_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.net.diff import UpdateElements

    cfg = EgressPolicy.model_validate(
        {
            "sets": {"corp": {"routes": ["198.18.0.1/32"]}},
            "egress": [{"from": ["host"], "to": {"set": "corp"}, "via": "upstream:office"}],
        }
    )
    plan = diff(ActualState(), compile_policy(cfg, facts()).desired)
    batches: list[list[NftLoad | UpdateElements]] = []
    kernel = RecordingKernel(set())
    original_apply = kernel._apply_nft

    def nft_batch(batch: list[NftLoad | UpdateElements]) -> None:
        batches.append(batch)
        original_apply(batch)

    monkeypatch.setattr(kernel_module, "IPRoute", _NoNetlink)
    monkeypatch.setattr(kernel, "_apply_nft", nft_batch)
    kernel.apply(plan)
    assert len(batches) == 2
    guard = batches[0][0]
    assert isinstance(guard, NftLoad) and guard.guard
    assert any(
        isinstance(op, UpdateElements) and op.set_name == "corp_v4" and op.target
        for op in batches[0]
    )
    assert max(kernel.applied.index(op) for op in batches[0]) < min(
        i for i, op in enumerate(kernel.applied) if isinstance(op, ReplaceRoute)
    )
    final = batches[1][0]
    assert isinstance(final, NftLoad) and not final.guard


def test_transit_reply_rpf_exemption_cannot_skip_identity_validation() -> None:
    from tests.test_net_transit import hub_facts

    compiled = compile_policy(EgressPolicy(), hub_facts())
    rpf = compiled.script.split("chain session_rpf {", 1)[1].split("}", 1)[0]
    prerouting = compiled.script.split("chain prerouting {", 1)[1].split("}", 1)[0]
    assert "iifname @transit_ifaces ct direction reply ct state established,related return" in rpf
    assert "ct direction reply" in rpf and "fib saddr . iif oif missing drop" in rpf
    assert "return" not in prerouting
    assert prerouting.index("jump session_rpf") < prerouting.index("goto validate_connection")
    # A return in the regular RPF chain resumes the base chain and reaches
    # validation; it cannot skip restore/validation like a base-chain return.
    assert "drop" in compiled.script.split("chain validate_connection {", 1)[1].split("}", 1)[0]


def test_netlab_ocserv_hooks_inherit_the_fixture_config_not_the_image_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from tests.netlab import kornode_nodes as nodes

    from kornode.services.command import CommandResult

    monkeypatch.setenv("KORNODE_CONFIG", "/unrelated/default.yaml")
    monkeypatch.setenv("AUDIT_PARENT_ENV", "retained")
    monkeypatch.setattr(nodes, "initialize_runtime", lambda *args: None)
    monkeypatch.setattr(
        nodes, "korctl", lambda *args: CommandResult((), 0, '{"pin": "test-pin"}', "")
    )
    monkeypatch.setattr(nodes, "_wait_until", lambda *args, **kwargs: None)
    process = SimpleNamespace(poll=lambda: None)
    captured: dict[str, Any] = {}

    def spawn(ns: Any, argv: list[str], log_file: Path, **kwargs: Any) -> Any:
        captured.update(argv=argv, log_file=log_file, **kwargs)
        return process

    monkeypatch.setattr(nodes, "_popen_in_namespace", spawn)
    lab = SimpleNamespace(log_dirs=[])
    topology = SimpleNamespace(hub=object(), node3=object())
    handle = nodes.start_hub_server(lab, topology, tmp_path)
    assert captured["argv"][0] == "ocserv"
    assert captured["env"]["KORNODE_CONFIG"] == str(handle.config_path)
    assert captured["env"]["AUDIT_PARENT_ENV"] == "retained"
    assert handle.process is process


def test_netlab_namespace_launcher_forwards_explicit_environment_without_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from tests.netlab import kornode_nodes as nodes

    captured: dict[str, Any] = {}
    marker = object()

    def popen(argv: list[str], **kwargs: Any) -> Any:
        captured.update(argv=argv, **kwargs)
        return marker

    monkeypatch.setattr(nodes.subprocess, "Popen", popen)
    env = {"KORNODE_CONFIG": str(tmp_path / "fixture.yaml")}
    result = nodes._popen_in_namespace(
        SimpleNamespace(full_name="isolated-test"), ["ocserv"], tmp_path / "ocserv.log", env=env
    )
    assert result is marker
    assert captured["argv"] == ["ip", "netns", "exec", "isolated-test", "ocserv"]
    assert captured["env"] == env


@pytest.mark.parametrize("auth_type", ["cert", "p12", "password"])
def test_connect_dry_run_is_read_only_even_with_uploaded_identity(
    tmp_path: Path, auth_type: str
) -> None:
    profile: dict[str, Any] = {
        "name": "main",
        "server": "203.0.113.2",
        "auth_type": auth_type,
        "username": "user",
        "password": "not-for-logs",
        "camouflage_secret": "hidden",
    }
    if auth_type != "password":
        profile.update(
            cert_file_base64=base64.b64encode(b"certificate").decode(),
            key_file_base64=base64.b64encode(b"private-key").decode(),
            cert_pass="key-pass",
        )
    config = _config(tmp_path, upstream={"enabled": True, "profiles": [profile]})
    from tests.test_upstream_service import FakeRunner as UpstreamRunner

    runner = UpstreamRunner()
    net = FakeNet()
    service = UpstreamService(config, runner=runner, net=net)
    before = list(tmp_path.rglob("*"))
    service.connect(dry_run=True)
    assert list(tmp_path.rglob("*")) == before
    assert net.calls == []
    assert all(call["dry_run"] for call in runner.calls)


@pytest.mark.parametrize("interface", ["eth0.100", "oc.office"])
def test_sysctl_compilation_keeps_dotted_tunnel_names_literal(interface: str) -> None:
    cfg = policy("upstream:office")
    node = dataclasses.replace(facts(), tunnels={"upstream:office": TunnelFact(interface, True)})
    assert (
        Sysctl(f"net.ipv4.conf.{interface}.rp_filter", "2")
        in compile_policy(cfg, node).desired.sysctls
    )


def test_connect_dry_run_does_not_overwrite_existing_runtime_material(tmp_path: Path) -> None:
    from tests.test_upstream_service import FakeRunner as UpstreamRunner

    config = _config(tmp_path, upstream=UPSTREAM)
    service = UpstreamService(config, runner=UpstreamRunner(), net=FakeNet())
    profile = config.upstream.profiles[0]
    profile.cert_file_base64 = base64.b64encode(b"replacement certificate").decode()
    profile.key_file_base64 = base64.b64encode(b"replacement key").decode()
    profile.auth_type = "cert"
    paths = [
        config.system.generated_dir / "vpnc-script-kornode",
        service._profile_secrets_dir(profile) / "cert",
        service._profile_secrets_dir(profile) / "key",
        service._profile_secrets_dir(profile) / "openconnect.conf",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("operator material")
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
    service.connect(dry_run=True)
    assert before == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
    assert not service._lock_path.exists()
