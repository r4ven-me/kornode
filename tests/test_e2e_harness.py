"""Local harness safety tests. All VM/Docker calls here are fakes, not E2E evidence."""

from __future__ import annotations

import io
import json
import os
import re
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest
import yaml
from tests.e2e.__main__ import main
from tests.e2e.fleet import Cluster, Fleet, wait_for
from tests.e2e.inventory import ACK, E2EError, Inventory
from tests.e2e.transport import SSH
from tests.e2e.worker import Worker
from tests.test_agent_tunnels import Fake as TunnelFake

from kornode.config.models import AppConfig
from kornode.tunnels.argv import DialSpec
from kornode_agent.tunnels import TunnelManager, TunnelSpec

RUN_ID = "a" * 24


@pytest.fixture
def environment(tmp_path: Path) -> dict[str, str]:
    key, known = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("fake-key-for-local-tests-only\n")
    key.chmod(0o600)
    known.write_text("fake-pinned-hosts-for-local-tests-only\n")
    return {
        "E2E_ALLOW_DESTRUCTIVE": ACK,
        "E2E_SSH_USER": "e2e",
        "E2E_HUB_HOST": "192.0.2.1",
        "E2E_AGENT_A_HOST": "192.0.2.2",
        "E2E_AGENT_B_HOST": "192.0.2.3",
        "E2E_EXT_HOST": "192.0.2.4",
        "E2E_SSH_KEY_FILE": str(key),
        "E2E_KNOWN_HOSTS_FILE": str(known),
    }


def request(action: str, role: str = "hub", case: str = "enroll", **payload: Any) -> dict[str, Any]:
    return {"run_id": RUN_ID, "role": role, "case": case, "action": action, "payload": payload}


class FakeWorker(Worker):
    commands: list[tuple[list[str], dict[str, Any]]]

    def run(self, argv: list[str], **kwargs: Any) -> tuple[int, bytes]:
        self.commands.append((argv, kwargs))
        return 0, b""

    def image(self, value: str) -> str:
        return "sha256:" + "1" * 64

    def cli(self, *args: str, **kwargs: Any) -> Any:
        self.commands.append((list(args), kwargs))
        return {"desired_version": 2}


@pytest.fixture
def worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeWorker:
    marker = tmp_path / "marker.json"
    machine = tmp_path / "machine-id"
    machine.write_text("f" * 32)
    marker.write_text(
        json.dumps({"purpose": "kornode-e2e-disposable", "role": "hub", "machine_id": "f" * 32})
    )
    instance = FakeWorker(request("deploy"), base=tmp_path / "base", marker=marker)
    instance.machine_file = machine
    instance.commands = []

    instance.marker = Mock(wraps=marker)
    instance.marker.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    instance.claim()
    return instance


def test_inventory_does_not_repr_hosts_or_secrets(environment: dict[str, str]) -> None:
    inventory = Inventory.from_env(environment)
    assert inventory.hub_address == environment["E2E_HUB_HOST"]
    assert environment["E2E_HUB_HOST"] not in repr(inventory)
    assert environment["E2E_SSH_KEY_FILE"] not in repr(inventory)
    assert len(inventory.hosts) == 4


@pytest.mark.parametrize(
    "field,value",
    [
        ("E2E_ALLOW_DESTRUCTIVE", "yes"),
        ("E2E_SSH_USER", "root;evil"),
        ("E2E_SSH_PORT", "0"),
        ("E2E_HUB_HOST", "127.0.0.1"),
        ("E2E_HUB_HOST", "0.0.0.0"),
        ("E2E_EXT_HOST", "192.0.2.1"),
        ("E2E_AGENT_A_HOST", "--ProxyCommand=evil"),
        ("E2E_HUB_ADDRESS", "hub;evil"),
    ],
)
def test_invalid_inventory_is_rejected_without_echoing(
    environment: dict[str, str], field: str, value: str
) -> None:
    environment[field] = value
    with pytest.raises(E2EError) as exc:
        Inventory.from_env(environment)
    assert value not in str(exc.value)


def test_empty_optional_hub_address_uses_inventory(environment: dict[str, str]) -> None:
    environment["E2E_HUB_ADDRESS"] = ""
    assert Inventory.from_env(environment).hub_address == environment["E2E_HUB_HOST"]


def test_key_permissions_and_symlinks_rejected(environment: dict[str, str], tmp_path: Path) -> None:
    Path(environment["E2E_SSH_KEY_FILE"]).chmod(0o644)
    with pytest.raises(E2EError):
        Inventory.from_env(environment)
    Path(environment["E2E_SSH_KEY_FILE"]).chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(environment["E2E_SSH_KEY_FILE"])
    environment["E2E_SSH_KEY_FILE"] = str(link)
    with pytest.raises(E2EError):
        Inventory.from_env(environment)


@pytest.mark.parametrize(
    "hub,agent", [("repo:latest", "repo:old"), ("repo@sha256:" + "1" * 64, "")]
)
def test_upgrade_requires_paired_digests(environment: dict[str, str], hub: str, agent: str) -> None:
    environment.update(E2E_PREVIOUS_HUB_IMAGE=hub, E2E_PREVIOUS_AGENT_IMAGE=agent)
    with pytest.raises(E2EError):
        Inventory.from_env(environment)


def test_pinned_ssh_and_payload_not_in_argv(environment: dict[str, str]) -> None:
    inventory = Inventory.from_env(environment)
    ssh = SSH(inventory, inventory.host("hub"), RUN_ID)
    command = ssh.argv()
    assert "StrictHostKeyChecking=yes" in command and "ForwardAgent=no" in command
    assert "-F" in command and "IdentitiesOnly=yes" in command
    secret = "sensitive-token-;$(do-not-execute)"
    body = ssh.request("enroll", "enroll", token=secret)
    assert secret.encode() in body and secret not in " ".join(command)
    assert "sudo -n -- python3 -c" in command[-1]


def test_transport_never_echoes_remote_output(
    environment: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    inventory = Inventory.from_env(environment)

    def fail(*args: Any, **kwargs: Any) -> Any:
        kwargs["stderr"].write(b"PRIVATE KEY secret-password")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr("tests.e2e.transport.subprocess.run", fail)
    with pytest.raises(E2EError) as exc:
        SSH(inventory, inventory.host("hub"), RUN_ID).call("status")
    assert "PRIVATE KEY" not in str(exc.value) and "secret-password" not in str(exc.value)


@pytest.mark.parametrize("location", ["controller", "worker"])
def test_docker_commands_pin_local_socket(
    worker: FakeWorker, monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    from tests.e2e.fleet import local

    calls = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        calls.append(argv)
        return SimpleNamespace(returncode=0)

    monkeypatch.setenv("DOCKER_HOST", "tcp://production.invalid:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "production-must-not-be-used")
    monkeypatch.setattr("subprocess.run", run)
    if location == "controller":
        local(["docker", "info"])
    else:
        Worker.run(worker, ["docker", "info"])
    assert calls == [["docker", "--host", "unix:///var/run/docker.sock", "info"]]


def test_build_pins_default_builder_and_run_specific_tags(
    environment: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance = Fleet(Inventory.from_env(environment))
    instance.artifacts = tmp_path / "artifacts"
    commands = []

    def local(argv: list[str]) -> bytes:
        commands.append(argv)
        return ("sha256:" + "1" * 64).encode() if "inspect" in argv else b""

    monkeypatch.setattr(instance, "preflight", lambda: {})
    monkeypatch.setattr(instance, "call", lambda *args: {})
    monkeypatch.setattr("tests.e2e.fleet.local", local)
    for connection in instance.connections.values():
        monkeypatch.setattr(connection, "load", lambda archive: {})
    instance.start()
    builds = [command for command in commands if command[1] == "build"]
    assert len(builds) == 2
    assert all(command[2:4] == ["--builder", "default"] for command in builds)
    assert all(instance.run_id in command[command.index("--tag") + 1] for command in builds)


def test_marker_required_before_commands(worker: FakeWorker) -> None:
    cast(Mock, worker.marker).read_text.return_value = "{}"
    with pytest.raises(ValueError):
        worker.dispatch(io.BytesIO())
    assert worker.commands == []


def test_marker_owner_and_permissions_required(worker: FakeWorker) -> None:
    cast(Mock, worker.marker).lstat.return_value = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o666,
        st_uid=0,
    )
    with pytest.raises(ValueError):
        worker.guard()
    cast(Mock, worker.marker).lstat.return_value = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_uid=1000,
    )
    with pytest.raises(ValueError):
        worker.guard()
    assert worker.commands == []


def test_lease_never_stolen(worker: FakeWorker) -> None:
    previous = (worker.base / "lease.json").read_bytes()
    with pytest.raises(FileExistsError):
        worker.claim()
    assert (worker.base / "lease.json").read_bytes() == previous


@pytest.mark.parametrize(
    "role,case", [("unknown", "enroll"), ("hub", "../victim"), ("hub", "/tmp/victim")]
)
def test_worker_identity_and_case_are_allowlisted(tmp_path: Path, role: str, case: str) -> None:
    with pytest.raises(ValueError):
        Worker(request("deploy", role, case), base=tmp_path)


def test_rendered_hub_compose_is_isolated_and_config_valid(worker: FakeWorker) -> None:
    worker.payload = {"image": "kornode-e2e:hub-test", "endpoint": "192.0.2.1"}
    worker.deploy()
    config = json.loads((worker.directory / "config.json").read_text())
    model = AppConfig.model_validate(config)
    assert model.control.enabled and not model.web.enabled
    service = json.loads((worker.directory / "compose.json").read_text())["services"]["node"]
    assert "network_mode" not in service and "privileged" not in service
    assert not any("docker.sock" in json.dumps(value) for value in service["volumes"])
    assert service["labels"]["org.kornode.e2e.run"] == RUN_ID
    assert service["volumes"][0]["read_only"] is True
    assert all(
        v["source"] != str(worker.directory) for v in service["volumes"] if not v.get("read_only")
    )
    assert (worker.directory / "config.json").stat().st_mode & 0o777 == 0o600


def test_cleanup_refuses_foreign_owner(worker: FakeWorker) -> None:
    worker.directory.mkdir()
    (worker.directory / "owner.json").write_text("{}")
    victim = worker.directory / "valuable"
    victim.write_text("keep")
    with pytest.raises(ValueError):
        worker.cleanup()
    assert victim.read_text() == "keep" and worker.commands == []


def test_release_retains_lease_when_unknown_data_remains(worker: FakeWorker) -> None:
    (worker.root / "unknown").write_text("keep")
    with pytest.raises(ValueError):
        worker.release()
    assert (worker.base / "lease.json").exists()


def test_secret_input_file_is_private_and_not_cli_argv(worker: FakeWorker) -> None:
    worker.payload = {"image": "test:hub", "endpoint": "192.0.2.1"}
    worker.deploy()
    worker.backup()
    path = worker.directory / "recovery" / "passphrase"
    secret = path.read_text()
    assert len(secret) > 12 and path.stat().st_mode & 0o777 == 0o600
    assert all(secret not in repr(command) for command in worker.commands)


def test_image_transfer_is_bounded_before_load(worker: FakeWorker) -> None:
    worker.payload = {"size": 3 * 1024**3 + 1}
    with pytest.raises(ValueError):
        worker.load_images(io.BytesIO())
    worker.payload = {"size": 10}
    with pytest.raises(ValueError):
        worker.load_images(io.BytesIO(b"too short"))
    assert worker.commands == []


def test_offline_plan_performs_no_inventory_or_ssh(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys, "argv", ["e2e", "plan"])
    monkeypatch.setattr(
        Inventory,
        "from_env",
        lambda *args, **kwargs: pytest.fail("inventory read during offline plan"),
    )
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["network_actions"] is False
    assert result["blocked_contracts"] == {}
    assert set(result["netlab_coverage"]) == {"NL-07", "NL-08", "NL-09"}
    assert any("access-client traffic" in case for case in result["runnable_cases"])


def test_sla_does_not_pass_after_slow_success(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = iter([0.0, 2.0])
    monkeypatch.setattr("tests.e2e.fleet.time.monotonic", lambda: next(clock))
    with pytest.raises(E2EError):
        wait_for(lambda: True, 1, "SLA exceeded")


def test_preflight_rejects_cloned_machine_ids(
    environment: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    instance = Fleet(Inventory.from_env(environment))
    for connection in instance.connections.values():
        monkeypatch.setattr(connection, "call", lambda *args, **kwargs: {"machine": "f" * 64})
    with pytest.raises(E2EError):
        instance.preflight()


def test_workflow_guards_and_artifact_allowlist() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / ".github/workflows/e2e.yml").read_text()
    workflow = yaml.safe_load(text)
    job = workflow["jobs"]["e2e"]
    assert job["environment"] == "kornode-e2e"
    assert "github.event_name == 'workflow_dispatch'" in job["if"]
    assert "github.ref_protected" in job["if"]
    assert "E2E_ENVIRONMENT_APPROVAL_CONFIGURED" in job["if"]
    assert workflow["concurrency"]["cancel-in-progress"] is False
    triggers = workflow.get("on") or workflow.get(True)
    assert set(triggers) == {"workflow_dispatch"}
    checkout = next(
        s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout")
    )
    assert checkout["with"]["clean"] is False  # keeps artifacts/e2e/*/active.json
    upload = next(
        step
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert 1 <= upload["with"]["retention-days"] <= 14
    assert set(upload["with"]["path"].splitlines()) == {
        "artifacts/e2e/**/summary.json",
        "artifacts/e2e/junit.xml",
    }
    assert all("network_mode: host" not in line for line in text.splitlines())


@pytest.mark.parametrize("tamper", [False, True])
def test_fault_bundle_is_signed_or_really_tampered_without_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    tamper: bool,
) -> None:
    from tests.e2e.worker import INJECT_BUNDLE
    from tests.test_bundle_service import Env

    from kornode.bundle.errors import BundleError
    from kornode.bundle.signing import key_id, verify

    env = Env(tmp_path / "hub")
    try:
        env.add(2)
        env.registry.update_node(2, name="agent-a")
        previous = env.compile(2)
        config = tmp_path / "config.json"
        config.write_text(json.dumps(env.config.model_dump(mode="json")))
        monkeypatch.setenv("KORNODE_CONFIG", str(config))
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"tamper": tamper})))
        exec(compile(INJECT_BUNDLE, "<e2e-fault-bundle>", "exec"), {})
        result = json.loads(capsys.readouterr().out)
        stored = env.registry.latest_bundle(2)
        assert stored is not None
        assert stored.version == result["version"] > previous.version
        key = env.service.signing_key().public_key()
        if tamper:
            with pytest.raises(BundleError):
                verify(stored.body, stored.signature, {key_id(key): key})
        else:
            verify(stored.body, stored.signature, {key_id(key): key})
            assert json.loads(stored.body)["hubs"][0]["port"] == 1
    finally:
        env.registry.conn.close()


def test_fault_watchdog_armed_before_namespaced_drop(
    worker: FakeWorker, monkeypatch: pytest.MonkeyPatch
) -> None:
    order = []
    worker.role, worker.case = "agent-b", "blackhole"
    monkeypatch.setattr(worker, "container", lambda: "c" * 64)
    monkeypatch.setattr(
        "tests.e2e.worker.subprocess.Popen", lambda *args, **kwargs: order.append("watchdog")
    )
    monkeypatch.setattr(worker, "execute", lambda *args, **kwargs: order.append("namespaced-drop"))
    assert worker.fault()["seconds"] == 60
    assert order == ["watchdog", "namespaced-drop"]


@pytest.mark.parametrize("role", ["agent-a", "agent-b", "ext"])
def test_agent_and_ext_compose_never_use_host_namespace(worker: FakeWorker, role: str) -> None:
    worker.role = role
    worker.payload = {"image": "test:node", "endpoint": "192.0.2.4"}
    worker.deploy()
    service = json.loads((worker.directory / "compose.json").read_text())["services"]["node"]
    assert "network_mode" not in service and "pid" not in service and "privileged" not in service
    assert "18444:18444/tcp" not in service.get("ports", [])
    if role.startswith("agent-"):
        assert any(v["target"] == "/var/lib/kornode-agent" for v in service["volumes"])
        assert worker.commands[-1][0][-2:] == ["create", "node"]
    else:
        # ext is a plain upstream "office": no control plane, no web (the interlink itself
        # is always part of a hub, D-71).
        model = AppConfig.model_validate(json.loads((worker.directory / "config.json").read_text()))
        assert not model.control.enabled


def test_cleanup_failure_preserves_state_and_lease(
    worker: FakeWorker, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker.payload = {"image": "test:hub", "endpoint": "192.0.2.1"}
    worker.deploy()

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("simulated Docker failure")

    monkeypatch.setattr(worker, "compose", fail)
    with pytest.raises(ValueError):
        worker.cleanup()
    assert worker.directory.exists() and (worker.base / "lease.json").exists()


def test_foreign_lease_refused_before_any_action(worker: FakeWorker) -> None:
    (worker.base / "lease.json").write_text(json.dumps({"run_id": "b" * 24, "role": "hub"}))
    with pytest.raises(ValueError):
        worker.dispatch(io.BytesIO())
    assert worker.commands == []


def test_worker_never_uses_shell_true_or_global_prune() -> None:
    import ast

    import tests.e2e.worker as module

    text = Path(module.__file__).read_text()
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            assert not any(
                k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in node.keywords
            )
    assert '"prune"' not in text
    # Never the host's network; only the wg-easy source shares the node container's own (NL-05).
    assert re.findall(r'"network_mode": "([^"]*)"', text) == ["service:node"]
    assert text.count('"network_mode"') == 1
    assert '"/var/run/docker.sock"' not in text


def test_all_embedded_programs_compile() -> None:
    import tests.e2e.worker as module

    for name in (
        "PROXY",
        "PROBE",
        "ENROLL",
        "EXT_USER",
        "WATCHDOG",
        "IDENTITY",
        "REPAIR_ROUTE",
        "INJECT_BUNDLE",
        "LISTEN",
        "CONNECT",
        "ACCESS_CLIENT",
        "ACCESS_CLIENT_STOP",
        "RESOLVE",
        "UPGRADE_SERVER",
        "FORWARD_OBSERVER",
        "UPLINK_CAPTURE",
        "NL05_SNAPSHOT",
    ):
        compile(getattr(module, name), f"<e2e-{name}>", "exec")


def test_unknown_remote_action_has_no_generic_exec(worker: FakeWorker) -> None:
    worker.request["action"] = "execute"
    worker.payload = {"argv": ["unsafe", "arbitrary-command"]}
    with pytest.raises(ValueError):
        worker.dispatch(io.BytesIO())
    assert worker.commands == []


def test_recovery_cannot_steal_foreign_lease(worker: FakeWorker) -> None:
    worker.request["action"] = "recover"
    foreign = json.dumps({"role": "hub", "run_id": "b" * 24})
    (worker.base / "lease.json").write_text(foreign)
    with pytest.raises(ValueError):
        worker.dispatch(io.BytesIO())
    assert (worker.base / "lease.json").read_text() == foreign and worker.commands == []


def test_artifact_disk_failure_still_cleans_all_roles(
    environment: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = Fleet(Inventory.from_env(environment))
    instance.artifacts = tmp_path / "artifacts"
    instance.active.add("enroll")
    commands = []
    monkeypatch.setattr(
        instance, "call", lambda role, action, case: commands.append((role, action))
    )
    monkeypatch.setattr(instance, "summary", lambda: None)
    original = Path.mkdir

    def fail(path: Path, *args: Any, **kwargs: Any) -> None:
        if path == instance.artifacts / "enroll":
            raise OSError("disk full")
        original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail)
    with pytest.raises(E2EError):
        instance.finish("enroll", outcome="failed")
    assert set(commands) == {(role, "cleanup") for role in ("hub", "agent-a", "agent-b", "ext")}
    assert "enroll" not in instance.active


def test_partial_deploy_failure_cleanup_does_not_depend_on_setup_success(
    environment: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = Fleet(Inventory.from_env(environment))
    instance.artifacts = tmp_path / "artifacts"
    instance.image_ids = {"hub": "sha256:" + "1" * 64, "agent": "sha256:" + "2" * 64}
    commands = []

    def call(role: str, action: str, case: str, **payload: Any) -> Any:
        commands.append((role, action))
        if action == "deploy":
            if role == "hub":
                raise E2EError("simulated partial setup")
            return {"image_id": instance.image_ids["hub"]}
        if action == "diagnostics":
            raise E2EError("not enrolled")
        return {"clean": True}

    monkeypatch.setattr(instance, "call", call)
    with pytest.raises(E2EError):
        try:
            instance.setup("enroll")
        finally:
            instance.finish("enroll", outcome="failed")
    assert {(role, action) for role, action in commands if action == "cleanup"} == {
        (role, "cleanup") for role in ("hub", "agent-a", "agent-b", "ext")
    }


def test_workflow_embedded_python_is_valid() -> None:
    import ast

    root = Path(__file__).resolve().parents[1]
    job = yaml.safe_load((root / ".github/workflows/e2e.yml").read_text())["jobs"]["e2e"]
    count = 0
    for step in job["steps"]:
        script = step.get("run", "")
        if "<<'PY'\n" in script:
            code = script.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
            ast.parse(code)
            count += 1
    assert count == 2


def test_public_state_probe_contains_no_private_data(
    worker: FakeWorker, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker.role = "agent-a"

    def execute(argv: list[str]) -> tuple[int, bytes]:
        compile(argv[2], "<public-state-probe>", "exec")
        assert "key.pem" not in argv[2] and "read_bytes" not in argv[2]
        return 0, b'{"current":1,"high_water":1,"last_apply":null}'

    monkeypatch.setattr(worker, "execute", execute)
    assert worker.state()["current"] == 1


@pytest.mark.parametrize("role", ["hub", "agent-a", "agent-b", "ext"])
def test_upgrade_deployment_has_an_independent_client_and_only_owned_ports(
    worker: FakeWorker,
    role: str,
) -> None:
    worker.role, worker.case = role, "upgrade"
    worker.directory = worker.root / "upgrade"
    worker.payload = {"image": "baseline:previous", "endpoint": "192.0.2.1"}
    worker.deploy()
    services = json.loads((worker.directory / "compose.json").read_text())["services"]
    node = services["node"]
    assert "network_mode" not in node and "privileged" not in node
    if role == "agent-a":
        assert node["ports"] == ["8443:8443/tcp"]
    elif role == "ext":
        assert "9100:9100/tcp" in node["ports"]
    elif role == "agent-b":
        assert services["client"]["entrypoint"] == ["sleep", "infinity"]
        assert "network_mode" not in services["client"]
        assert "volumes" not in services["client"]
    assert "awg" not in services and "awg-client" not in services


def test_upgrade_restart_targets_only_node_and_preserves_client_image(
    worker: FakeWorker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker.role, worker.case = "agent-b", "upgrade"
    worker.directory.mkdir()
    client = {"image": "baseline:previous", "entrypoint": ["sleep", "infinity"]}
    compose_path = worker.directory / "compose.json"
    compose_path.write_text(
        json.dumps(
            {
                "services": {
                    "node": {"image": "baseline:previous"},
                    "client": client,
                }
            }
        )
    )
    worker.payload = {"image": "current:agent"}
    monkeypatch.setattr(worker, "owned_case", lambda: {"image": "baseline:previous"})
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(worker, "compose", lambda *args: calls.append(args))
    worker.restart()
    services = json.loads(compose_path.read_text())["services"]
    assert services["client"] == client
    assert services["node"]["image"] == "current:agent"
    assert calls == [("up", "-d", "--force-recreate", "node")]
    assert worker.commands == []


@pytest.mark.parametrize(
    "action",
    [
        "upgrade_traffic_start",
        "upgrade_traffic_status",
        "uplink_capture",
        "nl05_snapshot",
        "nl05_ext_kill",
        "nl05_tunnel_down",
    ],
)
def test_new_runtime_actions_reject_unrelated_cases_before_any_command(
    worker: FakeWorker,
    action: str,
) -> None:
    with pytest.raises(ValueError):
        getattr(worker, action)()
    assert worker.commands == []


def test_upgrade_policy_uses_only_the_shared_local_client_subset(worker: FakeWorker) -> None:
    worker.case = "upgrade"
    worker.directory.mkdir()
    captured: list[Any] = []

    def cli(*args: str, **kwargs: Any) -> dict[str, int]:
        captured.append(json.loads(Path(args[-1]).read_text()))
        return {"desired_version": 2}

    worker.cli = cli  # type: ignore[method-assign]
    worker.access_policy()
    assert captured == [
        {
            "egress": [
                {"id": "clients-out", "from": ["clients"], "to": "any", "via": "local"},
            ]
        }
    ]
    assert not (worker.directory / "access-policy.json").exists()


@pytest.mark.parametrize("full", [False, True])
def test_access_client_hook_restores_routes_on_reconnect_without_relogin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    full: bool,
) -> None:
    import subprocess

    from tests.e2e.worker import ACCESS_CLIENT

    directory = tmp_path / "access"
    dials: list[list[str]] = []
    watchers: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        if argv[0] == "openconnect":
            dials.append(argv)
            return SimpleNamespace(returncode=0)
        if argv == ["ip", "-4", "-j", "route", "show", "default"]:
            return SimpleNamespace(returncode=0, stdout=b'[{"gateway":"192.0.2.254"}]')
        assert argv == ["ip", "-4", "-j", "addr", "show", "dev", "kn-vpnc0"]
        return SimpleNamespace(returncode=0, stdout=b'[{"addr_info":[{"local":"10.9.0.2"}]}]')

    options = {
        "host": "192.0.2.2",
        "port": 8443,
        "pin": "fake-pin",
        "user": "alice",
        "password": "local-test-only",
        "routes": ["192.0.2.4/32"],
        "full": full,
    }
    # Execute the actual generator, but never start openconnect or inspect real routes.
    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdin", io.StringIO(json.dumps(options)))
        patch.setattr(subprocess, "run", run)
        patch.setattr(subprocess, "Popen", lambda argv, **_kw: watchers.append(argv))
        code = ACCESS_CLIENT.replace("/tmp/kn-access", str(directory))
        exec(compile(code, "<access-client>", "exec"), {})
    assert len(dials) == 1
    assert "--script=" + str(directory / "vpnc") in dials[0]
    # The same dial is repeated by the redial watcher; the password never reaches argv.
    assert len(watchers) == 1 and watchers[0][-len(dials[0]) :] == dials[0]
    assert "local-test-only" not in " ".join(watchers[0] + dials[0])
    assert (directory / "pw").read_text() == "local-test-only\n"
    assert (directory / "pw").stat().st_mode & 0o777 == 0o600

    state_path = tmp_path / "ip-state.json"
    state_path.write_text(json.dumps({"address": None, "routes": {}, "errors": 0}))
    ip = tmp_path / "ip"
    ip.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """import json,os,sys
from pathlib import Path
path=Path(os.environ["FAKE_IP_STATE"])
state=json.loads(path.read_text());args=sys.argv[1:];code=0
if args[:2]==["link","set"]:
 pass
elif args[0] in {"addr","route"} and args[1] in {"add","replace"}:
 target=args[2]
 exists=state["address"] is not None if args[0]=="addr" else target in state["routes"]
 if args[1]=="add" and exists:
  state["errors"]+=1;code=2
 elif args[0]=="addr":
  state["address"]=target
 else:
  state["routes"][target]=args[3:]
else:
 raise SystemExit("unexpected fake ip command")
path.write_text(json.dumps(state))
sys.exit(code)
"""
    )
    ip.chmod(0o700)
    env = {
        **os.environ,
        "PATH": str(tmp_path),
        "FAKE_IP_STATE": str(state_path),
        "TUNDEV": "kn-vpnc0",
        "INTERNAL_IP4_ADDRESS": "10.9.0.2",
    }

    def hook(reason: str) -> dict[str, Any]:
        subprocess.run(
            ["/bin/sh", str(directory / "vpnc")],
            env={**env, "reason": reason},
            check=True,
            capture_output=True,
            timeout=5,
        )
        return cast(dict[str, Any], json.loads(state_path.read_text()))

    connected = hook("connect")
    expected_routes = {"192.0.2.4/32": ["dev", "kn-vpnc0"]}
    if full:
        expected_routes.update(
            {
                "192.0.2.2/32": ["via", "192.0.2.254"],
                "default": ["dev", "kn-vpnc0"],
            }
        )
    assert connected["routes"] == expected_routes
    # A link flap may remove routes while leaving the assigned address. The hook
    # must restore those routes, not rely on a new login or a fresh tun device.
    connected["routes"] = {}
    state_path.write_text(json.dumps(connected))
    assert hook("attempt-reconnect") == connected
    for _ in range(2):
        recovered = hook("reconnect")
        assert recovered["routes"] == expected_routes
        assert recovered["address"] == "10.9.0.2/32"
        assert recovered["errors"] == 0
    assert len(dials) == 1


@pytest.mark.parametrize(
    "samples,device,successes,wrong_peer",
    [
        (["192.0.2.2", None, "192.0.2.2"], "kn-vpnc0", 2, 0),
        (["192.0.2.3"], "kn-vpnc0", 0, 1),
        (["192.0.2.2"], "eth0", 0, 0),
        (["192.0.2.2", *([None] * 31), "192.0.2.2"], "kn-vpnc0", 2, 0),
    ],
)
def test_forwarding_observer_counts_real_recovery_and_rejects_direct_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    samples: list[str | None],
    device: str,
    successes: int,
    wrong_peer: int,
) -> None:
    import socket
    from contextlib import nullcontext

    from tests.e2e.worker import FORWARD_OBSERVER

    clock = [0.0]
    pending = list(samples)
    index = [0]

    def connect(*args: Any, **kwargs: Any) -> Any:
        peer = pending[index[0]]
        if peer is None:
            clock[0] += 1
            raise TimeoutError
        return nullcontext(SimpleNamespace(recv=lambda size: peer.encode()))

    def sleep(seconds: float) -> None:
        index[0] += 1
        clock[0] += seconds
        if index[0] == len(pending):
            clock[0] = 601

    monkeypatch.setattr(sys, "argv", ["probe", "192.0.2.4", "192.0.2.2"])
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    monkeypatch.setattr("time.sleep", sleep)
    monkeypatch.setattr("subprocess.check_output", lambda *a, **kw: json.dumps([{"dev": device}]))
    monkeypatch.setattr(socket, "create_connection", connect)
    path = tmp_path / "stats.json"
    code = FORWARD_OBSERVER.replace("/tmp/kn-upgrade-traffic.json", str(path))
    exec(compile(code, "<forward-observer>", "exec"), {})
    stats = json.loads(path.read_text())
    assert stats["successes"] == successes and stats["wrong_peer"] == wrong_peer
    assert stats["failures"] == len(samples) - successes
    if len(samples) > 30:
        assert stats["healthy"] and stats["max_gap_seconds"] > 30
    elif successes == 2:
        assert stats["healthy"] and stats["max_gap_seconds"] == 1.5


@pytest.mark.parametrize("client_gap,wrong_peer", [(0.5, 0), (31.0, 0), (0.5, 1)])
def test_upgrade_preserves_client_gap_and_checks_post_upgrade_success(
    environment: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    client_gap: float,
    wrong_peer: int,
) -> None:
    fleet = Fleet(Inventory.from_env(environment))
    fleet.image_ids = {"hub": "hub-id", "agent": "agent-id"}
    cluster = Cluster(fleet, "upgrade")
    actions: list[tuple[str, str]] = []
    successes = [0]

    def call(role: str, action: str, **payload: Any) -> Any:
        actions.append((role, action))
        if action == "upgrade_traffic_status":
            successes[0] += 2
            return {
                "healthy": True,
                "successes": successes[0],
                "wrong_peer": wrong_peer,
                "max_gap_seconds": client_gap,
            }
        if action == "restart":
            return {"image_id": fleet.image_ids["hub" if role == "hub" else "agent"]}
        return {"started": True}

    monkeypatch.setattr(cluster, "call", call)
    monkeypatch.setattr(cluster, "ping", lambda role: 204)
    if wrong_peer:
        with pytest.raises(E2EError, match="bypassed"):
            cluster.upgrade()
    else:
        assert cluster.upgrade() >= client_gap
        assert fleet.results["upgrade.max_client_gap_seconds"] == client_gap
    assert actions.index(("agent-b", "upgrade_traffic_start")) < actions.index(("hub", "restart"))
    assert actions[-1] == ("agent-b", "upgrade_traffic_status")
    assert successes[0] >= 6  # baseline, completion snapshot, fresh recovery


@pytest.mark.parametrize("healthy", [False, True])
def test_upgrade_rejects_stale_client_success_without_operator_relogin(
    environment: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    healthy: bool,
) -> None:
    fleet = Fleet(Inventory.from_env(environment))
    fleet.image_ids = {"hub": "hub-id", "agent": "agent-id"}
    cluster = Cluster(fleet, "upgrade")
    actions: list[tuple[str, str]] = []
    replaced: list[str] = []

    def call(role: str, action: str, **payload: Any) -> Any:
        actions.append((role, action))
        if action == "upgrade_traffic_status":
            return {"healthy": healthy if replaced else True, "successes": 2}
        if action == "restart":
            replaced.append(role)
            return {"image_id": fleet.image_ids["hub" if role == "hub" else "agent"]}
        return {"started": True}

    def bounded_wait(predicate: Any, seconds: float, message: str) -> None:
        if message == "upgrade access-client forwarding did not recover automatically":
            assert seconds == 40
            assert replaced == ["hub", "agent-a", "agent-b"]
            assert not predicate()
            assert not predicate()
            raise E2EError(message)
        wait_for(predicate, seconds, message)

    monkeypatch.setattr(cluster, "call", call)
    monkeypatch.setattr(cluster, "ping", lambda role: 204)
    monkeypatch.setattr("tests.e2e.fleet.wait_for", bounded_wait)
    with pytest.raises(E2EError, match="forwarding did not recover automatically"):
        cluster.upgrade()
    assert all(action != "access_client" for _, action in actions)
    assert actions[-3:] == [("agent-b", "upgrade_traffic_status")] * 3


def test_nl05_capture_filter_counts_only_cleartext_target_packets_on_the_uplink() -> None:
    import ast
    import socket

    from tests.e2e.worker import UPLINK_CAPTURE

    tree = ast.parse(UPLINK_CAPTURE)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "matches")
    scope: dict[str, Any] = {"socket": socket}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<capture-filter>", "exec"), scope)
    target = socket.inet_aton("192.0.2.3")
    frame = bytearray(54)
    frame[12:14] = b"\x08\x00"
    frame[14], frame[23] = 0x45, 6
    frame[30:34], frame[36:38] = target, (9100).to_bytes(2, "big")
    outgoing = ("eth0", 0, socket.PACKET_OUTGOING)
    matches = scope["matches"]
    assert matches(frame, outgoing, target)
    assert not matches(frame, ("eth0", 0, socket.PACKET_HOST), target)
    assert not matches(frame, outgoing, socket.inet_aton("192.0.2.4"))
    assert not matches(frame[:37], outgoing, target)
    frame[36:38] = (443).to_bytes(2, "big")
    assert not matches(frame, outgoing, target), "encrypted upstream carrier must not count"


@pytest.mark.parametrize("code", [0, 1, 9, 10, 13])
def test_nl05_trace_correlates_icmp_unreachable_and_incoming_awg_syn(code: int) -> None:
    import ast
    import socket

    from tests.e2e.worker import UPLINK_CAPTURE

    tree = ast.parse(UPLINK_CAPTURE)
    function = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "trace_packet"
    )
    scope: dict[str, Any] = {"socket": socket}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<icmp-filter>", "exec"), scope)
    trace = scope["trace_packet"]
    target = socket.inet_aton("192.0.2.3")
    original = bytearray(40)
    original[0], original[9] = 0x45, 6
    original[16:20], original[22:24] = target, (9100).to_bytes(2, "big")
    assert trace(original, ("wg0", 0, socket.PACKET_HOST), target) == "wg0:in:tcp9100"
    packet = bytearray(28) + original
    packet[0], packet[9], packet[20], packet[21] = 0x45, 1, 3, code
    assert trace(packet, ("wg0", 0, socket.PACKET_OUTGOING), target) == f"wg0:out:icmp_3_{code}"
    assert trace(packet, ("wg0", 0, socket.PACKET_HOST), target) == f"wg0:in:icmp_3_{code}"
    assert trace(packet[:24], ("wg0", 0, socket.PACKET_HOST), target) is None
    assert trace(packet, ("wg0", 0, socket.PACKET_HOST), socket.inet_aton("192.0.2.4")) is None
    packet[50:52] = (443).to_bytes(2, "big")
    assert trace(packet, ("wg0", 0, socket.PACKET_HOST), target) is None


def test_netlab_coverage_references_resolve_to_real_tests() -> None:
    from tests.e2e.test_routed_interlink import NETLAB_COVERAGE

    root = Path(__file__).resolve().parents[1]
    for reference in NETLAB_COVERAGE.values():
        path, names = reference.split("::")
        source = (root / path).read_text()
        for name in names.split("; "):
            assert f"def {name}(" in source


@pytest.mark.parametrize("unsafe", ["showlocals", "xdist", None])
def test_vm_opt_in_cannot_be_bypassed_by_root_or_secret_leaking_pytest_options(
    monkeypatch: pytest.MonkeyPatch,
    unsafe: str | None,
) -> None:
    from tests.e2e.conftest import pytest_collection_modifyitems

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    item = Mock()
    item.get_closest_marker.return_value = object()
    config = Mock()
    config.getoption.return_value = False
    config.option.showlocals = False
    pytest_collection_modifyitems(config, [item])
    assert item.add_marker.call_args.args[0].name == "skip"
    config.getoption.return_value = True
    config.option.showlocals = unsafe == "showlocals"
    if unsafe == "xdist":
        monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
    if unsafe:
        with pytest.raises(pytest.UsageError):
            pytest_collection_modifyitems(config, [item])
    else:
        item.add_marker.reset_mock()
        pytest_collection_modifyitems(config, [item])
        item.add_marker.assert_not_called()


def test_fail_closed_requires_a_completed_listener_and_actual_traffic_attempts(
    environment: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cluster = Cluster(Fleet(Inventory.from_env(environment)), "routed")
    thread = Mock()
    thread.is_alive.return_value = False
    monkeypatch.setattr("tests.e2e.fleet.threading.Thread", lambda **kw: thread)
    with pytest.raises(E2EError, match="observation window"):
        cluster.tcp_unreachable("agent-b", "agent-b", "192.0.2.3", awg=True)


def test_example_forwarding_expectations_cover_every_file_and_match_its_policy() -> None:
    import ipaddress

    from tests.netlab.example_driver import load
    from tests.netlab.test_examples_forwarding import PROBES
    from tests.netlab.test_examples_kernel import EXAMPLES

    from kornode.config.models import profile_slug
    from kornode.net.compile import NodeFacts, TunnelFact, compile_policy
    from kornode.net.explain import explain

    assert {path.name for path in EXAMPLES} == set(PROBES)
    for path in EXAMPLES:
        config = load(path)
        policy = config.egress_policy()
        pool = ipaddress.IPv4Network(config.server.ipv4_network)
        for up in (True, False):
            facts = NodeFacts(
                node_id=1,
                client_pool=pool,
                uplink="uplink0",
                upstreams=tuple(profile_slug(p.name) for p in config.upstream.profiles),
                tunnels={
                    f"upstream:{profile_slug(p.name)}": TunnelFact(
                        config.upstream.profile_interface(p),
                        up,
                    )
                    for p in config.upstream.profiles
                },
                resolved={name: frozenset({"198.51.100.9"}) for name in config.sets},
            )
            compiled = compile_policy(policy, facts)
            for source, destination, profile in PROBES[path.name]:
                decision = explain(
                    compiled,
                    policy,
                    facts,
                    "host" if source == "host" else str(pool[2]),
                    destination,
                )
                if profile:
                    assert decision.matched_rule is not None
                    assert decision.matched_rule["via"] == f"upstream:{profile_slug(profile)}"
                    assert ("unreachable" in (decision.route or "")) is not up
                else:
                    assert "main table" in (decision.route or "")


def test_awg_peer_accepts_gateway_icmp_without_installing_a_full_tunnel(
    worker: FakeWorker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.e2e.worker import AWG_SOURCE_CIDR

    worker.role, worker.case = "agent-b", "routed"
    worker.payload = {
        "endpoint_host": "192.0.2.2",
        "routes": ["192.0.2.3/32"],
        "config": (
            "[Interface]\nAddress = 10.8.2.2/24\nPrivateKey = fake-local-test-only\n"
            "[Peer]\nPublicKey = fake-local-test-only\nAllowedIPs = 0.0.0.0/0\n"
        ),
    }
    monkeypatch.setattr(worker, "container", lambda service="node": "owned-awg-client")
    worker.awg_client()
    written = next(kw["data"].decode() for argv, kw in worker.commands if "data" in kw)
    assert f"AllowedIPs = 192.0.2.3/32, {AWG_SOURCE_CIDR}" in written
    assert "0.0.0.0/0" not in written
    assert "Endpoint = 192.0.2.2:51820" in written


def test_nl05_abrupt_fault_disables_restart_and_targets_only_the_owned_container(
    worker: FakeWorker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker.case, worker.role = "routed", "ext"
    identifier = "a" * 64
    owned = Mock(return_value=identifier)
    monkeypatch.setattr(worker, "container", owned)
    assert worker.nl05_ext_kill() == {"stopped": True}
    owned.assert_called_once_with()
    assert [argv for argv, kwargs in worker.commands] == [
        ["docker", "update", "--restart=no", identifier],
        ["docker", "kill", "--signal", "KILL", identifier],
    ]


@pytest.fixture
def upstream_health_manager(tmp_path: Path) -> Iterator[tuple[TunnelManager, TunnelFake, Mock]]:
    fake = TunnelFake(tmp_path)
    probe = Mock(return_value=True)

    def converge() -> None:
        # Closing the only userspace TUN owner removes its interface in Linux.
        if not any(process.poll() is None for process in fake.procs):
            fake.links.discard("oc-office")
        fake.converge()

    manager = TunnelManager(
        tmp_path,
        converge=converge,
        link_up=fake.link_up,
        runner=fake,
        resolve=lambda server: ["192.0.2.4"],
        clock=fake.clock,
        sleep=fake.sleep,
        jitter=lambda: 1.0,
        probe=probe,
    )
    spec = TunnelSpec(
        "upstream:office",
        (
            DialSpec(
                server="192.0.2.4",
                port=443,
                interface="oc-office",
                pid_file=tmp_path / "run" / "oc-office.pid",
            ),
        ),
        check_host="10.8.0.1",
    )
    manager.set_desired({spec.exit_name: spec})
    try:
        yield manager, fake, probe
    finally:
        for process in fake.procs:
            process.kill()
            process.wait()


def test_retrying_upstream_pid_is_stopped_and_guard_converges_before_redial(
    upstream_health_manager: tuple[TunnelManager, TunnelFake, Mock],
) -> None:
    manager, fake, probe = upstream_health_manager
    manager.tick()
    assert manager.is_up("upstream:office")
    old_pid = fake.procs[-1].pid
    probe.return_value = False
    for now in (5.0, 10.0):
        fake.now = now
        manager.tick()
        assert manager.is_up("upstream:office")
    fake.calls.clear()
    fake.now = 15.0
    manager.tick()
    assert not manager._alive(old_pid)
    assert not manager.is_up("upstream:office")
    assert manager.errors["upstream:office"] == "upstream health check failed"
    assert fake.calls == ["converge"], "guard must converge with no immediate blocking redial"
    probe.assert_called_with("oc-office", "10.8.0.1")
    fake.codes = [1]
    fake.now += 1
    manager.tick()
    assert fake.calls[-2:] == ["converge", "dial"]
    assert not manager.is_up("upstream:office")
    fake.now += 2
    probe.return_value = True
    manager.tick()
    assert manager.is_up("upstream:office") and fake.procs[-1].pid != old_pid
    assert "upstream:office" not in manager.errors


def test_upstream_health_is_rate_limited_and_success_resets_consecutive_failures(
    upstream_health_manager: tuple[TunnelManager, TunnelFake, Mock],
) -> None:
    manager, fake, probe = upstream_health_manager
    manager.tick()
    probe.assert_not_called()
    probe.return_value = False
    for now in (5.0, 10.0):
        fake.now = now
        manager.tick()
        manager.tick()  # one probe per interval, not per loop iteration
    assert probe.call_count == 2
    fake.now = 15
    probe.return_value = True
    manager.tick()
    probe.return_value = False
    for now in (20.0, 25.0):
        fake.now = now
        manager.tick()
    assert manager.is_up("upstream:office"), "isolated failures must not accumulate across recovery"


@pytest.mark.parametrize("name,check_host", [("interlink", "10.8.0.1"), ("upstream:office", None)])
def test_steady_upstream_probe_does_not_change_interlink_or_unconfigured_health(
    upstream_health_manager: tuple[TunnelManager, TunnelFake, Mock],
    name: str,
    check_host: str | None,
) -> None:
    from dataclasses import replace

    manager, fake, probe = upstream_health_manager
    spec = next(iter(manager.specs().values()))
    manager.set_desired({name: replace(spec, exit_name=name, check_host=check_host)})
    manager.tick()
    fake.now = 100
    manager.tick()
    probe.assert_not_called()
    assert manager.is_up(name)


def test_access_client_redials_after_the_server_ends_the_session_until_stopped(
    tmp_path: Path,
) -> None:
    """A graceful server restart makes openconnect exit ("Session terminated by server").
    The harness client stands in for a VPN application: it dials again, and stops on request."""
    import re
    import subprocess
    import time

    from tests.e2e.worker import ACCESS_CLIENT

    match = re.search(r"\nwatch=(.*?)\nsubprocess\.Popen", ACCESS_CLIENT, re.S)
    assert match
    namespace: dict[str, Any] = {}
    exec("watch=" + match.group(1), namespace)  # the literal from the generator
    directory = tmp_path / "access"
    directory.mkdir()
    (directory / "pw").write_text("secret\n")
    fake = tmp_path / "fake-openconnect"
    fake.write_text(
        "#!/bin/sh\n"
        f'echo "$$ $(cat)" >> "{tmp_path}/dials"\n'  # one line per dial, with the stdin
        f'echo $$ > "{directory}/pid"\n'
        "exit 0\n"  # the "client" ends at once: the session was terminated by the server
    )
    fake.chmod(0o700)
    (directory / "pid").write_text("999999")  # no such process
    proc = subprocess.Popen(
        ["sh", "-c", namespace["watch"], "kn-redial", str(directory), str(fake)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        dials = tmp_path / "dials"
        while time.monotonic() < deadline and (
            not dials.exists() or len(dials.read_text().splitlines()) < 2
        ):
            time.sleep(0.2)
        assert dials.exists() and len(dials.read_text().splitlines()) >= 2  # redialed
        assert all(line.endswith(" secret") for line in dials.read_text().splitlines())
        (directory / "stop").touch()
        assert proc.wait(timeout=10) == 0
    finally:
        proc.kill()
