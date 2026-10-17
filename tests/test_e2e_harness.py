"""Local harness safety tests. All VM/Docker calls here are fakes, not E2E evidence."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml
from tests.e2e.__main__ import main
from tests.e2e.fleet import Fleet, wait_for
from tests.e2e.inventory import ACK, E2EError, Inventory
from tests.e2e.transport import SSH
from tests.e2e.worker import Worker

from kornode.config.models import AppConfig

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
    worker.marker.read_text.return_value = "{}"
    with pytest.raises(ValueError):
        worker.dispatch(io.BytesIO())
    assert worker.commands == []


def test_marker_owner_and_permissions_required(worker: FakeWorker) -> None:
    worker.marker.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o666, st_uid=0)
    with pytest.raises(ValueError):
        worker.guard()
    worker.marker.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000)
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
    assert model.fabric.enabled and model.control.enabled and not model.web.enabled
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
    assert "E2E-07" in result["blocked_contracts"]


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
        assert not AppConfig.model_validate(
            json.loads((worker.directory / "config.json").read_text())
        ).fabric.enabled


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
    assert '"network_mode"' not in text
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
