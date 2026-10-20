"""P4-04 agent side: ocserv of role `access` from the bundle (D-67)."""

from __future__ import annotations

import shutil
import stat
from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from tests.test_agent_access import World
from tests.test_agent_inputs import CONFIG, FakeCarriers, FakeProbes

from kornode.net.compile import compile_policy
from kornode_agent.access import AccessServer, render
from kornode_agent.inputs import AgentNetInputs

pytestmark = pytest.mark.skipif(shutil.which("certtool") is None, reason="needs certtool")


class Control:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.ok = True

    def __call__(self, action: str) -> bool:
        self.calls.append(action)
        return self.ok


class Occtl:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: Any) -> bool:
        self.calls.append(list(args))
        return True


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    # A hash per password, as ocpasswd makes: a password change must change the entry.
    result = World(
        tmp_path / "hub", password_hasher=lambda pw: "$6$s$" + sha256(pw.encode()).hexdigest()
    )
    result.service.set_access("node3", {"hostname": "vpn.branch.example", "port": 8443})
    result.service.set_user("node3", "alice", {"password": "alice-password", "groups": ["staff"]})
    result.service.set_user("node3", "bob", {"password": "bob-password1"})
    yield result
    result.env.registry.conn.close()


def server(tmp_path: Path) -> tuple[AccessServer, Control, Occtl]:
    control, occtl = Control(), Occtl()
    return AccessServer(tmp_path / "agent/run/access", control=control, occtl=occtl), control, occtl


def test_render_is_derived_from_the_bundle(world: World, tmp_path: Path) -> None:
    validated = world.bundle()
    files = render(validated.bundle, validated.secrets, tmp_path / "run")
    assert files is not None
    conf = files.content("ocserv.conf")
    assert conf is not None
    lines = conf.splitlines()
    assert "tcp-port = 8443" in lines and "udp-port = 8443" not in lines
    assert "ipv4-network = 10.100.3.0/24" in lines
    assert "dns = 10.100.3.1" in lines
    assert f'auth = "plain[passwd={tmp_path / "run" / "ocpasswd"}]"' in lines
    passwd = files.content("ocpasswd")
    assert passwd is not None
    entries = {line.split(":")[0]: line.split(":") for line in passwd.splitlines()}
    assert entries["alice"][1] == "staff" and entries["bob"][1] == "*"
    assert entries["alice"][2].startswith("$6$")
    assert files.users == {"alice", "bob"}
    key = files.content("server.key")
    assert key is not None and key.startswith("-----BEGIN PRIVATE KEY-----")


def test_disabled_users_are_not_in_the_password_file(world: World, tmp_path: Path) -> None:
    world.service.set_user("node3", "bob", {"enabled": False})
    validated = world.bundle()
    files = render(validated.bundle, validated.secrets, tmp_path)
    assert files is not None and files.users == {"alice"}
    assert "bob" not in (files.content("ocpasswd") or "")


def test_no_server_without_role_listener_or_key(world: World, tmp_path: Path) -> None:
    validated = world.bundle()
    assert render(validated.bundle, {}, tmp_path) is None  # key missing
    bare = validated.bundle.model_copy(update={"access": None})
    assert render(bare, validated.secrets, tmp_path) is None


def test_files_are_written_private_and_ocserv_restarts_once(world: World, tmp_path: Path) -> None:
    validated = world.bundle()
    access, control, _ = server(tmp_path)
    assert access.apply(validated.bundle, validated.secrets) is True
    assert access.apply(validated.bundle, validated.secrets) is True
    assert control.calls == ["restart"]
    run = tmp_path / "agent/run/access"
    for name in ("server.key", "ocpasswd"):
        assert stat.S_IMODE((run / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(run.stat().st_mode) == 0o755


def test_user_changes_rewrite_ocpasswd_and_disconnect_without_a_restart(
    world: World, tmp_path: Path
) -> None:
    first = world.bundle()
    access, control, occtl = server(tmp_path)
    access.apply(first.bundle, first.secrets)
    world.service.set_user("node3", "bob", None)
    world.service.set_user("node3", "carol", {"password": "carol-password"})
    second = world.bundle()
    assert access.apply(second.bundle, second.secrets) is True
    assert control.calls == ["restart"]
    assert occtl.calls == [["disconnect", "user", "bob"]]
    passwd = (tmp_path / "agent/run/access/ocpasswd").read_text()
    assert "carol:" in passwd and "bob:" not in passwd


def test_listener_change_restarts_ocserv(world: World, tmp_path: Path) -> None:
    first = world.bundle()
    access, control, _ = server(tmp_path)
    access.apply(first.bundle, first.secrets)
    world.service.set_access("node3", {"hostname": "vpn.branch.example", "port": 9443})
    second = world.bundle()
    access.apply(second.bundle, second.secrets)
    assert control.calls == ["restart", "restart"]


def test_removing_the_listener_stops_ocserv_and_removes_secrets(
    world: World, tmp_path: Path
) -> None:
    first = world.bundle()
    access, control, _ = server(tmp_path)
    access.apply(first.bundle, first.secrets)
    world.service.set_access("node3", None)
    gone = world.bundle()
    assert access.apply(gone.bundle, gone.secrets) is True
    assert control.calls == ["restart", "stop"]
    run = tmp_path / "agent/run/access"
    assert not any((run / name).exists() for name in ("server.key", "ocpasswd", "ocserv.conf"))


def test_failures_are_kept_and_retried(world: World, tmp_path: Path) -> None:
    validated = world.bundle()
    access, control, _ = server(tmp_path)
    control.ok = False
    assert access.apply(validated.bundle, validated.secrets) is False
    assert access.error == "supervisorctl restart ocserv failed"
    control.ok = True
    assert access.apply(validated.bundle, validated.secrets) is True
    assert access.error is None


def test_session_devices_get_the_strict_reverse_path_check(world: World) -> None:
    validated = world.bundle()
    inputs = AgentNetInputs(CONFIG, FakeProbes({"oc-hub0": True}), FakeCarriers())
    inputs.set_bundle(validated)
    facts = inputs.facts()
    assert facts.access_ifaces == ("vpns*",)
    script = compile_policy(inputs.policy(), facts).script
    assert 'iifname "vpns*" meta nfproto ipv4 fib saddr . iif oif missing drop' in script
    # Clients reach the node itself only for DNS and ping; the rest of the host is closed.
    assert 'iifname "vpns*" ip daddr 10.100.3.1 udp dport 53 accept' in script
    assert 'iifname "vpns*" ip daddr 10.100.3.1 tcp dport 53 accept' in script
    assert 'iifname "vpns*" icmp type echo-request accept' in script
    assert script.index("echo-request accept") < script.index(
        'iifname "vpns*" fib daddr type local drop'
    )
    # Without the listener there is no rule.
    inputs.set_bundle(None)
    assert "vpns*" not in compile_policy(inputs.policy(), inputs.facts()).script


def test_runtime_uses_the_run_directory_the_supervisor_program_reads(tmp_path: Path) -> None:
    """agent/supervisord.conf starts ocserv from RUN_DIR; the runtime must write there."""
    from unittest.mock import MagicMock

    from kornode_agent.access import RUN_DIR
    from kornode_agent.agent import AgentRuntime

    runtime = AgentRuntime(MagicMock(), MagicMock(), MagicMock(), MagicMock(), tmp_path)
    assert runtime.access.run == RUN_DIR
    conf = (Path(__file__).parent.parent / "agent/supervisord.conf").read_text()
    assert f"--config {RUN_DIR}/ocserv.conf" in conf


def test_password_or_group_change_ends_the_session_of_that_user(
    world: World, tmp_path: Path
) -> None:
    first = world.bundle()
    access, control, occtl = server(tmp_path)
    access.apply(first.bundle, first.secrets)
    world.service.set_user("node3", "alice", {"groups": ["admins"]})
    second = world.bundle()
    access.apply(second.bundle, second.secrets)
    assert occtl.calls == [["disconnect", "user", "alice"]]
    world.service.set_user("node3", "bob", {"password": "another-password"})
    third = world.bundle()
    access.apply(third.bundle, third.secrets)
    assert occtl.calls[-1] == ["disconnect", "user", "bob"] and control.calls == ["restart"]


def test_a_failed_disconnect_is_retried_not_forgotten(world: World, tmp_path: Path) -> None:
    first = world.bundle()
    access, _, occtl = server(tmp_path)
    access.apply(first.bundle, first.secrets)
    world.service.set_user("node3", "bob", None)
    second = world.bundle()
    ran = [False, True]
    access.occtl = lambda args: ran.pop(0)  # type: ignore[assignment]
    assert access.apply(second.bundle, second.secrets) is False
    assert access.error == "occtl could not disconnect a user"
    assert access.apply(second.bundle, second.secrets) is True and access.error is None
    assert occtl.calls == []


def test_a_bundle_whose_key_did_not_unseal_is_reported_and_serves_nothing(
    world: World, tmp_path: Path
) -> None:
    validated = world.bundle()
    access, control, _ = server(tmp_path)
    assert access.apply(validated.bundle, {}) is True
    assert access.error and "unusable" in access.error
    assert control.calls == []  # never started, so nothing to stop
    assert access.apply(validated.bundle, validated.secrets) is True
    assert access.error is None and control.calls == ["restart"]


def test_a_node_without_the_role_never_touches_ocserv(world: World, tmp_path: Path) -> None:
    access, control, _ = server(tmp_path)
    assert access.apply(None, {}) is True
    bare = world.bundle().bundle.model_copy(update={"access": None})
    assert access.apply(bare, {}) is True
    assert control.calls == [] and access.error is None


def test_a_leftover_configuration_is_stopped_when_the_role_is_gone(
    world: World, tmp_path: Path
) -> None:
    validated = world.bundle()
    first, control, _ = server(tmp_path)
    first.apply(validated.bundle, validated.secrets)
    # The agent process restarted (new instance, same container): the files remain.
    second = AccessServer(tmp_path / "agent/run/access", control=control, occtl=Occtl())
    bare = validated.bundle.model_copy(update={"access": None})
    assert second.apply(bare, {}) is True
    assert control.calls == ["restart", "stop"]
    assert not (tmp_path / "agent/run/access/server.key").exists()


def test_the_worker_survives_an_unexpected_exception(tmp_path: Path) -> None:
    import threading

    from kornode_agent.programs import Converger

    seen: list[str | None] = []
    done = threading.Event()

    class Flaky(Converger[str]):
        def apply_content(self, desired: str | None) -> bool:
            seen.append(desired)
            if len(seen) == 1:
                raise ValueError("bug")
            done.set()
            return True

    flaky = Flaky(retry_seconds=0.05)
    flaky.submit_content("x")
    assert done.wait(5)
    assert seen == ["x", "x"]
