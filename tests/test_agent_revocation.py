from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from tests.test_enrollment import Env

from kornode.config.models import AppConfig
from kornode.services.agents import AgentService
from kornode.services.command import CommandError, CommandResult, CommandRunner
from kornode.services.enrollment import EnrollmentError
from kornode.services.sessions import SessionService


@pytest.mark.parametrize(
    ("code", "output", "accepted"),
    [
        (2, "[]", True),
        (0, "[]", True),
        (1, "[]", False),
        (2, "", False),
        (0, "not json", False),
        (0, "{}", False),
        (0, '[{"Username":"agent-3"}]', False),
    ],
)
def test_disconnect_failure_requires_verified_absence(
    code: int, output: str, accepted: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def run(_self: CommandRunner, argv: list[str], **kwargs: Any) -> CommandResult:
        calls.append(argv)
        if "disconnect" in argv:
            return CommandResult(tuple(argv), 1, "", "")
        return CommandResult(tuple(argv), code, output, "")

    monkeypatch.setattr(CommandRunner, "run", run)
    service = SessionService(AppConfig())
    if accepted:
        service.disconnect_if_present("agent-3")
    else:
        with pytest.raises(CommandError):
            service.disconnect_if_present("agent-3")
    assert calls[0][-3:] == ["disconnect", "user", "agent-3"]
    assert "--json" in calls[1] and calls[1][-3:] == ["show", "user", "agent-3"]


@pytest.mark.skipif(shutil.which("certtool") is None, reason="certtool not installed")
def test_failed_disconnect_leaves_registry_revoked_and_guard_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path)
    try:
        env.registry.set_state(3, "active")
        env.service.groups.sync()
        guard = env.service.groups.user_dir() / "agent-3"
        assert guard.exists()
        original = env.runner.run

        def run(argv: list[str], **kwargs: Any) -> CommandResult:
            if argv[0] == "occtl":
                return CommandResult(tuple(argv), 1, "", "unavailable")
            return original(argv, **kwargs)

        monkeypatch.setattr(env.runner, "run", run)
        with pytest.raises(EnrollmentError, match="disconnect"):
            env.service.revoke_node(3)
        assert env.registry.get_node(3).state == "revoked"
        assert not guard.exists()
        assert env.reloads == 1
    finally:
        env.registry.conn.close()


def test_management_enrollment_wires_occtl_reload(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def run(_self: CommandRunner, argv: list[str], **kwargs: Any) -> CommandResult:
        calls.append(argv)
        return CommandResult(tuple(argv), 0, "", "")

    monkeypatch.setattr(CommandRunner, "run", run)
    service = AgentService(AppConfig())
    service.enrollment._reload_ocserv()
    assert len(calls) == 1 and calls[0][0] == "occtl" and calls[0][-1] == "reload"
