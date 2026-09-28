from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from kornode.services.command import CommandError, CommandRunner


def test_command_runner_returns_masked_timeout_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*_args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd=["slow"],
            timeout=kwargs["timeout"],
            output=b"token on stdout",
            stderr="token on stderr",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = CommandRunner(secrets=["token"]).run(
        ["slow"],
        timeout=7,
        check=False,
    )

    assert result.returncode == 124
    assert result.stdout == "*** on stdout"
    assert result.stderr == "*** on stderr\ncommand timed out after 7 seconds"


def test_command_runner_raises_masked_timeout_error_when_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*_args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd=["slow"],
            timeout=kwargs["timeout"],
            stderr=b"hidden",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(CommandError) as exc_info:
        CommandRunner(secrets=["hidden"]).run(["slow"], timeout=3)

    assert exc_info.value.result.returncode == 124
    assert exc_info.value.result.stderr == "***\ncommand timed out after 3 seconds"


def test_graceful_timeout_lets_process_clean_up_before_kill() -> None:
    script = (
        "import signal, sys, time\n"
        "def handler(signum, frame):\n"
        "    print('cleaned up')\n"
        "    sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, handler)\n"
        "time.sleep(30)\n"
    )

    result = CommandRunner().run(
        [sys.executable, "-c", script],
        timeout=1,
        graceful_timeout=5,
        check=False,
    )

    assert result.returncode == 124
    assert result.stdout == "cleaned up\n"
    assert result.stderr == "command timed out after 1 seconds"


def test_graceful_timeout_hard_kills_process_that_ignores_sigterm() -> None:
    script = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(30)\n"
    )

    result = CommandRunner().run(
        [sys.executable, "-c", script],
        timeout=1,
        graceful_timeout=0.3,
        check=False,
    )

    assert result.returncode == 124
    assert result.stdout == ""
    assert result.stderr == "command timed out after 1 seconds"


def test_graceful_timeout_does_not_affect_commands_that_finish_in_time() -> None:
    result = CommandRunner().run(
        [sys.executable, "-c", "print('hello')"],
        timeout=5,
        graceful_timeout=5,
    )

    assert result.returncode == 0
    assert result.stdout == "hello\n"


def test_output_file_writes_command_output_to_the_file(tmp_path: Path) -> None:
    log_file = tmp_path / "cmd.log"

    result = CommandRunner().run(
        [sys.executable, "-c", "print('hello from child')"],
        timeout=5,
        graceful_timeout=5,
        output_file=log_file,
    )

    assert result.returncode == 0
    assert "hello from child" in result.stdout
    assert "hello from child" in log_file.read_text(encoding="utf-8")


def test_output_file_masks_secrets_in_the_returned_stdout(tmp_path: Path) -> None:
    log_file = tmp_path / "cmd.log"

    result = CommandRunner(secrets=["hunter2"]).run(
        [sys.executable, "-c", "print('using password hunter2')"],
        timeout=5,
        graceful_timeout=5,
        output_file=log_file,
    )

    assert "hunter2" not in result.stdout
    assert "***" in result.stdout


def test_output_file_returns_promptly_even_if_a_forked_child_keeps_writing(
    tmp_path: Path,
) -> None:
    # Regression test: openconnect's --background forks after the tunnel is
    # up; the parent (the process we invoke) exits immediately, but the
    # child that continues holding the tunnel open never closes or
    # redirects the stdout/stderr fd it inherited from the parent. Piping
    # that output through subprocess.PIPE means communicate() blocks
    # reading it until *every* holder closes it -- i.e. until the tunnel is
    # disconnected, which for a live VPN session is effectively forever.
    # Redirecting to a real file sidesteps that: only the parent PID needs
    # to exit for wait() to return.
    log_file = tmp_path / "upstream.log"
    script = (
        "import os, sys, time\n"
        "pid = os.fork()\n"
        "if pid > 0:\n"
        "    sys.exit(0)\n"
        "time.sleep(5)\n"
    )

    started = time.monotonic()
    result = CommandRunner().run(
        [sys.executable, "-c", script],
        timeout=2,
        graceful_timeout=1,
        output_file=log_file,
    )
    elapsed = time.monotonic() - started

    assert result.returncode == 0
    assert elapsed < 2


def test_output_file_kills_process_that_ignores_sigterm(tmp_path: Path) -> None:
    log_file = tmp_path / "upstream.log"
    script = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(30)\n"
    )

    result = CommandRunner().run(
        [sys.executable, "-c", script],
        timeout=1,
        graceful_timeout=0.3,
        output_file=log_file,
        check=False,
    )

    assert result.returncode == 124
    assert "command timed out after 1 seconds" in log_file.read_text(encoding="utf-8")


MISSING_BINARY = "kornode-test-binary-that-does-not-exist"


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"graceful_timeout": 1.0}, {"output_file": "log"}],
    ids=["plain", "graceful", "output_file"],
)
def test_missing_binary_returns_failed_result_when_unchecked(
    tmp_path: Path, kwargs: dict[str, Any]
) -> None:
    # Status probes call e.g. `ip` with check=False and expect a failed
    # result back, not a raw FileNotFoundError that surfaces as HTTP 500.
    if "output_file" in kwargs:
        kwargs = {"output_file": tmp_path / "out.log"}

    result = CommandRunner().run([MISSING_BINARY, "--flag"], check=False, **kwargs)

    assert result.returncode == 127
    assert not result.ok
    assert MISSING_BINARY in result.stderr


def test_missing_binary_raises_command_error_when_checked() -> None:
    with pytest.raises(CommandError) as excinfo:
        CommandRunner().run([MISSING_BINARY])

    assert excinfo.value.result.returncode == 127


def test_missing_binary_masks_secrets_in_argv() -> None:
    result = CommandRunner(secrets=["hunter2"]).run(
        [MISSING_BINARY, "--password=hunter2"], check=False
    )

    assert "hunter2" not in " ".join(result.argv)
