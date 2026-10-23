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
    script = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(30)\n"

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
    assert "hunter2" not in log_file.read_text(encoding="utf-8")
    assert "***" in log_file.read_text(encoding="utf-8")
    assert log_file.stat().st_mode & 0o777 == 0o600


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
    script = "import os, sys, time\npid = os.fork()\nif pid > 0:\n    sys.exit(0)\ntime.sleep(5)\n"

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
    script = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(30)\n"

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


def test_log_sink_masks_chunk_boundaries_and_secret_assignments(tmp_path: Path) -> None:
    log = tmp_path / "masked.log"
    script = (
        "import os, time\n"
        "os.write(1, b'A' * 8190 + b'hun'); time.sleep(.15)\n"
        "os.write(2, b'ter2\\npassword=unregistered-value\\n')\n"
        "os.write(1, b'-----BEGIN PRIVATE KEY-----\\nprivate-material\\n' "
        "+ b'-----END PRIVATE KEY-----\\n')\n"
        "os.write(1, b'multiline-first\\nsecond-half\\nfinished\\n')\n"
    )
    result = CommandRunner(secrets=["hunter2", "multiline-first\nsecond-half"]).run(
        [sys.executable, "-c", script],
        output_file=log,
        timeout=5,
    )
    content = log.read_text()
    assert result.ok
    for secret in (
        "hunter2",
        "unregistered-value",
        "private-material",
        "multiline-first",
        "second-half",
    ):
        assert secret not in content
    assert "finished" in content
    assert "password=***" in content


def test_detached_sink_keeps_masking_after_the_caller_exits(tmp_path: Path) -> None:
    import os

    import kornode.services.command as command_module

    log = tmp_path / "background.log"
    done = tmp_path / "done"
    child = (
        "import os, sys, time\n"
        "if os.fork(): os._exit(0)\n"
        "time.sleep(.5)\n"
        "os.write(1, b'hun'); time.sleep(.15)\n"
        "os.write(2, b'ter2\\nlate output\\n')\n"
        f"open({str(done)!r}, 'w').close()\n"
    )
    caller = (
        "from kornode.services.command import CommandRunner\n"
        "from pathlib import Path\n"
        f"CommandRunner(secrets=['hunter2']).run({[sys.executable, '-c', child]!r}, "
        f"output_file=Path({str(log)!r}), timeout=3)\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(command_module.__file__).resolve().parents[2])}
    started = time.monotonic()
    caller_result = subprocess.run([sys.executable, "-c", caller], env=env, timeout=4, check=False)
    assert caller_result.returncode == 0
    assert time.monotonic() - started < 2
    deadline = time.monotonic() + 4
    snapshots = []
    while time.monotonic() < deadline:
        content = log.read_text()
        snapshots.append(content)
        assert "hunter2" not in content
        # Even the first partial secret must not have hit disk during the gap.
        assert "hun" not in content
        if done.exists() and "late output" in content:
            break
        time.sleep(0.02)
    else:
        pytest.fail("detached masking sink did not persist background output")
    assert "***" in snapshots[-1]


def test_log_sink_discards_oversized_sensitive_line(tmp_path: Path) -> None:
    log = tmp_path / "large.log"
    CommandRunner().run(
        [sys.executable, "-c", "print('password=' + 'sensitive' * 20000); print('done')"],
        output_file=log,
        timeout=5,
    )
    content = log.read_text()
    assert "sensitive" not in content
    assert "done" in content
    assert len(content) < 1000


def _delay_log_sink(
    monkeypatch: pytest.MonkeyPatch,
    *,
    startup: float = 0,
    drain: float = 0,
) -> list[subprocess.Popen[Any]]:
    """Slow the real helper, not the command or a mocked result."""
    popen = subprocess.Popen
    helpers: list[subprocess.Popen[Any]] = []

    def delayed_popen(argv: Any, *args: Any, **kwargs: Any) -> subprocess.Popen[Any]:
        helper = len(argv) > 2 and "_log_sink_main" in argv[2]
        if helper:
            prefix = f"import time; time.sleep({startup!r})\n"
            if drain:
                prefix += (
                    "import selectors\n"
                    "original_select = selectors.DefaultSelector.select\n"
                    "delayed_once = False\n"
                    "def slow_select(self, *args, **kwargs):\n"
                    "    global delayed_once\n"
                    "    if not delayed_once:\n"
                    "        delayed_once = True\n"
                    f"        time.sleep({drain!r})\n"
                    "    return original_select(self, *args, **kwargs)\n"
                    "selectors.DefaultSelector.select = slow_select\n"
                )
            argv = [*argv[:2], prefix + argv[2], *argv[3:]]
        process = popen(argv, *args, **kwargs)
        if helper:
            helpers.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", delayed_popen)
    return helpers


@pytest.mark.parametrize("checked", [False, True])
@pytest.mark.parametrize("startup,drain", [(0.6, 0), (0, 0.6)])
def test_completed_command_waits_for_sanitized_output_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    checked: bool,
    startup: float,
    drain: float,
) -> None:
    helpers = _delay_log_sink(monkeypatch, startup=startup, drain=drain)
    log = tmp_path / "immediate-error.log"
    try:
        runner = CommandRunner(secrets=["hunter2"])
        argv = [
            sys.executable,
            "-c",
            "import os; os.write(2, b'immediate failure hunter2'); raise SystemExit(7)",
        ]
        if checked:
            with pytest.raises(CommandError) as exc:
                runner.run(argv, output_file=log, timeout=4)
            result = exc.value.result
        else:
            result = runner.run(argv, output_file=log, timeout=4, check=False)
        assert result.returncode == 7
        assert "immediate failure ***" in result.stdout
        content = log.read_text()
        assert "immediate failure ***" in content
        assert "hunter2" not in content
        assert "hunter2" not in result.stdout
    finally:
        for helper in helpers:
            helper.wait(timeout=5)


def test_barrier_flushes_parent_error_without_waiting_for_background_secret_tail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helpers = _delay_log_sink(monkeypatch, startup=0.6, drain=0.6)
    log = tmp_path / "background-barrier.log"
    release = tmp_path / "release"
    child = (
        "import os, time\n"
        "os.write(2, b'immediate failure hunter2\\n')\n"
        "os.write(1, b'hun')\n"
        "if os.fork(): os._exit(7)\n"
        "deadline = time.monotonic() + 5\n"
        f"while not os.path.exists({str(release)!r}) and time.monotonic() < deadline:\n"
        "    time.sleep(.01)\n"
        "os.write(2, b'ter2\\nlate output\\n')\n"
    )
    try:
        result = CommandRunner(secrets=["hunter2"]).run(
            [sys.executable, "-c", child],
            output_file=log,
            check=False,
            timeout=2,
        )
        assert result.returncode == 7
        assert "immediate failure ***" in result.stdout
        content = log.read_text()
        assert "immediate failure ***" in content
        assert "hun" not in content
        assert "late output" not in content
        assert not release.exists()
    finally:
        release.touch()
        for helper in helpers:
            helper.wait(timeout=5)
    content = log.read_text()
    assert "late output" in content
    assert content.count("***") == 2
    assert "hunter2" not in content


@pytest.mark.parametrize("phase", ["startup", "flush"])
def test_sink_protocol_failure_is_reported_not_silently_successful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    popen = subprocess.Popen
    helpers: list[subprocess.Popen[Any]] = []

    def failing_helper(argv: Any, *args: Any, **kwargs: Any) -> subprocess.Popen[Any]:
        helper = len(argv) > 2 and "_log_sink_main" in argv[2]
        if helper:
            if phase == "startup":
                prefix = "raise SystemExit(1)\n"
            else:
                prefix = (
                    "import selectors\n"
                    "def failed_select(*args, **kwargs):\n"
                    "    raise OSError('injected helper failure')\n"
                    "selectors.DefaultSelector.select = failed_select\n"
                )
            argv = [*argv[:2], prefix + argv[2], *argv[3:]]
        process = popen(argv, *args, **kwargs)
        if helper:
            helpers.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", failing_helper)
    marker = tmp_path / "child-started"
    try:
        result = CommandRunner().run(
            [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
            output_file=tmp_path / "failed-helper.log",
            check=False,
            timeout=2,
        )
        assert not result.ok
        assert "command log sink" in result.stderr
        if phase == "startup":
            assert result.returncode == 127
            assert not marker.exists()
        else:
            assert result.returncode == 125
            assert marker.exists()
    finally:
        for helper in helpers:
            helper.wait(timeout=5)


@pytest.fixture(scope="module", params=["PKCS8", "TraditionalOpenSSL", "OpenSSH"])
def generated_private_key(request: pytest.FixtureRequest) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat[request.param],
        serialization.NoEncryption(),
    )


def _fragment_log_sink(
    monkeypatch: pytest.MonkeyPatch,
    size: int,
    *,
    barrier_first: bool = False,
) -> list[subprocess.Popen[Any]]:
    """Force real pipe reads to split PEM markers and registered secrets."""
    popen = subprocess.Popen
    helpers: list[subprocess.Popen[Any]] = []

    def fragmented_popen(argv: Any, *args: Any, **kwargs: Any) -> subprocess.Popen[Any]:
        helper = len(argv) > 2 and "_log_sink_main" in argv[2]
        if helper:
            prefix = (
                "import os\n"
                "original_read = os.read\n"
                "def fragmented_read(fd, count):\n"
                f"    return original_read(fd, min(count, {size}))\n"
                "os.read = fragmented_read\n"
            )
            if barrier_first:
                # Queue both events, then drain the pipe via the barrier before
                # handling the now-stale data readiness from the same batch.
                prefix += (
                    "import select, selectors\n"
                    "original_select = selectors.DefaultSelector.select\n"
                    "first_select = True\n"
                    "def barrier_first_select(self, *args, **kwargs):\n"
                    "    global first_select\n"
                    "    if first_select:\n"
                    "        first_select = False\n"
                    "        control = next(k.fd for k in self.get_map().values() "
                    "if k.data == 'control')\n"
                    "        select.select([control], [], [])\n"
                    "    return sorted(original_select(self, *args, **kwargs), "
                    "key=lambda event: event[0].data != 'control')\n"
                    "selectors.DefaultSelector.select = barrier_first_select\n"
                )
            argv = [*argv[:2], prefix + argv[2], *argv[3:]]
        process = popen(argv, *args, **kwargs)
        if helper:
            helpers.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", fragmented_popen)
    return helpers


def _assert_no_private_payload(pem: bytes, content: str) -> None:
    payload = [line for line in pem.decode().splitlines() if not line.startswith("-----")]
    assert all(part not in content for part in payload), "private key payload reached the log"


@pytest.mark.parametrize(
    "secret_kind",
    ["PRIVATE", "KEY", "BEGIN", "END", "newline", "delimiter", "delimiter_line", "multiline"],
)
@pytest.mark.parametrize("read_size", [1, 8192])
def test_pem_suppression_precedes_registered_secret_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    generated_private_key: bytes,
    secret_kind: str,
    read_size: int,
) -> None:
    helpers = _fragment_log_sink(monkeypatch, read_size)
    pem = generated_private_key
    secret = {
        "newline": "\n",
        "delimiter": pem.splitlines()[0].decode(),
        "delimiter_line": pem.splitlines()[0].decode() + "\n",
        "multiline": "outside-first\noutside-second",
    }.get(secret_kind, secret_kind)
    log = tmp_path / "private-key.log"
    try:
        result = CommandRunner(secrets=[secret]).run(
            [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
            input_text="outside-first\noutside-second\n" + pem.decode() + "after\n",
            output_file=log,
            timeout=4,
        )
        assert result.ok
        content = log.read_text()
        _assert_no_private_payload(pem, content)
        _assert_no_private_payload(pem, result.stdout)
        assert "after" in content
        if secret_kind == "multiline":
            assert "outside-first" not in content
            assert "outside-second" not in content
    finally:
        for helper in helpers:
            helper.wait(timeout=5)


@pytest.mark.parametrize("barrier_first", [False, True], ids=["natural-order", "barrier-first"])
@pytest.mark.parametrize("cut_at", ["begin", "body", "end"])
@pytest.mark.parametrize("secret_kind", ["PRIVATE", "KEY", "BEGIN", "newline", "delimiter"])
def test_raw_pem_boundaries_survive_background_flush_barriers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    generated_private_key: bytes,
    cut_at: str,
    secret_kind: str,
    barrier_first: bool,
) -> None:
    helpers = _fragment_log_sink(monkeypatch, 2, barrier_first=barrier_first)
    pem = generated_private_key
    cut = {
        "begin": pem.index(b"PRIVATE") + 3,
        "body": pem.index(b"\n") + 80,
        "end": pem.index(b"-----END ") + 13,
    }[cut_at]
    secret = {"newline": "\n", "delimiter": pem.splitlines()[0].decode()}.get(
        secret_kind, secret_kind
    )
    release = tmp_path / "release"
    log = tmp_path / "key-barrier.log"
    child = (
        "import os, sys, time\n"
        "data = sys.stdin.buffer.read()\n"
        "os.write(1, b'before\\n')\n"
        f"os.write(1, data[:{cut}])\n"
        "if os.fork(): os._exit(0)\n"
        "deadline = time.monotonic() + 5\n"
        f"while not os.path.exists({str(release)!r}) and time.monotonic() < deadline:\n"
        "    time.sleep(.01)\n"
        f"os.write(2, data[{cut}:] + b'after\\n')\n"
    )
    try:
        result = CommandRunner(secrets=[secret]).run(
            [sys.executable, "-c", child],
            input_text=pem.decode(),
            output_file=log,
            timeout=2,
        )
        assert result.ok
        _assert_no_private_payload(pem, log.read_text())
        _assert_no_private_payload(pem, result.stdout)
        assert "after" not in log.read_text()
        assert not release.exists()
    finally:
        release.touch()
        for helper in helpers:
            helper.wait(timeout=5)
    assert all(helper.returncode == 0 for helper in helpers), "log sink exited unsuccessfully"
    content = log.read_text()
    _assert_no_private_payload(pem, content)
    assert "after" in content


def test_raw_pem_filter_state_is_bounded_and_unterminated_keys_fail_closed() -> None:
    from kornode.services.command import _PrivateKeyFilter

    scrubber = _PrivateKeyFilter()
    assert (
        scrubber.feed("before\n-----BEGIN PRIVATE KEY-----\n") == "before\n[private key omitted]\n"
    )
    for _ in range(256):
        assert scrubber.feed("A" * 8192) == ""
        assert len(scrubber._pending) <= scrubber._MAX_HEADER
    assert scrubber.feed("", final=True) == ""

    scrubber = _PrivateKeyFilter()
    assert "omitted" in scrubber.feed("-----BEGIN " + "A" * 8192)
    assert len(scrubber._pending) <= scrubber._MAX_HEADER
    assert scrubber.feed("PRIVATE KEY-----\npayload\n-----END PRIVATE KEY-----\n", final=True) == ""


def test_raw_pem_filter_preserves_non_private_pem_and_matches_end_label() -> None:
    from kornode.services.command import _PrivateKeyFilter

    scrubber = _PrivateKeyFilter()
    public = "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n"
    assert "".join(scrubber.feed(char) for char in public) == public
    assert scrubber.feed("-----BEGIN PRIVATE KEY-----\n") == "[private key omitted]\n"
    assert scrubber.feed("-----END OTHER PRIVATE KEY-----\nstill-private\n") == ""
    assert scrubber.feed("-----END PRIVATE KEY-----\nafter\n", final=True) == "\nafter\n"


def test_raw_pem_filter_detects_key_after_oversized_line_prefix(
    tmp_path: Path,
    generated_private_key: bytes,
) -> None:
    log = tmp_path / "oversized-key-prefix.log"
    result = CommandRunner(secrets=["PRIVATE"]).run(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
        input_text="X" * 70000 + generated_private_key.decode() + "after\n",
        output_file=log,
        timeout=4,
    )
    assert result.ok
    content = log.read_text()
    _assert_no_private_payload(generated_private_key, content)
    assert len(content) < 1000
    assert "after" in content
