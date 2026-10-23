from __future__ import annotations

import errno
import io
import json
import os
import socket
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from kornode.services.secrets import mask_text

_LOG_SINK_TIMEOUT = 10.0


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult) -> None:
        super().__init__(f"command failed ({result.returncode}): {' '.join(result.argv)}")
        self.result = result


class CommandRunner:
    def __init__(self, secrets: Sequence[str] | None = None) -> None:
        self.secrets = list(secrets or [])

    def masked_argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        return tuple(mask_text(str(item), self.secrets) for item in argv)

    def _timeout_result(
        self,
        exc: subprocess.TimeoutExpired,
        *,
        timeout: int,
        masked_argv: tuple[str, ...],
        secrets: Sequence[str],
    ) -> CommandResult:
        stdout = _decode_timeout_output(exc.stdout)
        stderr = _decode_timeout_output(exc.stderr).rstrip()
        timeout_note = f"command timed out after {timeout} seconds"
        stderr = f"{stderr}\n{timeout_note}" if stderr else timeout_note
        return CommandResult(
            argv=masked_argv,
            returncode=124,
            stdout=mask_text(stdout, secrets),
            stderr=mask_text(stderr, secrets),
        )

    def _spawn_error_result(
        self,
        exc: OSError,
        *,
        masked_argv: tuple[str, ...],
        secrets: Sequence[str],
        check: bool,
    ) -> CommandResult:
        # A missing/non-executable binary is reported like a shell would
        # (exit 127) instead of leaking a raw OSError: check=False callers
        # (status probes, best-effort cleanup) rely on getting a result back
        # rather than an exception that surfaces as an HTTP 500.
        reason = exc.strerror or exc.__class__.__name__
        result = CommandResult(
            argv=masked_argv,
            returncode=127,
            stdout="",
            stderr=mask_text(f"{masked_argv[0]}: {reason}", secrets),
        )
        if check:
            raise CommandError(result) from exc
        return result

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        cwd: str | None = None,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
        graceful_timeout: float | None = None,
        output_file: Path | None = None,
    ) -> CommandResult:
        if not argv:
            raise ValueError("argv must not be empty")
        if any(not isinstance(item, str) or item == "" for item in argv):
            raise ValueError("argv must contain non-empty strings")

        secrets = [*self.secrets, *(extra_secrets or [])]
        masked_argv = tuple(mask_text(item, secrets) for item in argv)

        if dry_run:
            return CommandResult(masked_argv, 0, "", "", dry_run=True)

        if output_file is not None:
            return self._run_to_file(
                argv,
                timeout=timeout,
                graceful_timeout=graceful_timeout if graceful_timeout is not None else timeout,
                cwd=cwd,
                input_text=input_text,
                env=env,
                check=check,
                secrets=secrets,
                masked_argv=masked_argv,
                output_file=output_file,
            )

        if graceful_timeout is not None:
            return self._run_graceful(
                argv,
                timeout=timeout,
                graceful_timeout=graceful_timeout,
                cwd=cwd,
                input_text=input_text,
                env=env,
                check=check,
                secrets=secrets,
                masked_argv=masked_argv,
            )

        try:
            completed = subprocess.run(
                list(argv),
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                env=dict(env) if env is not None else None,
                shell=False,
                check=False,
            )
        except OSError as exc:
            return self._spawn_error_result(
                exc, masked_argv=masked_argv, secrets=secrets, check=check
            )
        except subprocess.TimeoutExpired as exc:
            result = self._timeout_result(
                exc,
                timeout=timeout,
                masked_argv=masked_argv,
                secrets=secrets,
            )
            if check:
                raise CommandError(result) from exc
            return result
        result = CommandResult(
            argv=masked_argv,
            returncode=completed.returncode,
            stdout=mask_text(completed.stdout, secrets),
            stderr=mask_text(completed.stderr, secrets),
        )
        if check and not result.ok:
            raise CommandError(result)
        return result

    def _run_to_file(
        self,
        argv: Sequence[str],
        *,
        timeout: int,
        graceful_timeout: float,
        cwd: str | None,
        input_text: str | None,
        env: Mapping[str, str] | None,
        check: bool,
        secrets: Sequence[str],
        masked_argv: tuple[str, ...],
        output_file: Path,
    ) -> CommandResult:
        """A detached sink masks every byte before persistence, even after return.

        RUNTIME: launch only after READY; after the immediate child exits, wait
        for a FLUSH acknowledgement, not for descendants to close their output.
        Secrets and control traffic use private pipes, never argv/environment.
        """
        output_file.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab", buffering=0) as log:
            os.fchmod(log.fileno(), 0o600)
            start_offset = os.fstat(log.fileno()).st_size
            worker = (
                "import sys; sys.path.insert(0, "
                + repr(str(Path(__file__).resolve().parents[2]))
                + "); from kornode.services.command import _log_sink_main; _log_sink_main()"
            )
            control, sink_control = socket.socketpair()
            with control, sink_control:
                control.settimeout(_LOG_SINK_TIMEOUT)
                try:
                    sink = subprocess.Popen(  # noqa: S603 - fixed helper, no shell
                        [sys.executable, "-c", worker],
                        stdin=subprocess.PIPE,
                        stdout=log,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                        pass_fds=(sink_control.fileno(),),
                    )
                except OSError as exc:
                    return self._spawn_error_result(
                        exc,
                        masked_argv=masked_argv,
                        secrets=secrets,
                        check=check,
                    )
                control_fd = sink_control.fileno()
                sink_control.close()
                assert sink.stdin is not None
                try:
                    sink.stdin.write(
                        json.dumps(
                            {
                                "secrets": list(secrets),
                                "control_fd": control_fd,
                            }
                        ).encode()
                        + b"\n"
                    )
                    sink.stdin.flush()
                    if control.recv(1) != b"R":
                        raise OSError(errno.EIO, "command log sink did not become ready")
                except OSError:
                    with suppress(BrokenPipeError):
                        sink.stdin.close()
                    threading.Thread(target=sink.wait, daemon=True).start()
                    return self._spawn_error_result(
                        OSError(errno.EIO, "command log sink did not become ready"),
                        masked_argv=masked_argv,
                        secrets=secrets,
                        check=check,
                    )
                # Do not persist argv: it can contain unregistered credentials.
                log.write(mask_text("--- command output ---\n", secrets).encode())
                try:
                    process = subprocess.Popen(  # noqa: S603 - validated argv, shell=False
                        list(argv),
                        stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                        stdout=sink.stdin,
                        stderr=subprocess.STDOUT,
                        text=True,
                        cwd=cwd,
                        env=dict(env) if env is not None else None,
                    )
                except OSError as exc:
                    sink.stdin.close()
                    threading.Thread(target=sink.wait, daemon=True).start()
                    return self._spawn_error_result(
                        exc,
                        masked_argv=masked_argv,
                        secrets=secrets,
                        check=check,
                    )
                timed_out = False
                sink_failed = False
                try:
                    if process.stdin is not None:
                        try:
                            process.stdin.write(input_text or "")
                        except BrokenPipeError:
                            pass
                        finally:
                            with suppress(BrokenPipeError):
                                process.stdin.close()
                    try:
                        process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.terminate()
                        try:
                            process.wait(timeout=graceful_timeout)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                finally:
                    sink.stdin.close()
                    try:
                        control.sendall(b"B")
                        # F = drained through EOF; B = drained the measured
                        # boundary while descendants still hold the pipe open.
                        if control.recv(1) not in (b"F", b"B"):
                            raise OSError(errno.EIO, "command log sink failed to flush output")
                    except OSError:
                        sink_failed = True
                    finally:
                        threading.Thread(target=sink.wait, daemon=True).start()
                if timed_out:
                    log.write(
                        mask_text(f"command timed out after {timeout} seconds\n", secrets).encode()
                    )
        output = self._read_since(output_file, start_offset)
        result = CommandResult(
            argv=masked_argv,
            returncode=124 if timed_out else (process.returncode or (125 if sink_failed else 0)),
            stdout="" if timed_out else mask_text(output, secrets),
            stderr=mask_text(output, secrets) if timed_out else "",
        )
        if sink_failed:
            result = CommandResult(
                result.argv,
                result.returncode,
                result.stdout,
                result.stderr + mask_text("\ncommand log sink failed to flush output", secrets),
            )
        if check and not result.ok:
            raise CommandError(result)
        return result

    @staticmethod
    def _read_since(path: Path, offset: int) -> str:
        with path.open("r", encoding="utf-8") as handle:
            handle.seek(offset)
            return handle.read().strip()

    def _run_graceful(
        self,
        argv: Sequence[str],
        *,
        timeout: int,
        graceful_timeout: float,
        cwd: str | None,
        input_text: str | None,
        env: Mapping[str, str] | None,
        check: bool,
        secrets: Sequence[str],
        masked_argv: tuple[str, ...],
    ) -> CommandResult:
        """Like run(), but on timeout sends SIGTERM and gives the process a
        grace period before SIGKILL, instead of killing it outright.

        subprocess.run's own timeout handling kills unconditionally, which
        never gives a script-driven process (e.g. openconnect invoking
        vpnc-script) a chance to run its own cleanup/disconnect handler --
        for openconnect specifically that cleanup is what restores
        /etc/resolv.conf, so an unconditional kill leaves it in a
        half-modified state that breaks every later connection attempt.
        """
        try:
            process = subprocess.Popen(  # noqa: S603 - argv validated above, shell=False
                list(argv),
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=dict(env) if env is not None else None,
            )
        except OSError as exc:
            return self._spawn_error_result(
                exc, masked_argv=masked_argv, secrets=secrets, check=check
            )
        try:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=graceful_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            timeout_note = f"command timed out after {timeout} seconds"
            stderr = f"{stderr}\n{timeout_note}" if stderr else timeout_note
            result = CommandResult(
                argv=masked_argv,
                returncode=124,
                stdout=mask_text(stdout, secrets),
                stderr=mask_text(stderr, secrets),
            )
            if check:
                raise CommandError(result) from None
            return result
        result = CommandResult(
            argv=masked_argv,
            returncode=process.returncode,
            stdout=mask_text(stdout, secrets),
            stderr=mask_text(stderr, secrets),
        )
        if check and not result.ok:
            raise CommandError(result)
        return result


class _PrivateKeyFilter:
    """Suppress raw PEM blocks before anything can rewrite their delimiters.

    Retained state is at most 256 characters, independent of key/body length.
    An oversized or unterminated BEGIN header fails closed rather than risking
    disclosure of a body whose boundary we could not fully classify.
    """

    _BEGIN = "-----BEGIN "
    _MAX_HEADER = 256

    def __init__(self) -> None:
        self._pending = ""
        self._header = False
        self._end: str | None = None
        self._discarding = False

    @staticmethod
    def _suffix_length(text: str, marker: str) -> int:
        for size in range(min(len(text), len(marker) - 1), 0, -1):
            if text.endswith(marker[:size]):
                return size
        return 0

    def feed(self, text: str, *, final: bool = False) -> str:
        self._pending += text
        safe: list[str] = []
        while self._pending:
            if self._discarding:
                self._pending = ""
                break
            if self._end is not None:
                position = self._pending.find(self._end)
                if position >= 0:
                    self._pending = self._pending[position + len(self._end) :]
                    self._end = None
                    continue
                keep = self._suffix_length(self._pending, self._end) if not final else 0
                self._pending = self._pending[-keep:] if keep else ""
                break
            if self._header:
                end = self._pending.find("-----", len(self._BEGIN))
                newline = self._pending.find("\n", len(self._BEGIN))
                if 0 <= end <= self._MAX_HEADER - 5 and (newline < 0 or end < newline):
                    header = self._pending[: end + 5]
                    self._pending = self._pending[end + 5 :]
                    self._header = False
                    label = header[len(self._BEGIN) : -5]
                    if label.endswith("PRIVATE KEY"):
                        self._end = f"-----END {label}-----"
                        safe.append("[private key omitted]\n")
                    else:
                        safe.append(header)
                    continue
                if 0 <= newline < self._MAX_HEADER:
                    safe.append(self._pending[: newline + 1])
                    self._pending = self._pending[newline + 1 :]
                    self._header = False
                    continue
                if len(self._pending) > self._MAX_HEADER or final:
                    self._discarding = True
                    self._pending = ""
                    safe.append("[incomplete PEM header omitted]\n")
                break
            position = self._pending.find(self._BEGIN)
            if position >= 0:
                safe.append(self._pending[:position])
                self._pending = self._pending[position:]
                self._header = True
                continue
            keep = self._suffix_length(self._pending, self._BEGIN) if not final else 0
            safe.append(self._pending[:-keep] if keep else self._pending)
            self._pending = self._pending[-keep:] if keep else ""
            break
        return "".join(safe)


def _log_sink_main() -> None:
    """Detached, bounded-memory reader. Only sanitized text reaches stdout (the log).

    First suppress PEM keys on the original stream, then recognize known
    secrets split across arbitrary reads and mask assignments on complete
    lines. Both raw delimiter state and ambiguous secret suffixes survive
    background barriers. Oversized lines are discarded, never partially flushed.
    """
    import array
    import codecs
    import fcntl
    import selectors
    import termios

    source = cast(io.BufferedReader, sys.stdin.buffer)
    settings = json.loads(source.readline())
    secrets = sorted({value for value in settings["secrets"] if value}, key=len, reverse=True)
    lookahead = max(map(len, secrets), default=1)
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    pem_filter = _PrivateKeyFilter()
    pending = ""
    line = ""
    dropping = False

    def persist(text: str) -> None:
        nonlocal line, dropping
        for part in text.splitlines(keepends=True):
            # Only LF delimits persisted records; known multiline secrets have
            # already been removed by the streaming matcher below.
            line += part
            if len(line) > 65536:
                dropping = True
                line = ""
            if part.endswith("\n"):
                if dropping:
                    sys.stdout.write("[oversized output omitted]\n")
                else:
                    sys.stdout.write(mask_text(line))
                line = ""
                dropping = False
        sys.stdout.flush()

    def consume(chunk: bytes, *, final: bool = False) -> None:
        nonlocal pending
        # Delimiters must be recognized on the original stream: a registered
        # secret may itself be PRIVATE, BEGIN, a newline, or the whole marker.
        pending += pem_filter.feed(decoder.decode(chunk, final=final), final=final)
        pos = 0
        sanitized: list[str] = []
        while pos < len(pending):
            # Retain only an ambiguous suffix, not a fixed lookahead window.
            # In particular a safe newline must flush before a background
            # barrier, without exposing a secret that straddles the barrier.
            if not final and len(pending) - pos < lookahead:
                suffix = pending[pos:]
                if any(value.startswith(suffix) and value != suffix for value in secrets):
                    break
            match = next((value for value in secrets if pending.startswith(value, pos)), None)
            if match is not None:
                sanitized.append("***")
                pos += len(match)
            else:
                sanitized.append(pending[pos])
                pos += 1
        pending = pending[pos:]
        persist("".join(sanitized))
        if final and (line or dropping):
            persist("\n")

    # Configuration is consumed before READY, so the buffered config reader
    # cannot prefetch any child output. All subsequent reads are unbuffered.
    data_fd = source.fileno()
    os.set_blocking(data_fd, False)
    with (
        socket.socket(fileno=settings["control_fd"]) as control,
        selectors.DefaultSelector() as events,
    ):
        events.register(data_fd, selectors.EVENT_READ, "data")
        events.register(control, selectors.EVENT_READ, "control")
        eof = False
        control_open = True

        def read_data(size: int) -> int:
            nonlocal eof
            chunk = os.read(data_fd, size)
            consume(chunk, final=not chunk)
            if not chunk:
                eof = True
                events.unregister(data_fd)
            return len(chunk)

        control.sendall(b"R")
        while True:
            for key, _ in events.select():
                if key.data == "data":
                    if not eof:
                        # A preceding control event in this batch may have
                        # drained the pipe, invalidating its data readiness.
                        with suppress(BlockingIOError):
                            read_data(8192)
                    continue
                request = control.recv(1)
                if not request:
                    events.unregister(control)
                    control_open = False
                    continue
                if request != b"B":
                    raise ValueError("invalid log sink control message")
                if not eof:
                    # A snapshot bounds the drain even if descendants write
                    # continuously. Everything the exited parent wrote is
                    # already in this pipe or has been consumed above.
                    queued = array.array("i", [0])
                    fcntl.ioctl(data_fd, termios.FIONREAD, queued, True)
                    remaining = queued[0]
                    while remaining:
                        remaining -= read_data(min(8192, remaining))
                    # EOF distinguishes a finished foreground stream from a
                    # daemon's open stream without waiting for descendants.
                    with suppress(BlockingIOError):
                        read_data(1)
                sys.stdout.flush()
                control.sendall(b"F" if eof else b"B")
                if eof:
                    return
            if eof and not control_open:
                return


def _decode_timeout_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
