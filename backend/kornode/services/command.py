from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from kornode.services.secrets import mask_text


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
        """Like _run_graceful, but for a command that daemonizes (forks to
        the background) after startup, e.g. `openconnect --background`.

        A backgrounded child inherits its parent's stdout/stderr file
        descriptors; if those are pipes, reading them via communicate()
        blocks until *every* process holding the write end closes it --
        for a VPN client that's still running to hold the tunnel open,
        that's "until disconnected", i.e. it never returns for the
        duration of this call, and the timeout/graceful-kill below would
        end up firing on every successful connection, tearing the tunnel
        back down right after it came up. Redirecting output to a real
        file instead sidesteps that: only the immediate (parent) process
        needs to exit for wait() to return, regardless of what its
        background child keeps writing to the inherited fd afterwards.

        The just-written slice of the file is also read back (masked) into
        the returned CommandResult, so an immediate failure (e.g. a bad
        passphrase, rejected before the process ever gets to backgrounding)
        still shows up right away in the caller's response instead of only
        being visible by going to look at the log file separately.
        """
        output_file.parent.mkdir(parents=True, exist_ok=True)
        start_offset = output_file.stat().st_size if output_file.exists() else 0
        with output_file.open("a", encoding="utf-8") as log:
            log.write(f"--- {' '.join(masked_argv)} ---\n")
            log.flush()
            try:
                process = subprocess.Popen(  # noqa: S603 - argv validated above, shell=False
                    list(argv),
                    stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=cwd,
                    env=dict(env) if env is not None else None,
                )
            except OSError as exc:
                return self._spawn_error_result(
                    exc, masked_argv=masked_argv, secrets=secrets, check=check
                )
            if process.stdin is not None:
                process.stdin.write(input_text or "")
                process.stdin.close()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=graceful_timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                timeout_note = f"command timed out after {timeout} seconds"
                log.write(f"{timeout_note}\n")
                log.flush()
                output = self._read_since(output_file, start_offset)
                stderr = f"{output}\n{timeout_note}" if output else timeout_note
                result = CommandResult(
                    argv=masked_argv,
                    returncode=124,
                    stdout="",
                    stderr=mask_text(stderr, secrets),
                )
                if check:
                    raise CommandError(result) from None
                return result
        output = self._read_since(output_file, start_offset)
        result = CommandResult(
            argv=masked_argv,
            returncode=process.returncode,
            stdout=mask_text(output, secrets),
            stderr="",
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


def _decode_timeout_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
