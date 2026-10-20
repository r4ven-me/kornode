"""Strict-host-key SSH. Remote argv is quoted for OpenSSH's unavoidable login shell.

No shell=True; payloads (including tokens) travel on stdin, never in argv/errors.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tests.e2e.inventory import E2EError, Host, Inventory

MAX_REPLY = 12 * 1024 * 1024
MAX_IMAGE = 3 * 1024**3


class SSH:
    def __init__(self, inventory: Inventory, host: Host, run_id: str) -> None:
        self.inventory, self.host, self.run_id = inventory, host, run_id

    def argv(self) -> list[str]:
        worker = Path(__file__).with_name("worker.py").read_text()
        return [
            "ssh",
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "LogLevel=ERROR",
            "-o",
            f"UserKnownHostsFile={self.inventory.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-i",
            str(self.inventory.key),
            "-p",
            str(self.host.port),
            "--",
            f"{self.host.user}@{self.host.address}",
            shlex.join(["sudo", "-n", "--", "python3", "-c", worker]),
        ]

    def request(self, action: str, case: str = "", **payload: Any) -> bytes:
        return (
            json.dumps(
                {
                    "action": action,
                    "role": self.host.role,
                    "run_id": self.run_id,
                    "case": case,
                    "payload": payload,
                }
            )
            + "\n"
        ).encode()

    def _invoke(self, *, data: bytes | None = None, source: Any = None, timeout: int = 180) -> Any:
        try:
            # Capture to private files rather than buffering unbounded SSH output.
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                result = subprocess.run(
                    self.argv(),
                    input=data,
                    stdin=source,
                    stdout=out,
                    stderr=err,
                    timeout=timeout,
                    check=False,
                )
                if result.returncode:
                    raise E2EError("E2E SSH action failed; remote output withheld")
                out.seek(0)
                raw = out.read(MAX_REPLY + 1)
                if len(raw) > MAX_REPLY:
                    raise E2EError("E2E SSH reply exceeded limit")
                reply = json.loads(raw)
                if not isinstance(reply, dict) or reply.get("ok") is not True:
                    raise E2EError("E2E remote action refused; output withheld")
                return reply.get("result")
        except E2EError:
            raise
        except Exception:
            raise E2EError("E2E SSH transport failed; output withheld") from None

    def call(self, action: str, case: str = "", **payload: Any) -> Any:
        timeout = (
            360
            if action in {"restore", "pull_previous"}
            else 30
            if action in {"probe", "status"}
            else 180
        )
        return self._invoke(data=self.request(action, case, **payload), timeout=timeout)

    def load(self, archive: Path) -> Any:
        size = archive.stat().st_size
        if not 0 < size <= MAX_IMAGE:
            raise E2EError("E2E image archive exceeds transfer limit")
        # A private seekable request avoids both GB-sized RAM buffers and leaking
        # an image path through remote shell interpolation. Extra disk cost: 1 copy.
        with tempfile.TemporaryFile() as handle, archive.open("rb") as image:
            handle.write(self.request("load_images", size=size))
            shutil.copyfileobj(image, handle, length=1024 * 1024)
            handle.seek(0)
            return self._invoke(source=handle, timeout=600)
