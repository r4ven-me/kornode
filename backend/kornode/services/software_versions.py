from __future__ import annotations

import platform
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from kornode import __version__
from kornode.services.command import CommandRunner


@dataclass(frozen=True)
class SoftwareVersion:
    name: str
    version: str
    command: tuple[str, ...] | None = None
    status: str = "ok"


class SoftwareVersionService:
    def __init__(
        self,
        runner: CommandRunner | None = None,
        os_release_path: Path = Path("/etc/os-release"),
    ) -> None:
        self.runner = runner or CommandRunner()
        self.os_release_path = os_release_path

    def collect(self) -> list[SoftwareVersion]:
        rows = [
            SoftwareVersion("kornode", __version__, None),
            SoftwareVersion("Python", platform.python_version(), ("python", "--version")),
            SoftwareVersion("Distribution", self._distribution(), None),
        ]
        commands: list[tuple[str, tuple[str, ...]]] = [
            ("ocserv", ("ocserv", "--version")),
            ("OpenConnect", ("openconnect", "--version")),
            ("dnsmasq", ("dnsmasq", "--version")),
            ("nftables", ("nft", "--version")),
            ("certtool", ("certtool", "--version")),
            ("oathtool", ("oathtool", "--version")),
            ("qrencode", ("qrencode", "--version")),
            ("supervisord", ("supervisord", "--version")),
            ("iproute2", ("ip", "-Version")),
            ("curl", ("curl", "--version")),
        ]
        # Each entry spawns a separate "--version" subprocess; running them
        # on a thread pool instead of sequentially cuts total latency from
        # the sum of every process's startup time down to the slowest one.
        with ThreadPoolExecutor(max_workers=len(commands)) as executor:
            rows.extend(executor.map(lambda item: self._command_version(*item), commands))
        return rows

    def _distribution(self) -> str:
        data = self._read_os_release()
        pretty_name = data.get("PRETTY_NAME")
        if pretty_name:
            return pretty_name
        name = data.get("NAME")
        version = data.get("VERSION")
        if name and version:
            return f"{name} {version}"
        if name:
            return name
        return platform.platform()

    def _read_os_release(self) -> dict[str, str]:
        try:
            content = self.os_release_path.read_text(encoding="utf-8")
        except OSError:
            return {}
        values: dict[str, str] = {}
        for line in content.splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            values[key] = raw_value.strip().strip('"')
        return values

    def _command_version(self, name: str, argv: tuple[str, ...]) -> SoftwareVersion:
        result = self.runner.run(argv, timeout=10, check=False)
        if result.returncode == 127:
            # Binary not installed (CommandRunner reports that as exit 127).
            return SoftwareVersion(name, "not available", argv, "missing")
        output = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
        if result.returncode != 0 and not output:
            return SoftwareVersion(name, "not available", argv, "missing")
        if result.returncode != 0:
            return SoftwareVersion(name, first_meaningful_line(output), argv, "warning")
        return SoftwareVersion(name, first_meaningful_line(output), argv)


def first_meaningful_line(output: str) -> str:
    for line in output.splitlines():
        normalized = re.sub(r"\s+", " ", line).strip()
        if normalized:
            return normalized
    return "unknown"
