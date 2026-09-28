from __future__ import annotations

from pathlib import Path

from kornode.services.command import CommandResult
from kornode.services.software_versions import SoftwareVersionService, first_meaningful_line


class FakeRunner:
    def run(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        timeout: int = 30,
        check: bool = True,
    ) -> CommandResult:
        del timeout, check
        if tuple(argv) == ("ocserv", "--version"):
            return CommandResult(tuple(argv), 0, "ocserv 1.4.2\n", "")
        if tuple(argv) == ("dnsmasq", "--version"):
            return CommandResult(tuple(argv), 1, "", "dnsmasq: failed to start")
        # CommandRunner reports a binary that isn't installed as exit 127.
        return CommandResult(tuple(argv), 127, "", f"{argv[0]}: No such file or directory")


def test_first_meaningful_line_normalizes_whitespace() -> None:
    assert first_meaningful_line("\n  dnsmasq   version  2.90\nmore") == "dnsmasq version 2.90"


def test_collect_includes_distribution_and_command_status(tmp_path: Path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text('PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n', encoding="utf-8")
    service = SoftwareVersionService(runner=FakeRunner(), os_release_path=os_release)  # type: ignore[arg-type]

    rows = {row.name: row for row in service.collect()}

    assert rows["Distribution"].version == "Debian GNU/Linux 13 (trixie)"
    assert rows["ocserv"].version == "ocserv 1.4.2"
    assert rows["dnsmasq"].status == "warning"
    assert rows["qrencode"].status == "missing"
    assert rows["qrencode"].version == "not available"
