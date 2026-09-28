from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.sessions import SessionService


@dataclass(frozen=True)
class DiagnosticProbe:
    name: str
    argv: tuple[str, ...]


class DiagnosticsService:
    def __init__(self, config: AppConfig, runner: CommandRunner | None = None) -> None:
        self.config = config
        self.runner = runner or CommandRunner()

    def probes(self) -> list[DiagnosticProbe]:
        prefix = self.config.routing.nft_prefix
        occtl = SessionService(self.config, runner=self.runner)
        return [
            DiagnosticProbe("ip addr", ("ip", "addr")),
            DiagnosticProbe("ip route", ("ip", "route")),
            DiagnosticProbe("ip route table all", ("ip", "route", "show", "table", "all")),
            DiagnosticProbe("ip rule", ("ip", "rule")),
            DiagnosticProbe("nft ruleset", ("nft", "list", "ruleset")),
            DiagnosticProbe(
                "nft filter table",
                ("nft", "list", "table", "inet", f"{prefix}_filter"),
            ),
            DiagnosticProbe("nft nat table", ("nft", "list", "table", "ip", f"{prefix}_nat")),
            DiagnosticProbe("ss listeners", ("ss", "-lntup")),
            DiagnosticProbe("occtl users", tuple(occtl.occtl_argv("show", "users"))),
            DiagnosticProbe("occtl status", tuple(occtl.occtl_argv("show", "status"))),
        ]

    def normalize(self, probe: DiagnosticProbe, result: CommandResult) -> CommandResult:
        if result.ok:
            return result
        stderr = result.stderr.lower()
        stdout = result.stdout.lower()
        if probe.name in {"nft filter table", "nft nat table"} and "no such file" in stderr:
            return CommandResult(
                result.argv,
                0,
                "project-owned nftables table is not installed yet; "
                "run korctl nft apply to create it",
                "",
                result.dry_run,
            )
        if probe.name.startswith("occtl ") and (
            "no such file" in stderr
            or "could not send message" in stderr
            or "server is offline" in stderr
            or "status: offline" in stdout
        ):
            return CommandResult(
                result.argv,
                0,
                "occtl control socket is not ready or ocserv reports offline",
                "",
                result.dry_run,
            )
        return result

    def run(self, *, dry_run: bool = False) -> dict[str, CommandResult]:
        probes = self.probes()

        def execute(probe: DiagnosticProbe) -> tuple[str, CommandResult]:
            result = self.runner.run(
                list(probe.argv),
                timeout=30,
                check=False,
                dry_run=dry_run,
            )
            return probe.name, self.normalize(probe, result)

        # Probes are independent subprocess calls; running them on a thread
        # pool instead of sequentially cuts total latency from the sum of
        # every probe's runtime down to roughly the slowest single one.
        with ThreadPoolExecutor(max_workers=len(probes)) as executor:
            return dict(executor.map(execute, probes))
