from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from kornode.config.models import AppConfig
from kornode.renderers import OcservConfigRenderer
from kornode.services.command import CommandResult
from kornode.services.config import ConfigService
from kornode.services.ocserv_reload import restart_required
from kornode.services.supervisor_rpc import SupervisorRpcClient, SupervisorRpcError

_NOT_RUNNING_FAULTS = ("NOT_RUNNING", "STOPPED", "already stopped")
_ALREADY_STARTED_FAULTS = ("ALREADY_STARTED", "SPAWN_ERROR")


@dataclass(frozen=True)
class ProcessStatus:
    name: str
    state: str
    description: str


class ServerService:
    def __init__(
        self,
        config: AppConfig,
        rpc_client: SupervisorRpcClient | None = None,
        config_service: ConfigService | None = None,
    ) -> None:
        self.config = config
        self.rpc = rpc_client or SupervisorRpcClient(config.generated_path("supervisor.sock"))
        self.config_service = config_service or ConfigService()

    def start(self, *, dry_run: bool = False) -> CommandResult:
        if dry_run:
            return _dry_run_result("startProcess", "ocserv")
        if not self.config.server.enabled:
            # With server.enabled false there is no [program:ocserv] in the
            # supervisor config, so startProcess would only answer BAD_NAME.
            return CommandResult(
                ("supervisor-rpc", "startProcess", "ocserv"),
                1,
                "",
                "ocserv is disabled: set server.enabled to true first",
            )
        self.config_service.write_rendered_files(self.config)
        return _run(lambda: self.rpc.start_process("ocserv"), "startProcess", "ocserv")

    def stop(self, *, dry_run: bool = False) -> CommandResult:
        if dry_run:
            return _dry_run_result("stopProcess", "ocserv")
        return _run(lambda: self.rpc.stop_process("ocserv"), "stopProcess", "ocserv")

    def reload(self, *, dry_run: bool = False) -> CommandResult:
        if dry_run:
            return _dry_run_result("signalProcess", "ocserv", "HUP")
        return _run(
            lambda: self.rpc.signal_process("ocserv", "HUP"),
            "signalProcess",
            "ocserv",
            "HUP",
        )

    def restart(self, *, dry_run: bool = False) -> CommandResult:
        if dry_run:
            return _dry_run_result("restartProcess", "ocserv")
        self.config_service.write_rendered_files(self.config)

        def _restart() -> None:
            try:
                self.rpc.stop_process("ocserv")
            except SupervisorRpcError as exc:
                if not _is_expected_fault(exc, _NOT_RUNNING_FAULTS):
                    raise
            self.rpc.start_process("ocserv")

        return _run(_restart, "restartProcess", "ocserv")

    def apply_config_change(
        self,
        previous_ocserv_conf: str,
        *,
        dry_run: bool = False,
    ) -> CommandResult | None:
        """Make the running ocserv use the config saved as ``self.config``.

        RUNTIME: talks to supervisord. ``previous_ocserv_conf`` is the
        ocserv.conf the process was running with. Settings SIGHUP can't
        apply (auth methods, ports, device) get a full restart, which drops
        the active VPN sessions; everything else a reload, which keeps them.
        Returns None when the ocserv server is disabled.
        """
        if not self.config.server.enabled:
            return None
        current = OcservConfigRenderer().render(self.config)
        if restart_required(previous_ocserv_conf, current):
            return self.restart(dry_run=dry_run)
        return self.reload(dry_run=dry_run)

    def status(self) -> CommandResult:
        try:
            info = self.rpc.get_all_process_info()
        except SupervisorRpcError as exc:
            return CommandResult(("supervisor-rpc", "getAllProcessInfo"), 1, "", str(exc))
        stdout = "\n".join(_format_process_line(entry) for entry in info)
        return CommandResult(("supervisor-rpc", "getAllProcessInfo"), 0, stdout, "")

    def processes(self) -> list[ProcessStatus]:
        status = self.status()
        observed = {process.name: process for process in self.parse_processes(status)}
        processes: list[ProcessStatus] = []
        for name in self.expected_process_names():
            process = observed.get(name)
            if process is not None:
                processes.append(process)
                continue
            state, description = self.missing_process_state(name)
            processes.append(ProcessStatus(name=name, state=state, description=description))
        return processes

    def process_action(
        self,
        action: str,
        process: str,
        *,
        dry_run: bool = False,
    ) -> CommandResult:
        if action not in {"start", "stop", "restart", "status"}:
            raise ValueError("unsupported supervisor action")
        if not self.is_managed_process(process):
            raise ValueError("unsupported managed process")
        if dry_run:
            return _dry_run_result(action, process)
        if action == "start":
            return _run(lambda: self.rpc.start_process(process), "startProcess", process)
        if action == "stop":
            return _run(lambda: self.rpc.stop_process(process), "stopProcess", process)
        if action == "restart":

            def _restart() -> None:
                try:
                    self.rpc.stop_process(process)
                except SupervisorRpcError as exc:
                    if not _is_expected_fault(exc, _NOT_RUNNING_FAULTS):
                        raise
                self.rpc.start_process(process)

            return _run(_restart, "restartProcess", process)
        try:
            info = self.rpc.get_process_info(process)
        except SupervisorRpcError as exc:
            return CommandResult(("supervisor-rpc", "getProcessInfo", process), 1, "", str(exc))
        return CommandResult(
            ("supervisor-rpc", "getProcessInfo", process),
            0,
            _format_process_line(info),
            "",
        )

    @staticmethod
    def is_managed_process(process: str) -> bool:
        return process in {"api", "ocserv", "dnsmasq", "certbot-renew", "upstream-watchdog"}

    def expected_process_names(self) -> list[str]:
        return ["api", "ocserv", "dnsmasq", "certbot-renew", "upstream-watchdog"]

    def missing_process_state(self, name: str) -> tuple[str, str]:
        if name == "dnsmasq" and not self.config.dns_tunnel_active():
            return "DISABLED", "internal DNS and split DNS are disabled"
        if name == "certbot-renew" and not self.config.certificates.letsencrypt.enabled:
            return "DISABLED", "Let's Encrypt is disabled"
        if name == "certbot-renew" and not self.config.certificates.letsencrypt.auto_renew_enabled:
            return "DISABLED", "Let's Encrypt auto-renew is disabled"
        if name == "upstream-watchdog" and not self.config.upstream.enabled:
            return "DISABLED", "upstream is disabled"
        return "UNKNOWN", "not reported by supervisor"

    @staticmethod
    def parse_processes(result: CommandResult) -> list[ProcessStatus]:
        processes: list[ProcessStatus] = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            name = parts[0]
            state = parts[1]
            description = parts[2] if len(parts) > 2 else ""
            processes.append(ProcessStatus(name=name, state=state, description=description))
        return processes


def _dry_run_result(*argv: str) -> CommandResult:
    return CommandResult(("supervisor-rpc", *argv), 0, "", "", dry_run=True)


def _run(action: Callable[[], None], *argv: str) -> CommandResult:
    try:
        action()
    except SupervisorRpcError as exc:
        return CommandResult(("supervisor-rpc", *argv), 1, "", str(exc))
    return CommandResult(("supervisor-rpc", *argv), 0, "", "")


def _is_expected_fault(exc: SupervisorRpcError, markers: tuple[str, ...]) -> bool:
    text = str(exc).upper()
    return any(marker.upper() in text for marker in markers)


def _format_process_line(entry: dict[str, object]) -> str:
    name = entry.get("name", "")
    statename = entry.get("statename", "UNKNOWN")
    description = entry.get("description", "")
    return f"{name} {statename} {description}".rstrip()
