from __future__ import annotations

from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig
from kornode.services.server import ServerService
from kornode.services.supervisor_rpc import SupervisorRpcError


class FakeRpcClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.all_process_info: list[dict[str, Any]] = []
        self.fail_stop_with: str | None = None

    def start_process(self, name: str) -> None:
        self.calls.append(("startProcess", name))

    def stop_process(self, name: str) -> None:
        self.calls.append(("stopProcess", name))
        if self.fail_stop_with:
            raise SupervisorRpcError(self.fail_stop_with)

    def signal_process(self, name: str, signal_name: str) -> None:
        self.calls.append(("signalProcess", name, signal_name))

    def get_process_info(self, name: str) -> dict[str, Any]:
        self.calls.append(("getProcessInfo", name))
        return {"name": name, "statename": "RUNNING", "description": "pid 1, uptime 0:00:01"}

    def get_all_process_info(self) -> list[dict[str, Any]]:
        self.calls.append(("getAllProcessInfo",))
        return self.all_process_info


def test_server_start_stop_restart_use_supervisor_rpc(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "generated_dir": tmp_path,
                "data_dir": tmp_path,
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    rpc = FakeRpcClient()
    service = ServerService(config, rpc_client=rpc)

    service.start(dry_run=True)
    assert rpc.calls == []

    service.stop()
    service.restart()

    assert rpc.calls == [
        ("stopProcess", "ocserv"),
        ("stopProcess", "ocserv"),
        ("startProcess", "ocserv"),
    ]


def test_server_restart_ignores_not_running_fault(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "generated_dir": tmp_path,
                "data_dir": tmp_path,
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    rpc = FakeRpcClient()
    rpc.fail_stop_with = "NOT_RUNNING"
    service = ServerService(config, rpc_client=rpc)

    result = service.restart()

    assert result.ok
    assert rpc.calls == [("stopProcess", "ocserv"), ("startProcess", "ocserv")]


def test_server_reload_signals_hup(tmp_path: Path) -> None:
    config = AppConfig.model_validate({"system": {"generated_dir": tmp_path}})
    rpc = FakeRpcClient()
    service = ServerService(config, rpc_client=rpc)

    result = service.reload()

    assert result.ok
    assert rpc.calls == [("signalProcess", "ocserv", "HUP")]


def test_server_processes_report_managed_processes_only(tmp_path: Path) -> None:
    # server.enabled off: otherwise dnsmasq is expected to run (the resolver
    # is mandatory while server.enabled) and would show "UNKNOWN" rather
    # than "DISABLED" for not being reported by the fake supervisor.
    config = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "server": {"enabled": False}}
    )
    rpc = FakeRpcClient()
    rpc.all_process_info = [
        {"name": "api", "statename": "RUNNING", "description": "pid 1, uptime 0:00:01"},
        {"name": "ocserv", "statename": "RUNNING", "description": "pid 2, uptime 0:00:01"},
    ]
    service = ServerService(config, rpc_client=rpc)

    processes = service.processes()

    assert [(item.name, item.state) for item in processes] == [
        ("api", "RUNNING"),
        ("ocserv", "RUNNING"),
        ("dnsmasq", "DISABLED"),
        ("certbot-renew", "DISABLED"),
        ("upstream-watchdog", "DISABLED"),
    ]


def test_server_status_reports_rpc_failure(tmp_path: Path) -> None:
    config = AppConfig.model_validate({"system": {"generated_dir": tmp_path}})

    class BrokenRpcClient(FakeRpcClient):
        def get_all_process_info(self) -> list[dict[str, Any]]:
            raise SupervisorRpcError(
                "cannot reach supervisord: [Errno 2] No such file or directory"
            )

    service = ServerService(config, rpc_client=BrokenRpcClient())

    result = service.status()

    assert not result.ok
    assert "cannot reach supervisord" in result.stderr


def _config(tmp_path: Path, **overrides: Any) -> AppConfig:
    data: dict[str, Any] = {
        "system": {
            "generated_dir": tmp_path,
            "data_dir": tmp_path,
            "secrets_dir": tmp_path / "secrets",
        }
    }
    data.update(overrides)
    return AppConfig.model_validate(data)


def test_auth_method_change_restarts_ocserv(tmp_path: Path) -> None:
    from kornode.renderers import OcservConfigRenderer

    before = _config(tmp_path, auth={"password": {"enabled": True}})
    after = _config(
        tmp_path,
        auth={"password": {"enabled": False}, "certificate": {"enabled": True}},
    )
    rpc = FakeRpcClient()

    result = ServerService(after, rpc_client=rpc).apply_config_change(
        OcservConfigRenderer().render(before)
    )

    assert result is not None and result.ok
    assert rpc.calls == [("stopProcess", "ocserv"), ("startProcess", "ocserv")]


def test_reloadable_change_only_sends_sighup(tmp_path: Path) -> None:
    from kornode.renderers import OcservConfigRenderer

    before = _config(tmp_path, server={"max_clients": 10})
    after = _config(tmp_path, server={"max_clients": 20})
    rpc = FakeRpcClient()

    ServerService(after, rpc_client=rpc).apply_config_change(OcservConfigRenderer().render(before))

    assert rpc.calls == [("signalProcess", "ocserv", "HUP")]


def test_apply_config_change_skips_disabled_ocserv(tmp_path: Path) -> None:
    config = _config(tmp_path, server={"enabled": False})
    rpc = FakeRpcClient()

    assert ServerService(config, rpc_client=rpc).apply_config_change("") is None
    assert rpc.calls == []


def test_server_start_reports_failure_when_ocserv_is_disabled(tmp_path: Path) -> None:
    # With server.enabled false supervisor has no ocserv program, so the start
    # must not reach startProcess (it would only say BAD_NAME) -- report a
    # clear non-zero result instead, which the panel shows as an error.
    config = AppConfig.model_validate(
        {
            "server": {"enabled": False},
            "system": {
                "generated_dir": tmp_path,
                "data_dir": tmp_path,
                "secrets_dir": tmp_path / "secrets",
            },
        }
    )
    rpc = FakeRpcClient()

    result = ServerService(config, rpc_client=rpc).start()

    assert rpc.calls == []
    assert result.returncode == 1
    assert "server.enabled" in result.stderr


def test_server_stop_and_restart_report_failure_when_ocserv_is_disabled(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "server": {"enabled": False},
            "system": {
                "generated_dir": tmp_path,
                "data_dir": tmp_path,
                "secrets_dir": tmp_path / "secrets",
            },
        }
    )
    rpc = FakeRpcClient()
    service = ServerService(config, rpc_client=rpc)

    stopped = service.stop()
    restarted = service.restart()

    assert rpc.calls == []
    assert stopped.returncode == 1
    assert restarted.returncode == 1
    assert "server.enabled" in stopped.stderr
    assert "server.enabled" in restarted.stderr
