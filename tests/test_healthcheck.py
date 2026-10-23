from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import yaml

from kornode import healthcheck
from kornode.config.models import AppConfig
from kornode.services.supervisor_rpc import SupervisorRpcError

_NOW = 1000.0


@dataclass
class Probes:
    config: AppConfig
    processes: dict[str, str]
    reply: Any
    rpc_error: Exception | None = None
    reconciler_error: Exception | None = None
    web_error: Exception | None = None
    web_status: int = 200
    timeouts: list[float] = field(default_factory=list)
    requests: list[tuple[str, str]] = field(default_factory=list)
    connections: list[tuple[str, int, ssl.SSLContext | None]] = field(default_factory=list)
    closed: int = 0


@pytest.fixture
def probes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Probes:
    config = AppConfig.model_validate({"system": {"generated_dir": tmp_path}})
    state = Probes(
        config=config,
        processes={
            name: "RUNNING"
            for name in (
                "reconciler",
                "ocserv",
                "dnsmasq",
                "api",
                "control-api",
                "upstream-watchdog",
            )
        },
        reply={
            "ok": True,
            "status": {
                "passes": 1,
                "last_pass_at": _NOW,
                "last_error": None,
                "consecutive_errors": 0,
                "last_plan_size": 7,
                "schema_hash": "structural-schema-only",
            },
        },
    )
    monkeypatch.delenv("KORNODE_CONFIG", raising=False)
    monkeypatch.setattr(healthcheck, "load_config", lambda: state.config)
    monkeypatch.setattr(time, "time", lambda: _NOW)

    class Rpc:
        def __init__(self, path: Path, timeout: float) -> None:
            assert path == state.config.generated_path("supervisor.sock")
            state.timeouts.append(timeout)

        def get_all_process_info(self) -> list[dict[str, str]]:
            if state.rpc_error:
                raise state.rpc_error
            return [{"name": name, "statename": status} for name, status in state.processes.items()]

    def reconciler(path: Path, op: str, *, timeout: float) -> Any:
        assert path == state.config.generated_path("reconciler.sock")
        assert op == "status"  # The healthcheck must never request apply/wake.
        state.timeouts.append(timeout)
        if state.reconciler_error:
            raise state.reconciler_error
        return state.reply

    class Connection:
        def __init__(
            self,
            host: str,
            port: int,
            timeout: float,
            *,
            context: ssl.SSLContext | None = None,
        ) -> None:
            state.connections.append((host, port, context))
            state.timeouts.append(timeout)

        def request(self, method: str, path: str) -> None:
            state.requests.append((method, path))

        def getresponse(self) -> Any:
            if state.web_error:
                raise state.web_error
            return type("Response", (), {"status": state.web_status})()

        def close(self) -> None:
            state.closed += 1

    monkeypatch.setattr(healthcheck, "SupervisorRpcClient", Rpc)
    monkeypatch.setattr(healthcheck, "control_request", reconciler)
    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    return state


def _web_config(probes: Probes, **overrides: Any) -> None:
    probes.config = AppConfig.model_validate(
        {
            "system": {"generated_dir": probes.config.system.generated_dir},
            "web": {"enabled": True, "admin_password": "test-only", **overrides},
        }
    )


def test_intentionally_disabled_services_still_require_a_ready_core(probes: Probes) -> None:
    probes.config.server.enabled = False
    probes.processes = {"reconciler": "RUNNING"}
    assert healthcheck.check() is True
    assert probes.connections == []
    probes.processes.clear()
    assert healthcheck.check() is False


@pytest.mark.parametrize(
    "name", ["occtl.sock", "ocserv.sock.stale", "supervisor.sock", "reconciler.sock"]
)
def test_stale_socket_files_are_not_readiness(
    tmp_path: Path,
    probes: Probes,
    name: str,
) -> None:
    path = tmp_path / name
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(str(path))
    assert path.is_socket()  # Bound then closed, never a real host daemon.
    if name == "reconciler.sock":
        probes.reconciler_error = ConnectionRefusedError("stale")
    else:
        probes.rpc_error = SupervisorRpcError("cannot reach supervisord")
    assert healthcheck.check() is False


@pytest.mark.parametrize(
    "process", ["reconciler", "ocserv", "dnsmasq", "api", "control-api", "upstream-watchdog"]
)
@pytest.mark.parametrize("state", ["missing", "STARTING", "FATAL"])
def test_each_configured_critical_process_must_be_running(
    probes: Probes,
    process: str,
    state: str,
) -> None:
    _web_config(probes)
    probes.config.control.enabled = True
    data = probes.config.model_dump()
    data["upstream"] = {
        "enabled": True,
        "profiles": [
            {"name": "office", "server": "192.0.2.1", "username": "alice"},
        ],
    }
    probes.config = AppConfig.model_validate(data)
    if state == "missing":
        probes.processes.pop(process)
    else:
        probes.processes[process] = state
    assert healthcheck.check() is False
    assert probes.connections == []


def test_control_is_required_independently_of_web_and_vpn(probes: Probes) -> None:
    probes.config.server.enabled = False
    probes.config.control.enabled = True
    probes.processes = {"reconciler": "RUNNING"}
    assert healthcheck.check() is False
    probes.processes["control-api"] = "RUNNING"
    assert healthcheck.check() is True


@pytest.mark.parametrize(
    "patch",
    [
        {"passes": 0},
        {"passes": True},
        {"passes": -1},
        {"last_pass_at": None},
        {"last_pass_at": "1000"},
        {"last_pass_at": True},
        {"last_pass_at": _NOW - 31},
        {"last_pass_at": _NOW + 1},
        {"last_pass_at": float("inf")},
        {"last_pass_at": float("nan")},
        {"last_error": "configuration provider failed"},
        {"consecutive_errors": 1},
        {"consecutive_errors": False},
    ],
)
def test_unstarted_failed_stale_or_malformed_reconciliation_is_not_ready(
    probes: Probes,
    patch: dict[str, Any],
) -> None:
    probes.reply["status"].update(patch)
    assert healthcheck.check() is False


@pytest.mark.parametrize(
    "reply",
    [
        {},
        [],
        None,
        {"ok": False},
        {"ok": True},
        {"ok": True, "status": []},
        {"ok": True, "status": {}},
    ],
)
def test_invalid_reconciler_reply_fails_closed(probes: Probes, reply: Any) -> None:
    probes.reply = reply
    assert healthcheck.check() is False


def test_first_successful_pass_is_ready_without_startup_sleep_or_empty_second_pass(
    probes: Probes,
) -> None:
    # One successful pass that applied changes is sufficient. schema_hash is
    # structural, not a claim that every byte of the current YAML was applied.
    assert probes.reply["status"]["passes"] == 1
    assert probes.reply["status"]["last_plan_size"] > 0
    assert healthcheck.check() is True
    probes.reply["status"]["last_pass_at"] = _NOW - 30
    assert healthcheck.check() is True


def test_web_liveness_does_not_override_failed_readiness(probes: Probes) -> None:
    _web_config(probes)
    assert healthcheck._web_alive(probes.config) is True
    probes.reply["status"]["last_error"] = "kernel apply failed"
    assert healthcheck.check() is False
    assert probes.requests == [("GET", "/healthz")]


@pytest.mark.parametrize(
    ("listen", "host"),
    [
        ("127.207.207.1", "127.207.207.1"),
        ("0.0.0.0", "127.0.0.1"),
        ("::", "::1"),
        ("::1", "::1"),
    ],
)
@pytest.mark.parametrize("tls", [False, True])
def test_web_liveness_uses_configured_address_and_closes_connection(
    probes: Probes,
    listen: str,
    host: str,
    tls: bool,
) -> None:
    _web_config(probes, listen=listen, tls=tls, allow_insecure_http=not tls)
    assert healthcheck.check() is True
    actual_host, port, context = probes.connections[0]
    assert actual_host == host and port == probes.config.web.port
    assert (context is not None) == tls
    assert probes.requests == [("GET", "/healthz")]
    assert probes.closed == 1
    assert all(0 < timeout <= 1 for timeout in probes.timeouts)


@pytest.mark.parametrize(
    "error", [TimeoutError("secret"), http.client.RemoteDisconnected("secret")]
)
def test_failed_web_probe_closes_connection_without_logging_details(
    probes: Probes,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
) -> None:
    _web_config(probes)
    probes.web_error = error
    assert healthcheck.check() is False
    assert probes.closed == 1
    assert capsys.readouterr() == ("", "")


def test_non_successful_web_response_is_not_ready(probes: Probes) -> None:
    _web_config(probes)
    probes.web_status = 503
    assert healthcheck.check() is False
    assert probes.closed == 1


@pytest.mark.parametrize("error", [TimeoutError("secret"), ValueError("secret")])
def test_unresponsive_or_malformed_reconciler_fails_without_logging_details(
    probes: Probes,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
) -> None:
    probes.reconciler_error = error
    assert healthcheck.check() is False
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "error", [ValueError("secret"), yaml.YAMLError("secret"), PermissionError("secret")]
)
def test_invalid_or_unreadable_config_is_unhealthy_without_secret_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
) -> None:
    def broken_config() -> AppConfig:
        raise error

    monkeypatch.delenv("KORNODE_CONFIG", raising=False)
    monkeypatch.setattr(healthcheck, "load_config", broken_config)
    assert healthcheck.check() is False
    assert capsys.readouterr() == ("", "")


def test_external_upstream_outage_is_not_a_container_health_failure(probes: Probes) -> None:
    probes.config.server.enabled = False
    data = probes.config.model_dump()
    data["upstream"] = {
        "enabled": True,
        "profiles": [
            {"name": "office", "server": "192.0.2.1", "username": "alice"},
        ],
    }
    probes.config = AppConfig.model_validate(data)
    probes.processes = {"reconciler": "RUNNING", "upstream-watchdog": "RUNNING"}
    # The tunnel can be down while the local policy has successfully installed
    # unreachable/fail-closed routes. Do not probe check_host or tunnel health.
    probes.reply["status"]["last_plan_size"] = 3
    assert healthcheck.check() is True
    assert probes.connections == []


@pytest.mark.parametrize(("healthy", "exit_code"), [(True, 0), (False, 1)])
def test_main_returns_readiness_exit_status(
    monkeypatch: pytest.MonkeyPatch,
    healthy: bool,
    exit_code: int,
) -> None:
    monkeypatch.setattr(healthcheck, "check", lambda: healthy)
    with pytest.raises(SystemExit) as exc:
        healthcheck.main()
    assert exc.value.code == exit_code


def test_healthcheck_uses_the_same_custom_config_path_as_runtime(
    probes: Probes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = str(probes.config.system.generated_dir / "custom-config.yaml")
    seen: list[str] = []

    def load(config_path: str) -> AppConfig:
        seen.append(config_path)
        return probes.config

    monkeypatch.setenv("KORNODE_CONFIG", path)
    monkeypatch.setattr(healthcheck, "load_config", load)
    assert healthcheck.check() is True
    assert seen == [path]


@pytest.mark.parametrize("field", ["passes", "last_pass_at", "last_error", "consecutive_errors"])
def test_incomplete_reconciler_status_does_not_imply_success(probes: Probes, field: str) -> None:
    probes.reply["status"].pop(field)
    assert healthcheck.check() is False
