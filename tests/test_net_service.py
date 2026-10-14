from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.test_netinputs import FakeRunner

from kornode import cli
from kornode.api import routes_net
from kornode.api.app import create_app
from kornode.config.models import AppConfig
from kornode.net.diff import Plan, apply_to_state
from kornode.net.state import ActualState
from kornode.services.net import NetService


class FakeKernel:
    def __init__(self) -> None:
        self.state = ActualState()

    def read(
        self, sysctl_keys: list[str], foreign_chains: object = (), address_devs: object = ()
    ) -> ActualState:
        return self.state

    def apply(self, plan: Plan) -> None:
        self.state = apply_to_state(self.state, plan)

    def route_get(self, dst: str, mark: int | None, src: str | None = None) -> str | None:
        return "oc-middle0"


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
                "log_dir": tmp_path / "logs",
            },
            "web": {"admin_password": "secret"},
            "upstream": {
                "enabled": True,
                "profiles": [{"name": "main", "server": "203.0.113.2", "username": "u"}],
            },
            "routing": {"client_policy": "full"},
        }
    )


def _service(tmp_path: Path, kernel: FakeKernel | None = None) -> NetService:
    service = NetService(_config(tmp_path), runner=FakeRunner(), kernel=kernel or FakeKernel())  # type: ignore[arg-type]
    return service


def test_plan_lists_exits_and_ops(tmp_path: Path) -> None:
    plan = _service(tmp_path).plan()

    assert plan["exits"][0]["name"] == "upstream:main"
    assert plan["exits"][0]["mark"] == "0x0c000100"
    texts = [op["text"] for op in plan["ops"]]
    assert "add rule ipv4 90: from all lookup main suppress_prefixlength 0" in texts
    assert any(text.startswith("load nft ruleset") for text in texts)


def test_apply_without_a_reconciler_runs_one_pass_then_plan_is_empty(tmp_path: Path) -> None:
    kernel = FakeKernel()
    service = _service(tmp_path, kernel)

    result = service.apply()

    assert result["via"] == "in-process" and result["ops"]
    assert service.plan()["ops"] == []


def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    kernel = FakeKernel()

    result = _service(tmp_path, kernel).apply(dry_run=True)

    assert result["dry_run"] is True and result["ops"]
    assert kernel.state == ActualState()


def test_explain_uses_the_kernel_check(tmp_path: Path) -> None:
    decision = _service(tmp_path).explain("10.10.10.5", "1.1.1.1")

    assert decision["matched_rule"]["via"] == "upstream:main"
    assert decision["kernel_check"].endswith("-> dev oc-middle0")


def test_status_without_reconciler(tmp_path: Path) -> None:
    assert _service(tmp_path).status() == {"running": False}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    kernel = FakeKernel()
    monkeypatch.setattr(
        routes_net,
        "NetService",
        lambda config: NetService(config, runner=FakeRunner(), kernel=kernel),  # type: ignore[arg-type]
    )
    return TestClient(create_app(config=_config(tmp_path)))


def test_api_plan_apply_explain(client: TestClient) -> None:
    auth = ("admin", "secret")

    assert client.get("/api/net/plan", auth=auth).json()["ops"]
    assert client.post("/api/net/apply", json={}, auth=auth).json()["via"] == "in-process"
    assert client.get("/api/net/plan", auth=auth).json()["ops"] == []
    explained = client.post(
        "/api/net/explain", json={"src": "10.10.10.5", "dst": "1.1.1.1"}, auth=auth
    ).json()
    assert explained["from_class"] == "clients"
    bad = client.post("/api/net/explain", json={"src": "nope", "dst": "1.1.1.1"}, auth=auth)
    assert bad.status_code == 422


def test_api_requires_admin(client: TestClient) -> None:
    assert client.get("/api/net/plan").status_code == 401


def test_cli_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                  capsys: pytest.CaptureFixture[str]) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(cli, "get_config", lambda: config)
    monkeypatch.setattr(
        cli, "NetService", lambda c: NetService(c, runner=FakeRunner(), kernel=FakeKernel())  # type: ignore[arg-type]
    )

    cli.net_plan(as_json=False)

    out: Any = capsys.readouterr().out
    assert "exit upstream:main: mark 0x0c000100 table 12001 (up)" in out
    assert "add rule ipv4 90: from all lookup main suppress_prefixlength 0" in out


class FailingKernel(FakeKernel):
    def apply(self, plan: Plan) -> None:
        raise OSError("read-only /proc/sys")


def test_converge_raises_when_the_pass_failed(tmp_path: Path) -> None:
    from kornode.services.net import NetApplyError

    service = _service(tmp_path, FailingKernel())

    with pytest.raises(NetApplyError, match="did not converge.*read-only /proc/sys"):
        service.converge()
    # `apply` (the CLI/API surface) still reports instead of raising.
    assert "read-only" in service.apply()["status"]["last_error"]


def test_converge_returns_the_result_when_it_worked(tmp_path: Path) -> None:
    assert _service(tmp_path).converge()["via"] == "in-process"


def test_apply_waits_for_a_running_reconciler(tmp_path: Path) -> None:
    from kornode.net.reconciler import Reconciler, serve_control
    from kornode.services.net import reconciler_socket

    config = _config(tmp_path)
    kernel = FakeKernel()
    service = NetService(config, runner=FakeRunner(), kernel=kernel)  # type: ignore[arg-type]
    reconciler = Reconciler(service.inputs.desired, kernel)
    reconciler_socket(config).parent.mkdir(parents=True)
    server = serve_control(reconciler, reconciler_socket(config))
    try:
        result = service.apply()

        assert result["via"] == "reconciler"
        assert result["status"]["running"] and result["status"]["last_error"] is None
        assert service.plan()["ops"] == []  # converged before apply() returned
    finally:
        server.shutdown()
        server.server_close()


def test_wake_without_a_reconciler_is_a_quiet_noop(tmp_path: Path) -> None:
    assert _service(tmp_path).wake() is False


def _serve(path: Path, handler: Any) -> Any:
    import socket
    import threading

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)

    def run() -> None:
        conn, _ = server.accept()
        with conn:
            conn.recv(4096)
            handler(conn)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return server


@pytest.mark.parametrize("reply", [b"\n", b'{"ok": false, "error": "unknown op"}\n'])
def test_converge_fails_closed_on_an_empty_or_refusing_reconciler(
    tmp_path: Path, reply: bytes
) -> None:
    from kornode.services.net import NetApplyError, reconciler_socket

    kernel = FakeKernel()
    service = _service(tmp_path, kernel)
    reconciler_socket(service.config).parent.mkdir(parents=True)
    server = _serve(reconciler_socket(service.config), lambda conn: conn.sendall(reply))
    try:
        with pytest.raises(NetApplyError, match="reconciler"):
            service.converge()
        assert kernel.state == ActualState()  # no second writer
    finally:
        server.close()


def test_a_reconciler_that_does_not_answer_is_not_replaced_by_a_second_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    from kornode.services import net as net_module
    from kornode.services.net import NetApplyError, reconciler_socket

    monkeypatch.setattr(net_module, "APPLY_TIMEOUT_SECONDS", 0.2)
    kernel = FakeKernel()
    service = _service(tmp_path, kernel)
    reconciler_socket(service.config).parent.mkdir(parents=True)
    release = threading.Event()
    server = _serve(reconciler_socket(service.config), lambda conn: release.wait(5))
    try:
        with pytest.raises(NetApplyError, match="did not answer"):
            service.apply()
        assert kernel.state == ActualState()
    finally:
        release.set()
        server.close()


def test_a_failed_pass_is_not_reported_as_applied(tmp_path: Path) -> None:
    result = _service(tmp_path, FailingKernel()).apply()

    assert result["applied"] is False
