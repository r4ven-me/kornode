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
        self, sysctl_keys: list[str], foreign_chains: object = ()
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
