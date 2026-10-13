from __future__ import annotations

import pytest

from kornode import cli
from kornode.config.models import AppConfig
from kornode.services.net import NetApplyError


class FakeNetService:
    applies = 0

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def converge(self) -> dict[str, object]:
        FakeNetService.applies += 1
        return {"applied": True}


def test_server_hook_waits_for_a_reconciler_pass_for_a_new_ocserv_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeNetService.applies = 0
    monkeypatch.setenv("DEVICE", "vpns0")
    monkeypatch.setattr(cli, "get_config", lambda: AppConfig.model_validate({}))
    monkeypatch.setattr(cli, "NetService", FakeNetService)

    cli.server_hook()

    assert FakeNetService.applies == 1


def test_server_hook_fails_without_device(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEVICE", raising=False)

    with pytest.raises(cli.typer.Exit) as exc:
        cli.server_hook()

    assert exc.value.exit_code == 1


def test_server_hook_reports_but_survives_a_failed_pass(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Failing(FakeNetService):
        def converge(self) -> dict[str, object]:
            # converge, not apply: a pass that ran but failed is reported too.
            raise NetApplyError("kernel did not converge: ApplyError: timed out")

    monkeypatch.setenv("DEVICE", "vpns0")
    monkeypatch.setattr(cli, "get_config", lambda: AppConfig.model_validate({}))
    monkeypatch.setattr(cli, "NetService", Failing)

    cli.server_hook()  # must not raise: ocserv needs exit 0 from the script

    assert "timed out" in capsys.readouterr().err
