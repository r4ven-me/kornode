from __future__ import annotations

import pytest

from kornode import cli
from kornode.config.models import AppConfig


class FakeNetService:
    wakes = 0

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def wake(self) -> bool:
        FakeNetService.wakes += 1
        return True


def test_server_hook_wakes_the_reconciler_for_a_new_ocserv_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeNetService.wakes = 0
    monkeypatch.setenv("DEVICE", "vpns0")
    monkeypatch.setattr(cli, "get_config", lambda: AppConfig.model_validate({}))
    monkeypatch.setattr(cli, "NetService", FakeNetService)

    cli.server_hook()

    assert FakeNetService.wakes == 1


def test_server_hook_fails_without_device(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEVICE", raising=False)

    with pytest.raises(cli.typer.Exit) as exc:
        cli.server_hook()

    assert exc.value.exit_code == 1
