from __future__ import annotations

import socket
from pathlib import Path

import pytest

from kornode import healthcheck
from kornode.config.models import AppConfig


def test_healthcheck_accepts_intentionally_disabled_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = AppConfig.model_validate({"server": {"enabled": False}})
    monkeypatch.setattr(healthcheck, "load_config", lambda: config)

    assert healthcheck.check() is True


def test_healthcheck_requires_runtime_socket_when_web_is_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "server": {"enabled": True}}
    )
    monkeypatch.setattr(healthcheck, "load_config", lambda: config)

    assert healthcheck.check() is False

    runtime_socket = socket.socket(socket.AF_UNIX)
    runtime_socket.bind(str(tmp_path / "occtl.sock"))
    try:
        assert healthcheck.check() is True
    finally:
        runtime_socket.close()


@pytest.mark.parametrize(
    ("listen", "expected_host"),
    [
        ("127.207.207.1", "127.207.207.1"),
        ("0.0.0.0", "127.0.0.1"),
    ],
)
def test_healthcheck_connects_to_the_configured_listen_address(
    monkeypatch: pytest.MonkeyPatch,
    listen: str,
    expected_host: str,
) -> None:
    config = AppConfig.model_validate(
        {
            "web": {
                "enabled": True,
                "listen": listen,
                "tls": False,
                "allow_insecure_http": True,
                "admin_password": "x",
            }
        }
    )
    monkeypatch.setattr(healthcheck, "load_config", lambda: config)

    seen_hosts: list[str] = []

    class FakeResponse:
        status = 200

    class FakeConnection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            seen_hosts.append(host)

        def request(self, method: str, path: str) -> None:
            pass

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(healthcheck.http.client, "HTTPConnection", FakeConnection)

    assert healthcheck.check() is True
    assert seen_hosts == [expected_host]
