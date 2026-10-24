"""Boot fail-closed: ocserv starts only after the reconciler converged once."""

from __future__ import annotations

from typing import Any

from kornode.services.net import NetService


class _Net(NetService):
    def __init__(self, replies: list[dict[str, Any]]) -> None:
        self.replies = replies

    def status(self) -> dict[str, Any]:
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


def _clock() -> Any:
    now = [0.0]

    def clock() -> float:
        return now[0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    return clock, sleep


def test_waits_for_a_converged_pass_without_error() -> None:
    clock, sleep = _clock()
    net = _Net(
        [
            {"running": False},
            {"running": True, "passes": 0, "schema_hash": None},
            {"running": True, "passes": 1, "schema_hash": None, "last_error": "OSError: boom"},
            {"running": True, "passes": 2, "schema_hash": "abc", "last_error": None},
        ]
    )
    assert net.wait_ready(clock=clock, sleep=sleep) is True
    assert clock() == 1.5


def test_a_failing_reconciler_keeps_ocserv_waiting_and_reports_why() -> None:
    clock, sleep = _clock()
    lines: list[str] = []
    net = _Net([{"running": True, "schema_hash": "old", "last_error": "Error: nft"}])
    assert net.wait_ready(clock=clock, sleep=sleep, report=lines.append, timeout=65) is False
    assert lines and all("Error: nft" in line for line in lines)


def test_supervisor_starts_ocserv_through_the_gate() -> None:
    from pathlib import Path

    template = Path(__file__).resolve().parents[1] / "templates" / "supervisor.conf.j2"
    text = template.read_text(encoding="utf-8")
    assert "command=/usr/local/bin/korctl net wait-ready -- /usr/sbin/ocserv -f" in text
