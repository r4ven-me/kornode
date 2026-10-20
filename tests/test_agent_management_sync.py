from __future__ import annotations

import threading
from pathlib import Path

from tests.test_fabric_groups import _config, _registry

from kornode.services.fabric_groups import FabricGroupsService


def test_concurrent_sync_cannot_resurrect_a_revoked_agent_guard(tmp_path: Path) -> None:
    config = _config(tmp_path)
    registry = _registry(config)
    registry.create_node(id=3, name="branch", state="active")
    first, second = FabricGroupsService(config), FabricGroupsService(config)
    captured, release, second_started, second_read = (threading.Event() for _ in range(4))
    original_first, original_second = first.nodes, second.nodes
    errors: list[BaseException] = []

    def old_snapshot():
        nodes = original_first()
        captured.set()
        assert release.wait(3)
        return nodes

    def new_snapshot():
        second_read.set()
        return original_second()

    first.nodes = old_snapshot  # type: ignore[method-assign]
    second.nodes = new_snapshot  # type: ignore[method-assign]

    def run(service: FabricGroupsService, start: threading.Event | None = None) -> None:
        if start:
            start.set()
        try:
            service.sync()
        except BaseException as exc:
            errors.append(exc)

    t1 = threading.Thread(target=run, args=(first,))
    t2 = threading.Thread(target=run, args=(second, second_started))
    t1.start()
    try:
        assert captured.wait(3)
        registry.set_state(3, "revoked")
        t2.start()
        assert second_started.wait(3)
        assert not second_read.wait(0.05), "fresh writer must wait before reading its snapshot"
    finally:
        release.set()
        t1.join(3)
        if t2.ident:
            t2.join(3)
        registry.conn.close()
    assert not t1.is_alive() and not t2.is_alive() and not errors
    assert second_read.is_set()
    assert not (first.user_dir() / "agent-3").exists()
