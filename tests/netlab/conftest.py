from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    if os.geteuid() == 0:
        return
    skip_netlab = pytest.mark.skip(reason="netlab tests require root for Linux network namespaces")
    for item in items:
        if item.get_closest_marker("netlab") is not None:
            item.add_marker(skip_netlab)
