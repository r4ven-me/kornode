from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from tests.netlab.lab import Lab
from tests.netlab.topology import Topology, build_default_topology


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


@pytest.fixture
def lab() -> Iterator[Lab]:
    lab_instance = Lab()
    try:
        yield lab_instance
    finally:
        lab_instance.teardown()


@pytest.fixture
def topology() -> Iterator[Topology]:
    lab_instance = Lab()
    topology_instance: Topology | None = None
    try:
        topology_instance = build_default_topology(lab_instance)
        yield topology_instance
    finally:
        if topology_instance is not None:
            topology_instance.stop()
        lab_instance.teardown()
