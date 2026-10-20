from __future__ import annotations

import os
from collections.abc import Generator, Iterator
from typing import Any

import pytest
from tests.e2e.fleet import Cluster, Fleet
from tests.e2e.inventory import E2EError, Inventory


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--e2e-run",
        action="store_true",
        default=False,
        help="explicitly enable destructive tests on designated disposable VMs",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    enabled = config.getoption("--e2e-run", default=False)
    if enabled and (config.option.showlocals or os.getenv("PYTEST_XDIST_WORKER")):
        raise pytest.UsageError("E2E forbids --showlocals and parallel workers (secrets/leases)")
    if not enabled:
        for item in items:
            if item.get_closest_marker("e2e"):
                item.add_marker(
                    pytest.mark.skip(
                        reason="VM E2E disabled; requires --e2e-run and disposable VM opt-in"
                    )
                )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[Any]
) -> Generator[None, Any, None]:
    outcome = yield
    report = outcome.get_result()
    setattr(item, "e2e_" + report.when, report)


@pytest.fixture(scope="session")
def fleet() -> Iterator[Fleet]:
    try:
        inventory = Inventory.from_env(os.environ)
    except E2EError as exc:
        raise pytest.UsageError(str(exc)) from None
    instance = Fleet(inventory)
    try:
        instance.start()
        yield instance
    finally:
        instance.close()


@pytest.fixture
def cluster(request: pytest.FixtureRequest) -> Iterator[Cluster]:
    marker = request.node.get_closest_marker("e2e_case")
    if marker is None:
        raise pytest.UsageError("E2E case marker missing")
    case = str(marker.args[0])
    if case == "upgrade" and not (
        os.getenv("E2E_PREVIOUS_HUB_IMAGE") and os.getenv("E2E_PREVIOUS_AGENT_IMAGE")
    ):
        pytest.skip("E2E-06 blocked: owner must supply both compatible previous image digests")
    instance: Fleet = request.getfixturevalue("fleet")
    try:
        yield instance.setup(case)
    finally:
        report = getattr(request.node, "e2e_call", None)
        instance.finish(case, outcome="passed" if report and report.passed else "failed")
