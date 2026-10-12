from __future__ import annotations

import os
import re
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.netlab.lab import Lab, Namespace
from tests.netlab.topology import Topology, build_default_topology

LAB_KEY = pytest.StashKey[Lab]()
ARTIFACT_PATHS_KEY = pytest.StashKey[list[Path]]()
ARTIFACT_ERROR_KEY = pytest.StashKey[str]()

NETLAB_DUMP_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("ip", "-d", "addr"),
    ("ip", "rule"),
    ("ip", "route", "show", "table", "all"),
    ("nft", "list", "ruleset"),
    ("ss", "-tanp"),
    (
        "sysctl",
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.all.src_valid_mark",
    ),
)
ARTIFACT_COMMAND_TIMEOUT = 3


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


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Iterator[None]:
    outcome = yield
    report: pytest.TestReport | None = None
    try:
        report = outcome.get_result()
        if item.get_closest_marker("netlab") is None:
            return
        if report.when not in {"setup", "call"} or not report.failed:
            return

        paths = item.stash.get(ARTIFACT_PATHS_KEY, [])
        if not paths:
            lab_instance = item.stash.get(LAB_KEY, None)
            if lab_instance is not None:
                paths = [_capture_netlab_artifacts(item, lab_instance)]
                item.stash[ARTIFACT_PATHS_KEY] = paths
        error = item.stash.get(ARTIFACT_ERROR_KEY, None)
    except Exception as exc:  # noqa: BLE001 - diagnostics must never mask the test failure
        if report is not None:
            report.sections.append(("netlab artifacts", f"artifact collection failed: {exc}"))
        return

    if paths:
        report.sections.append(("netlab artifacts", "\n".join(str(path) for path in paths)))
    if error is not None:
        report.sections.append(("netlab artifacts", error))


@pytest.fixture
def lab(request: pytest.FixtureRequest) -> Iterator[Lab]:
    lab_instance = Lab()
    request.node.stash[LAB_KEY] = lab_instance
    try:
        yield lab_instance
    finally:
        lab_instance.teardown()


@pytest.fixture
def topology(request: pytest.FixtureRequest) -> Iterator[Topology]:
    lab_instance = Lab()
    request.node.stash[LAB_KEY] = lab_instance
    topology_instance: Topology | None = None
    try:
        topology_instance = build_default_topology(lab_instance)
        yield topology_instance
    except BaseException:
        if request.node.get_closest_marker("netlab") is not None:
            _capture_setup_failure_artifacts(request.node, lab_instance)
        raise
    finally:
        if topology_instance is not None:
            topology_instance.stop()
        lab_instance.teardown()


def _capture_setup_failure_artifacts(item: pytest.Item, lab_instance: Lab) -> None:
    try:
        item.stash[ARTIFACT_PATHS_KEY] = [_capture_netlab_artifacts(item, lab_instance)]
    except Exception as exc:  # noqa: BLE001 - diagnostics must never mask the setup failure
        item.stash[ARTIFACT_ERROR_KEY] = f"artifact collection failed: {exc}"


def _capture_netlab_artifacts(item: pytest.Item, lab_instance: Lab) -> Path:
    artifact_dir = (
        item.config.rootpath
        / "artifacts"
        / "netlab"
        / _sanitize_nodeid(item.nodeid)
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for namespace in lab_instance.namespaces:
        _write_namespace_dump(artifact_dir / f"{_sanitize_filename(namespace.name)}.txt", namespace)
    _copy_log_files(artifact_dir, lab_instance.log_dirs)
    return artifact_dir


def _write_namespace_dump(path: Path, namespace: Namespace) -> None:
    chunks: list[str] = []
    for command in NETLAB_DUMP_COMMANDS:
        chunks.append(f"### {' '.join(command)}\n")
        result = namespace.run(list(command), check=False, timeout=ARTIFACT_COMMAND_TIMEOUT)
        if result.stdout:
            chunks.append(result.stdout)
            if not result.stdout.endswith("\n"):
                chunks.append("\n")
        if result.returncode != 0:
            chunks.append(f"[returncode] {result.returncode}\n")
            if result.stderr:
                chunks.append("[stderr]\n")
                chunks.append(result.stderr)
                if not result.stderr.endswith("\n"):
                    chunks.append("\n")
        elif result.stderr:
            chunks.append("[stderr]\n")
            chunks.append(result.stderr)
            if not result.stderr.endswith("\n"):
                chunks.append("\n")
        chunks.append("\n")
    path.write_text("".join(chunks), encoding="utf-8")


def _copy_log_files(artifact_dir: Path, log_dirs: list[Path]) -> None:
    for index, log_dir in enumerate(log_dirs, start=1):
        for log_file in sorted(log_dir.glob("*.log")):
            if log_file.is_file():
                target = artifact_dir / f"log-{index}-{_sanitize_filename(log_file.name)}"
                shutil.copy2(log_file, target)


def _sanitize_nodeid(nodeid: str) -> str:
    safe = _sanitize_filename(nodeid)
    if len(safe) <= 180:
        return safe
    return safe[:180].rstrip("._-")


def _sanitize_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "item"
