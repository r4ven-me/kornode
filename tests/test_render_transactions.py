from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import Request

from kornode import cli
from kornode.api.routes_config import write_rendered_config
from kornode.api.routes_internal_dns import BlocklistRefreshRequest, refresh_blocklist
from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.services import render_transaction
from kornode.services.config import ConfigService
from kornode.services.config_store import config_lock, mutate_config
from kornode.services.internal_dns import InternalDnsService


@pytest.fixture(autouse=True)
def no_kernel_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests are about locks and rendering; DNS applies must not run a real
    reconciler pass (it would write /var/lib/kornode and, as root, touch the kernel)."""
    from kornode.services.command import CommandResult

    monkeypatch.setattr(
        InternalDnsService,
        "ensure_listen_address",
        lambda *_args, **_kwargs: CommandResult(("korctl", "net", "apply"), 0, "", ""),
    )


def request_for(path: Path) -> Request:
    state = SimpleNamespace(config_path=path, config=load_config(path))
    return Request({"type": "http", "app": SimpleNamespace(state=state)})


@pytest.mark.parametrize("entry", ["api", "cli", "service"])
def test_reload_waits_for_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("system: {project_name: old}\n")
    request = request_for(path)
    entered = Event()
    release = Event()
    attempted = Event()
    rendered: list[str] = []

    def mutation(raw: dict[str, Any]) -> dict[str, Any]:
        entered.set()
        assert release.wait(5)
        return {**raw, "system": {"project_name": "new"}}

    @contextmanager
    def observed_lock(source: Path) -> Any:
        attempted.set()
        with config_lock(source) as target:
            yield target

    def write(_self: ConfigService, config: AppConfig) -> list[Path]:
        rendered.append(config.system.project_name)
        return []

    monkeypatch.setattr(render_transaction, "config_lock", observed_lock)
    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    monkeypatch.setitem(cli.STATE, "config_path", path)
    monkeypatch.setitem(cli.STATE, "env_file", None)

    def render() -> object:
        if entry == "api":
            return write_rendered_config(request)
        if entry == "cli":
            return cli.config_render(dry_run=False)
        return render_transaction.render_config(path)

    with ThreadPoolExecutor(max_workers=2) as pool:
        saving = pool.submit(mutate_config, path, mutation, write_rendered=False)
        try:
            assert entered.wait(5)
            rendering = pool.submit(render)
            assert attempted.wait(5)
            assert not rendering.done()
        finally:
            release.set()
        saving.result(timeout=5)
        rendering.result(timeout=5)
    assert rendered == ["new"]
    assert request.app.state.config.system.project_name == "old"


def test_mutation_waits_until_rendered_writes_finish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("system: {project_name: old}\n")
    writing = Event()
    release = Event()
    attempted = Event()
    order: list[str] = []
    from kornode.services import config_store

    @contextmanager
    def observed_lock(source: Path) -> Any:
        attempted.set()
        with config_lock(source) as target:
            yield target

    def write(_self: ConfigService, config: AppConfig) -> list[Path]:
        writing.set()
        assert release.wait(5)
        order.append(config.system.project_name)
        return []

    def mutation(raw: dict[str, Any]) -> dict[str, Any]:
        order.append("mutation")
        return {**raw, "system": {"project_name": "new"}}

    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    monkeypatch.setattr(config_store, "config_lock", observed_lock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        rendering = pool.submit(render_transaction.render_config, path)
        try:
            assert writing.wait(5)
            saving = pool.submit(mutate_config, path, mutation, write_rendered=False)
            assert attempted.wait(5)
            assert not saving.done()
            assert order == []
        finally:
            release.set()
        rendering.result(timeout=5)
        saving.result(timeout=5)
    assert order == ["old", "mutation"]


def test_delayed_blocklist_refresh_renders_latest_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.yaml"
    url = "https://example.com/list"
    path.write_text(f"internal_dns:\n  blocklist_urls: [{url}]\n  blocklist_enabled: true\n")
    request = request_for(path)
    fetching = Event()
    release = Event()
    rendered: list[AppConfig] = []

    def refresh(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        fetching.set()
        assert release.wait(5)
        return SimpleNamespace(
            saved=True, url=url, total_lines=1, valid=1, skipped=0, sample=["example.org"]
        )

    def write(_self: ConfigService, config: AppConfig) -> list[Path]:
        rendered.append(config)
        return []

    monkeypatch.setattr(InternalDnsService, "refresh_url_blocklist", refresh)
    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(refresh_blocklist, request, BlocklistRefreshRequest(url=url))
        try:
            assert fetching.wait(5)
            mutate_config(
                path,
                lambda raw: {**raw, "internal_dns": {"blocklist_enabled": False}},
                write_rendered=False,
            )
        finally:
            release.set()
        assert pending.result(timeout=5)["saved"] is True
    assert len(rendered) == 1
    assert not rendered[0].internal_dns.blocklist_enabled


@pytest.mark.parametrize("explicit_env", [False, True])
def test_symlink_preserves_original_environment_through_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, explicit_env: bool
) -> None:
    canonical = tmp_path / "canonical"
    alias = tmp_path / "alias"
    canonical.mkdir()
    alias.mkdir()
    target = canonical / "config.yaml"
    target.write_text("web: {admin_password: '${SECRET:RENDER_TEST_PASSWORD}'}\n")
    path = alias / "config.yaml"
    path.symlink_to(target)
    (canonical / ".env").write_text("RENDER_TEST_PASSWORD=wrong\n")
    (alias / ".env").write_text("RENDER_TEST_PASSWORD=alias-secret\n")
    override = tmp_path / "override.env"
    override.write_text("RENDER_TEST_PASSWORD=explicit-secret\n")
    monkeypatch.delenv("RENDER_TEST_PASSWORD", raising=False)
    expected = "explicit-secret" if explicit_env else "alias-secret"

    def write(_self: ConfigService, config: AppConfig) -> list[Path]:
        assert config.web.admin_password == expected
        # Even nested reads retain the frozen original-path environment.
        (alias / ".env").write_text("RENDER_TEST_PASSWORD=changed\n")
        override.write_text("RENDER_TEST_PASSWORD=changed\n")
        assert load_config(path).web.admin_password == expected
        return [tmp_path / "rendered"]

    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    before = target.read_bytes()
    assert render_transaction.render_config(path, env_file=override if explicit_env else None) == [
        str(tmp_path / "rendered")
    ]
    assert target.read_bytes() == before
    assert path.is_symlink()


@pytest.mark.parametrize("entry", ["dns", "start", "restart", "apply_change"])
def test_runtime_writer_reloads_after_concurrent_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    from fastapi import BackgroundTasks

    from kornode.services.apply import apply_dns_configuration
    from kornode.services.server import ServerService

    path = tmp_path / "config.yaml"
    path.write_text("system: {project_name: old}\nserver: {enabled: true}\n")
    stale = load_config(path)
    entered = Event()
    attempted = Event()
    release = Event()
    artifact = tmp_path / "rendered.txt"
    actions: list[str] = []

    class Rpc:
        def start_process(self, process: str) -> None:
            actions.append("start")

        def stop_process(self, process: str) -> None:
            actions.append("stop")

        def get_process_info(self, process: str) -> dict[str, str]:
            return {"statename": "STOPPED"}

    def mutation(raw: dict[str, Any]) -> dict[str, Any]:
        entered.set()
        assert release.wait(5)
        return {**raw, "system": {"project_name": "new"}, "server": {"enabled": False}}

    @contextmanager
    def observed_lock(source: Path) -> Any:
        attempted.set()
        with config_lock(source) as target:
            yield target

    def write(_self: ConfigService, config: AppConfig) -> list[Path]:
        artifact.write_text(config.system.project_name)
        return [artifact]

    def render() -> object:
        if entry == "dns":
            return apply_dns_configuration(
                stale, BackgroundTasks(), reconnect_clients=False, config_path=path
            )
        service = ServerService(stale, rpc_client=Rpc(), config_path=path)  # type: ignore[arg-type]
        if entry == "apply_change":
            return service.apply_config_change("")
        return getattr(service, entry)()

    monkeypatch.setattr(render_transaction, "config_lock", observed_lock)
    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    # The latest DNS config is disabled, so it must stop rather than restart dnsmasq.
    from kornode.services.command import CommandResult

    def process_action(_self: ServerService, action: str, process: str) -> CommandResult:
        actions.append(action)
        return CommandResult((action, process), 0, "", "")

    monkeypatch.setattr(ServerService, "process_action", process_action)
    with ThreadPoolExecutor(max_workers=2) as pool:
        saving = pool.submit(mutate_config, path, mutation, write_rendered=False)
        try:
            assert entered.wait(5)
            rendering = pool.submit(render)
            assert attempted.wait(5)
            assert not rendering.done()
        finally:
            release.set()
        saving.result(timeout=5)
        rendering.result(timeout=5)
    assert artifact.read_text() == "new"
    assert "start" not in actions
    if entry in {"dns", "apply_change"}:
        assert actions == ["stop"]


def test_cli_delayed_refresh_reloads_latest_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("system: {project_name: old}\ninternal_dns: {blocklist_enabled: false}\n")
    fetching = Event()
    release = Event()
    artifact = tmp_path / "rendered.txt"

    def refresh(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        fetching.set()
        assert release.wait(5)
        return SimpleNamespace(
            saved=True,
            url="https://example.com",
            total_lines=1,
            valid=1,
            skipped=0,
            sample=["example.org"],
        )

    def write(_self: ConfigService, config: AppConfig) -> list[Path]:
        artifact.write_text(config.system.project_name)
        return [artifact]

    monkeypatch.setitem(cli.STATE, "config_path", path)
    monkeypatch.setitem(cli.STATE, "env_file", None)
    monkeypatch.setattr(InternalDnsService, "refresh_url_blocklist", refresh)
    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    with ThreadPoolExecutor(max_workers=1) as pool:
        refreshing = pool.submit(cli.internal_dns_refresh, url="https://example.com", preview=False)
        try:
            assert fetching.wait(5)
            mutate_config(
                path,
                lambda raw: {**raw, "system": {"project_name": "new"}},
                write_rendered=False,
            )
        finally:
            release.set()
        refreshing.result(timeout=5)
    assert artifact.read_text() == "new"


@pytest.mark.parametrize("entry", ["start", "restart", "apply_change", "dns"])
def test_in_memory_candidate_under_existing_lock_is_not_reloaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    from fastapi import BackgroundTasks

    from kornode.services.apply import apply_dns_configuration
    from kornode.services.server import ServerService

    path = tmp_path / "config.yaml"
    path.write_text("system: {project_name: disk}\nserver: {enabled: false}\n")
    candidate = load_config(path)
    candidate.system.project_name = "intentional-override"
    candidate.server.enabled = True
    rendered: list[str] = []

    class Rpc:
        def start_process(self, process: str) -> None:
            pass

        def stop_process(self, process: str) -> None:
            pass

        def get_process_info(self, process: str) -> dict[str, str]:
            return {"statename": "STOPPED"}

    def write(_self: ConfigService, config: AppConfig) -> list[Path]:
        rendered.append(config.system.project_name)
        return []

    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    from kornode.services.command import CommandResult

    monkeypatch.setattr(
        ServerService,
        "process_action",
        lambda *_args, **_kwargs: CommandResult(("stop", "dnsmasq"), 0, "", ""),
    )
    with config_lock(path):
        if entry == "dns":
            apply_dns_configuration(candidate, BackgroundTasks(), reconnect_clients=False)
        else:
            service = ServerService(candidate, rpc_client=Rpc())  # type: ignore[arg-type]
            if entry == "apply_change":
                service.apply_config_change("")
            else:
                getattr(service, entry)()
    assert rendered == ["intentional-override"]


@pytest.mark.parametrize("entry", ["start", "restart", "apply_change", "dns"])
def test_runtime_action_keeps_source_lock_without_nested_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    from fastapi import BackgroundTasks

    from kornode.services import config_store
    from kornode.services.apply import apply_dns_configuration
    from kornode.services.command import CommandResult
    from kornode.services.server import ServerService

    path = tmp_path / "config.yaml"
    path.write_text("system: {project_name: old}\nserver: {enabled: true}\n")
    config = load_config(path)
    action_entered = Event()
    release_action = Event()
    mutation_attempted = Event()
    mutation_entered = Event()
    writes: list[str] = []

    def action() -> None:
        action_entered.set()
        assert release_action.wait(5)

    class Rpc:
        def start_process(self, process: str) -> None:
            action()

        def stop_process(self, process: str) -> None:
            pass

        def get_process_info(self, process: str) -> dict[str, str]:
            return {"statename": "STOPPED"}

    @contextmanager
    def observed_lock(source: Path) -> Any:
        mutation_attempted.set()
        with config_lock(source) as target:
            yield target

    def write(_self: ConfigService, current: AppConfig) -> list[Path]:
        writes.append(current.system.project_name)
        return []

    def mutate(raw: dict[str, Any]) -> dict[str, Any]:
        mutation_entered.set()
        return raw

    def process_action(_self: ServerService, command: str, process: str) -> CommandResult:
        action()
        return CommandResult((command, process), 0, "", "")

    def apply() -> object:
        if entry == "dns":
            return apply_dns_configuration(
                config, BackgroundTasks(), reconnect_clients=False, config_path=path
            )
        service = ServerService(config, rpc_client=Rpc(), config_path=path)  # type: ignore[arg-type]
        if entry == "apply_change":
            return service.apply_config_change("")
        return getattr(service, entry)()

    monkeypatch.setattr(config_store, "config_lock", observed_lock)
    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    monkeypatch.setattr(ServerService, "process_action", process_action)
    with ThreadPoolExecutor(max_workers=2) as pool:
        applying = pool.submit(apply)
        try:
            assert action_entered.wait(5)
            saving = pool.submit(mutate_config, path, mutate, write_rendered=False)
            assert mutation_attempted.wait(5)
            assert not mutation_entered.is_set()
            assert not saving.done()
        finally:
            release_action.set()
        applying.result(timeout=5)
        saving.result(timeout=5)
    assert writes == ["old"]
    assert mutation_entered.is_set()


def test_config_only_api_preserves_intentional_initialization_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastapi.testclient import TestClient

    from kornode.api.app import create_app

    monkeypatch.delenv("KORNODE_CONFIG", raising=False)
    config = AppConfig.model_validate(
        {
            "system": {"project_name": "embedded", "data_dir": str(tmp_path)},
            "web": {"admin_password": "secret"},
        }
    )
    rendered: list[str] = []

    def write(_self: ConfigService, candidate: AppConfig) -> list[Path]:
        rendered.append(candidate.system.project_name)
        return []

    def forbid_disk(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("embedded app must not acquire a default-source lock")

    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    monkeypatch.setattr(render_transaction, "config_lock", forbid_disk)
    app = create_app(config)
    assert app.state.config_source is None
    response = TestClient(app).post("/api/config/render", auth=("admin", "secret"))
    assert response.status_code == 200
    assert rendered == ["embedded"]


@pytest.mark.parametrize("entry", ["server", "dns"])
def test_runtime_actions_keep_symlink_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    from fastapi import BackgroundTasks

    from kornode.services.apply import apply_dns_configuration
    from kornode.services.server import ServerService

    target = tmp_path / "target.yaml"
    target.write_text("server: {enabled: true}\n")
    alias_dir = tmp_path / "alias"
    alias_dir.mkdir()
    path = alias_dir / "config.yaml"
    path.symlink_to(target)
    (tmp_path / ".env").write_text("KORNODE_SYSTEM__PROJECT_NAME=canonical\n")
    (alias_dir / ".env").write_text("KORNODE_SYSTEM__PROJECT_NAME=alias\n")
    monkeypatch.delenv("KORNODE_SYSTEM__PROJECT_NAME", raising=False)
    seen: list[str] = []

    def write(_self: ConfigService, current: AppConfig) -> list[Path]:
        seen.append(current.system.project_name)
        return []

    def runtime(*_args: Any, **_kwargs: Any) -> None:
        (alias_dir / ".env").write_text("KORNODE_SYSTEM__PROJECT_NAME=changed\n")
        assert load_config(path).system.project_name == "alias"

    class Rpc:
        def start_process(self, process: str) -> None:
            runtime()

    from kornode.services.command import CommandResult

    def process_action(*_args: Any, **_kwargs: Any) -> CommandResult:
        runtime()
        return CommandResult(("stop", "dnsmasq"), 0, "", "")

    monkeypatch.setattr(ConfigService, "write_rendered_files", write)
    monkeypatch.setattr(ServerService, "process_action", process_action)
    if entry == "server":
        ServerService(load_config(path), rpc_client=Rpc(), config_path=path).start()  # type: ignore[arg-type]
    else:
        apply_dns_configuration(
            load_config(path), BackgroundTasks(), reconnect_clients=False, config_path=path
        )
    assert seen == ["alias"]
