from __future__ import annotations

import multiprocessing
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from fastapi import Request
from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.api.routes_config import apply_config_mutation, apply_config_patch
from kornode.cli import STATE, _validate_config_data, save_config_patch
from kornode.config.env import env_overrides_from_mapping
from kornode.config.loader import deep_merge, load_config, load_yaml_file, validate_config_data
from kornode.services.config import ConfigService
from kornode.services.config_store import (
    ConfigApplyError,
    ConfigPreflightError,
    mutate_config,
    source_etag,
)
from kornode.services.files import FileManager

AUTH = ("admin", "secret")


@pytest.fixture
def path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "system": {
                    key: str(tmp_path / key)
                    for key in ("data_dir", "log_dir", "generated_dir", "secrets_dir")
                },
                "web": {"enabled": True, "admin_password": "secret"},
                "server": {"enabled": False},
            }
        )
    )
    return path


def _request(path: Path) -> Request:
    state = SimpleNamespace(config=load_config(path), config_path=path)
    return Request({"type": "http", "app": SimpleNamespace(state=state)})


def _source(client: TestClient) -> dict[str, Any]:
    response = client.get("/api/config/source", auth=AUTH)
    assert response.status_code == 200
    assert response.headers["etag"] == response.json()["etag"]
    return response.json()


def _save(client: TestClient, source: dict[str, Any], **changes: Any) -> Any:
    return client.post(
        "/api/config/source",
        auth=AUTH,
        json={
            "content": source["content"],
            "etag": source["etag"],
            "write_rendered": False,
            **changes,
        },
    )


def _profile(name: str, **changes: Any) -> dict[str, Any]:
    return {
        "name": name,
        "server": "vpn.example.com",
        "username": name,
        "password": f"{name}-password",
        "key_file_base64": "a2V5",
        **changes,
    }


def _set_profiles(path: Path, profiles: list[dict[str, Any]]) -> None:
    raw = load_yaml_file(path)
    raw["upstream"] = {"profiles": profiles}
    path.write_text(yaml.safe_dump(raw))


@pytest.mark.parametrize("operation", ["reverse", "remove-first", "insert"])
def test_source_masks_follow_name_not_index(path: Path, operation: str) -> None:
    path.with_name(".env").write_text("FIRST_PASS=one\nSECOND_PASS=two\n")
    _set_profiles(
        path,
        [
            _profile("first", password="${SECRET:FIRST_PASS}"),
            _profile("second", password="${SECRET:SECOND_PASS}", key_file_base64="c2Vjb25k"),
        ],
    )
    client = TestClient(create_app(config_path=path))
    source = _source(client)
    raw = yaml.safe_load(source["content"])
    profiles = raw["upstream"]["profiles"]
    if operation == "reverse":
        profiles.reverse()
    elif operation == "remove-first":
        profiles.pop(0)
    else:
        profiles.insert(0, _profile("new"))
    source["content"] = yaml.safe_dump(raw)
    response = _save(client, source)
    assert response.status_code == 200, response.text
    saved = {p["name"]: p for p in load_yaml_file(path)["upstream"]["profiles"]}
    assert saved["second"]["password"] == "${SECRET:SECOND_PASS}"
    assert saved["second"]["key_file_base64"] == "c2Vjb25k"
    if "first" in saved:
        assert saved["first"]["password"] == "${SECRET:FIRST_PASS}"
        assert saved["first"]["key_file_base64"] == "a2V5"
    assert "SECOND_PASS" not in response.text
    assert "two" not in response.json()["content"]


@pytest.mark.parametrize("operation", ["rename", "duplicate", "new", "unknown-key"])
def test_unknown_or_ambiguous_mask_never_commits(path: Path, operation: str) -> None:
    _set_profiles(path, [_profile("first")])
    client = TestClient(create_app(config_path=path))
    before = path.read_bytes()
    source = _source(client)
    raw = yaml.safe_load(source["content"])
    profile = raw["upstream"]["profiles"][0]
    if operation == "rename":
        profile["name"] = "renamed"
    elif operation == "duplicate":
        raw["upstream"]["profiles"].append(profile.copy())
    elif operation == "new":
        raw["upstream"]["profiles"].append(_profile("new", key_file_base64="***"))
    else:
        profile["cert_pass"] = "***"
    source["content"] = yaml.safe_dump(raw)
    response = _save(client, source)
    assert response.status_code == 400, response.text
    assert path.read_bytes() == before


def test_duplicate_original_identity_is_rejected(path: Path) -> None:
    _set_profiles(path, [_profile("first")])
    client = TestClient(create_app(config_path=path))
    _set_profiles(path, [_profile("first"), _profile("first", password="different")])
    source = _source(client)
    raw = yaml.safe_load(source["content"])
    raw["upstream"]["profiles"].pop()
    response = _save(client, source, content=yaml.safe_dump(raw))
    assert response.status_code == 400


def test_full_source_requires_exact_strong_version(path: Path) -> None:
    client = TestClient(create_app(config_path=path))
    source = _source(client)
    original = path.read_bytes()
    no_version = client.post(
        "/api/config/source",
        auth=AUTH,
        json={
            "content": source["content"],
            "write_rendered": False,
        },
    )
    assert no_version.status_code == 428
    for invalid in ("*", "W/" + source["etag"], '"stale"', source["etag"] + ', "other"'):
        assert _save(client, source, etag=invalid).status_code == 412
    assert path.read_bytes() == original
    response = client.post(
        "/api/config/source",
        auth=AUTH,
        headers={"If-Match": source["etag"]},
        json={"content": source["content"], "write_rendered": False},
    )
    assert response.status_code == 200
    assert response.headers["etag"] == source_etag(path)
    assert response.json()["etag"] == source_etag(path)


def test_cli_change_makes_source_and_optional_patch_version_stale(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(create_app(config_path=path))
    source = _source(client)
    monkeypatch.setitem(STATE, "config_path", path)
    monkeypatch.setitem(STATE, "env_file", None)
    save_config_patch({"server": {"realm": "CLI realm"}}, write_rendered=False)
    before = path.read_bytes()
    assert _save(client, source).status_code == 412
    response = client.patch(
        "/api/config",
        auth=AUTH,
        headers={"If-Match": source["etag"]},
        json={"patch": {"server": {"realm": "overwrite"}}, "write_rendered": False},
    )
    assert response.status_code == 412
    assert path.read_bytes() == before
    # Existing structured clients remain compatible without If-Match.
    assert (
        client.patch(
            "/api/config",
            auth=AUTH,
            json={"patch": {"server": {"port": 4443}}, "write_rendered": False},
        ).status_code
        == 200
    )
    assert load_yaml_file(path)["server"]["realm"] == "CLI realm"


@pytest.mark.parametrize(
    "field,value",
    [
        ("admin_password", "replacement"),
        ("admin_password", None),
        ("admin_password_hash", "a-hash"),
        ("admin_totp_secret", "JBSWY3DPEHPK3PXP"),
    ],
)
@pytest.mark.parametrize("endpoint", ["source", "source/validate", "patch", "validate"])
def test_public_config_cannot_bypass_dedicated_auth(
    path: Path,
    field: str,
    value: Any,
    endpoint: str,
) -> None:
    client = TestClient(create_app(config_path=path))
    source = _source(client)
    raw = yaml.safe_load(source["content"])
    raw["web"][field] = value
    before = path.read_bytes()
    if endpoint == "patch":
        response = client.patch(
            "/api/config",
            auth=AUTH,
            json={"patch": {"web": {field: value}}, "write_rendered": False},
        )
    elif endpoint == "validate":
        response = client.post("/api/config/validate", auth=AUTH, json=raw)
    else:
        response = client.post(
            f"/api/config/{endpoint}",
            auth=AUTH,
            json={
                "content": yaml.safe_dump(raw),
                "etag": source["etag"],
                "write_rendered": False,
            },
        )
    assert response.status_code in {400, 403}, response.text
    assert path.read_bytes() == before
    assert client.app.state.config.web.admin_password == "secret"


def test_source_omission_cannot_disable_totp(path: Path) -> None:
    raw = load_yaml_file(path)
    raw["web"].update(admin_totp_enabled=True, admin_totp_secret="JBSWY3DPEHPK3PXP")
    path.write_text(yaml.safe_dump(raw))
    request = _request(path)
    # Exercise the public candidate guard independently of login/TOTP transport.
    from fastapi import HTTPException

    from kornode.api.routes_config import _validate_public_candidate

    candidate = load_yaml_file(path)
    candidate["web"].pop("admin_totp_enabled")
    with pytest.raises(HTTPException) as error:
        _validate_public_candidate(candidate, raw, path)
    assert error.value.status_code == 403
    assert request.app.state.config.web.admin_totp_enabled


def test_trusted_helper_allows_auth_and_invalidates_after_state_install(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(path)
    previous = request.app.state.config
    calls = []

    def invalidate(req: Request, old: Any, new: Any) -> None:
        assert req.app.state.config is new
        assert old is previous
        calls.append(new)

    monkeypatch.setattr("kornode.api.routes_config.invalidate_auth_sessions", invalidate)
    config, written = apply_config_patch(
        request, {"web": {"admin_password": "new"}}, write_rendered=False
    )
    assert written == []
    assert calls == [config]
    assert config.web.admin_password == "new"


@pytest.mark.parametrize("role", ["api", "cli"])
def test_render_preflight_failure_leaves_source_state_and_runtime_untouched(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    request = _request(path)
    original_state = request.app.state.config
    before = path.read_bytes()
    sentinel = path.parent / "runtime"
    sentinel.write_text("original")

    def fail(*_: Any) -> Any:
        raise RuntimeError("sensitive renderer output")

    monkeypatch.setattr(ConfigService, "render_files", fail)
    monkeypatch.setattr(
        ConfigService,
        "write_rendered_files",
        lambda *_: pytest.fail("application must not start on failed preflight"),
    )
    if role == "api":
        with pytest.raises(Exception) as error:
            apply_config_patch(request, {"server": {"realm": "next"}})
        assert error.value.status_code == 500
        assert error.value.detail["saved"] is False
    else:
        monkeypatch.setitem(STATE, "config_path", path)
        monkeypatch.setitem(STATE, "env_file", None)
        with pytest.raises(ConfigPreflightError):
            save_config_patch({"server": {"realm": "next"}})
    assert path.read_bytes() == before
    assert request.app.state.config is original_state
    assert sentinel.read_text() == "original"
    assert not (path.parent / "generated_dir").exists()


def test_yaml_write_failure_does_not_install_state_or_apply_runtime(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(path)
    before, previous = path.read_bytes(), request.app.state.config

    def fail(*_: Any, **__: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(FileManager, "atomic_write_text", fail)
    monkeypatch.setattr(
        ConfigService,
        "write_rendered_files",
        lambda *_: pytest.fail("no runtime application before YAML persistence"),
    )
    with pytest.raises(OSError):
        apply_config_patch(request, {"server": {"realm": "next"}})
    assert path.read_bytes() == before
    assert request.app.state.config is previous


@pytest.mark.parametrize("failure", ["rendered-write", "default-group", "crl", "bundle"])
def test_postcommit_failure_is_explicit_and_installs_validated_candidate(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    client = TestClient(create_app(config_path=path))

    def fail(*_: Any, **__: Any) -> Any:
        raise OSError("sensitive runtime output")

    if failure == "rendered-write":
        original = FileManager.atomic_write_text

        def write(self: FileManager, target: Path, content: str, mode: int = 0o644) -> None:
            if target == path:
                original(self, target, content, mode)
            else:
                fail()

        monkeypatch.setattr(FileManager, "atomic_write_text", write)
    elif failure == "default-group":
        monkeypatch.setattr("kornode.services.users.UserService.ensure_default_group", fail)
    elif failure == "crl":
        monkeypatch.setattr(ConfigService, "_ensure_interlink_crl", fail)
    else:
        monkeypatch.setattr(ConfigService, "_recompile_bundles", fail)
    response = client.patch(
        "/api/config", auth=AUTH, json={"patch": {"server": {"realm": "saved candidate"}}}
    )
    assert response.status_code == 500
    assert response.json()["detail"]["status"] == "saved_but_not_applied"
    assert "sensitive" not in response.text
    assert load_yaml_file(path)["server"]["realm"] == "saved candidate"
    assert client.app.state.config.server.realm == "saved candidate"


def test_cli_postcommit_failure_is_not_silent(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_: Any) -> Any:
        raise OSError("runtime write")

    monkeypatch.setitem(STATE, "config_path", path)
    monkeypatch.setitem(STATE, "env_file", None)
    monkeypatch.setattr(ConfigService, "write_rendered_files", fail)
    with pytest.raises(ConfigApplyError, match="saved_but_not_applied"):
        save_config_patch({"server": {"realm": "saved"}})
    assert load_config(path).server.realm == "saved"


def test_candidate_and_file_loader_share_explicit_paths_and_env(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custom_env = path.parent / "custom.env"
    custom_env.write_text("KORNODE_NODE__ID=7\nKORNODE_SERVER__PORT=5555\n")
    raw = load_yaml_file(path)
    raw["node"] = {"id": 9}
    path.write_text(yaml.safe_dump(raw))
    monkeypatch.setitem(STATE, "config_path", path)
    monkeypatch.setitem(STATE, "env_file", custom_env)
    expected = load_config(path, env_file=custom_env)
    assert _validate_config_data(raw, path) == expected
    candidate = save_config_patch({"system": {"timezone": "Europe/Moscow"}}, write_rendered=False)
    assert candidate == load_config(path, env_file=custom_env)
    assert candidate.server.ipv4_network == "10.100.9.0/24"
    assert candidate.internal_dns.listen == "10.100.9.1"
    assert candidate.server.port == 5555
    assert "ipv4_network" not in load_yaml_file(path)["server"]
    assert "internal_dns" not in load_yaml_file(path)
    assert validate_config_data(raw, path, env_file=custom_env) == expected


def test_api_sparse_node_edit_uses_same_candidate_as_reload(path: Path) -> None:
    client = TestClient(create_app(config_path=path))
    response = client.patch(
        "/api/config", auth=AUTH, json={"patch": {"node": {"id": 12}}, "write_rendered": False}
    )
    assert response.status_code == 200, response.text
    assert client.app.state.config == load_config(path)
    assert client.app.state.config.server.ipv4_network == "10.100.12.0/24"
    assert "ipv4_network" not in load_yaml_file(path)["server"]


def test_known_top_level_env_collections_preserve_precedence_and_refs(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = {
        "KORNODE_EGRESS": "[]",
        "KORNODE_SOURCES": "[]",
        "KORNODE_SETS": '{"private":{"routes":["192.0.2.0/24"]}}',
        "KORNODE_UNRELATED_SECRET": "ignored",
        "KORNODE_OTHER": "[]",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    overrides = env_overrides_from_mapping(env)
    assert set(overrides) == {"egress", "sources", "sets"}
    config = load_config(path)
    assert config.egress == () and config.sources == ()
    assert "private" in config.sets
    config = load_config(path, cli_overrides={"sets": {"private": {"routes": ["198.51.100.0/24"]}}})
    assert str(config.sets["private"].routes[0]) == "198.51.100.0/24"
    request = _request(path)
    apply_config_patch(request, {"system": {"timezone": "UTC"}}, write_rendered=False)
    assert "egress" not in load_yaml_file(path)
    assert "sets" not in load_yaml_file(path)
    raw = load_yaml_file(path)
    raw["egress"] = []
    raw["sources"] = []
    raw["sets"] = {"private": {"routes": ["203.0.113.0/24"]}}
    path.write_text(yaml.safe_dump(raw))
    assert str(load_config(path).sets["private"].routes[0]) == "203.0.113.0/24"


def _parallel_save(
    path: Path,
    role: str,
    entered: Any,
    release: Any,
    attempted: Any,
) -> None:
    attempted.set()
    if role == "cli":
        original = FileManager.atomic_write_text

        def paused_write(
            self: FileManager,
            target: Path,
            content: str,
            mode: int = 0o644,
        ) -> None:
            entered.set()
            if not release.wait(15):
                raise TimeoutError("test did not release writer")
            original(self, target, content, mode)

        FileManager.atomic_write_text = paused_write  # type: ignore[method-assign]
        STATE.update(config_path=path, env_file=None)
        save_config_patch({"system": {"timezone": "Europe/Moscow"}}, write_rendered=False)
    else:

        def mutation(raw: dict[str, Any]) -> dict[str, Any]:
            entered.set()
            return deep_merge(raw, {"server": {"realm": "API"}})

        apply_config_mutation(_request(path), mutation, write_rendered=False)


def _stop_workers(workers: list[Any]) -> None:
    for worker in workers:
        if worker.pid is not None:
            if worker.is_alive():
                worker.terminate()
            worker.join(5)


def test_api_and_cli_processes_share_read_modify_write_lock(path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    cli_entered, api_entered = context.Event(), context.Event()
    cli_attempted, api_attempted, release = context.Event(), context.Event(), context.Event()
    workers = [
        context.Process(
            target=_parallel_save,
            args=(path, "cli", cli_entered, release, cli_attempted),
        ),
        context.Process(
            target=_parallel_save,
            args=(path, "api", api_entered, release, api_attempted),
        ),
    ]
    try:
        workers[0].start()
        assert cli_entered.wait(15)
        workers[1].start()
        assert api_attempted.wait(15)
        assert not api_entered.wait(0.2)
        release.set()
        for worker in workers:
            worker.join(15)
            assert worker.exitcode == 0
    finally:
        release.set()
        _stop_workers(workers)
    config = load_config(path)
    assert config.server.realm == "API"
    assert config.system.timezone == "Europe/Moscow"


def _crash_mutation(path: Path, phase: str, entered: Any, crash: Any) -> None:
    def stop() -> None:
        entered.set()
        if not crash.wait(15):
            raise TimeoutError("test did not request crash")
        # Simulate abrupt death without executing context managers/finalizers.
        os._exit(73)

    if phase == "before-replace":

        def interrupted_replace(_source: Any, _target: Any) -> None:
            stop()

        os.replace = interrupted_replace

    def mutation(raw: dict[str, Any]) -> dict[str, Any]:
        if phase == "before-commit":
            stop()
        return deep_merge(raw, {"server": {"realm": "crashed writer", "port": 4443}})

    def committed(_config: Any) -> None:
        stop()

    mutate_config(path, mutation, write_rendered=False, on_commit=committed)


@pytest.mark.parametrize("phase", ["before-commit", "before-replace", "after-commit"])
def test_process_crash_releases_lock_and_next_writer_reads_atomic_source(
    path: Path,
    phase: str,
) -> None:
    context = multiprocessing.get_context("spawn")
    entered, crash = context.Event(), context.Event()
    following_entered, release, attempted = context.Event(), context.Event(), context.Event()
    workers = [
        context.Process(target=_crash_mutation, args=(path, phase, entered, crash)),
        context.Process(
            target=_parallel_save,
            args=(path, "api", following_entered, release, attempted),
        ),
    ]
    original = load_yaml_file(path)
    try:
        workers[0].start()
        assert entered.wait(15)
        current = load_yaml_file(path)
        if phase != "after-commit":
            assert current == original
        else:
            assert current["server"]["realm"] == "crashed writer"
        if phase == "before-replace":
            staged = [
                candidate
                for candidate in path.parent.glob(f".{path.name}.*")
                if candidate.name != f".{path.name}.lock"
            ]
            assert len(staged) == 1
            assert staged[0].stat().st_mode & 0o777 == 0o600
        workers[1].start()
        assert attempted.wait(15)
        assert not following_entered.wait(0.2)
        crash.set()
        workers[0].join(15)
        assert workers[0].exitcode == 73
        assert following_entered.wait(15)
        workers[1].join(15)
        assert workers[1].exitcode == 0
    finally:
        crash.set()
        release.set()
        _stop_workers(workers)
    saved = load_yaml_file(path)
    assert saved["server"]["realm"] == "API"
    assert saved["server"].get("port") == (4443 if phase == "after-commit" else None)
    assert saved["web"] == original["web"]
    assert saved["system"] == original["system"]
    assert load_config(path).server.realm == "API"


@pytest.mark.parametrize("hook", ["on_commit", "after_apply"])
def test_lock_covers_state_assignment_not_only_file_write(path: Path, hook: str) -> None:
    request = _request(path)
    first_installed, release, second_entered = Event(), Event(), Event()

    def first(config: Any) -> None:
        first_installed.set()
        assert release.wait(5)
        request.app.state.config = config

    def second(raw: dict[str, Any]) -> dict[str, Any]:
        second_entered.set()
        return deep_merge(raw, {"server": {"realm": "second"}})

    with ThreadPoolExecutor(max_workers=2) as pool:
        future1 = pool.submit(
            mutate_config,
            path,
            lambda raw: deep_merge(raw, {"server": {"realm": "first"}}),
            write_rendered=False,
            **{hook: first},
        )
        assert first_installed.wait(5)
        future2 = pool.submit(apply_config_mutation, request, second, write_rendered=False)
        try:
            assert not second_entered.wait(0.1)
        finally:
            release.set()
        future1.result(timeout=5)
        future2.result(timeout=5)
    assert request.app.state.config.server.realm == "second"
    assert request.app.state.config == load_config(path)


def test_raw_callback_sees_latest_yaml_and_preserves_secret_refs(path: Path) -> None:
    request = _request(path)
    path.with_name(".env").write_text("PASS=first\n")
    _set_profiles(path, [_profile("first", password="${SECRET:PASS}")])

    def edit(raw: dict[str, Any]) -> dict[str, Any]:
        assert raw["upstream"]["profiles"][0]["password"] == "${SECRET:PASS}"
        raw["upstream"]["profiles"][0]["enabled"] = False
        return raw

    config, _ = apply_config_mutation(request, edit, write_rendered=False)
    assert config.upstream.profiles[0].password == "first"
    assert load_yaml_file(path)["upstream"]["profiles"][0]["password"] == "${SECRET:PASS}"
    path.with_name(".env").write_text("PASS=rotated\n")
    assert load_config(path).upstream.profiles[0].password == "rotated"


def test_render_does_not_migrate_live_registry(path: Path) -> None:
    config = load_config(path)
    db_path = config.system.data_dir / "registry.db"
    db_path.parent.mkdir()
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE user_content (value TEXT)")
        conn.execute("INSERT INTO user_content VALUES ('keep')")
    before = db_path.read_bytes()
    assert ConfigService().render_files(config)
    assert db_path.read_bytes() == before
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute("SELECT value FROM user_content").fetchone()[0] == "keep"


def test_strict_transaction_does_not_swallow_bundle_compilation_failure(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.bundle.errors import BundleError
    from kornode.services.bundle import BundleService

    raw = load_yaml_file(path)
    raw["control"] = {"enabled": True}
    path.write_text(yaml.safe_dump(raw))
    client = TestClient(create_app(config_path=path))

    def fail(*_: Any) -> Any:
        raise BundleError("compile_failed", "bundle cannot be compiled")

    monkeypatch.setattr(BundleService, "compile_all", fail)
    response = client.patch(
        "/api/config",
        auth=AUTH,
        json={"patch": {"server": {"realm": "saved before bundle failure"}}},
    )
    assert response.status_code == 500
    assert response.json()["detail"]["status"] == "saved_but_not_applied"
    assert load_config(path).server.realm == "saved before bundle failure"
    assert client.app.state.config.server.realm == "saved before bundle failure"


def test_cli_save_never_reloads_after_persistence(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(STATE, "config_path", path)
    monkeypatch.setitem(STATE, "env_file", None)

    def fail(*_: Any, **__: Any) -> Any:
        pytest.fail("must install validated candidate, not reload after saving")

    monkeypatch.setattr("kornode.cli.get_config", fail)
    config = save_config_patch({"node": {"id": 13}}, write_rendered=False)
    assert config.server.ipv4_network == "10.100.13.0/24"
    assert config == load_config(path)


def test_missing_and_empty_source_versions_differ(tmp_path: Path) -> None:
    missing = tmp_path / "config.yaml"
    previous = source_etag(missing)
    missing.write_text("")
    assert source_etag(missing) != previous


def _additional_writer(path: Path, role: str, attempted: Any, acquired: Any) -> None:
    import fcntl

    from kornode.api.routes_logs import LogRotationSettingsRequest, save_rotation_settings
    from kornode.main import _persist_certificate_patch
    from kornode.services.interlink import InterlinkService

    original = fcntl.flock

    def observed_lock(fd: Any, operation: int) -> Any:
        if operation == fcntl.LOCK_EX:
            attempted.set()
        result = original(fd, operation)
        if operation == fcntl.LOCK_EX:
            acquired.set()
        return result

    fcntl.flock = observed_lock
    if role == "startup":
        _persist_certificate_patch(
            path,
            {"server_cert": str(path.parent / "issued.crt")},
            FileManager(),
        )
    elif role == "interlink":
        InterlinkService(load_config(path), path, sync=lambda _: None).set(
            {"domain": "latest.example"}
        )
    else:
        save_rotation_settings(
            _request(path),
            LogRotationSettingsRequest(enabled=True, keep_files=3),
        )


@pytest.mark.parametrize("role", ["startup", "interlink", "rotation"])
def test_additional_writers_wait_for_latest_config_and_preserve_raw_refs(
    path: Path,
    role: str,
) -> None:
    raw = load_yaml_file(path)
    raw["web"]["admin_password"] = "${SECRET:ADMIN}"
    path.write_text(yaml.safe_dump(raw))
    path.with_name(".env").write_text("ADMIN=secret\nUPSTREAM=upstream-secret\n")
    _set_profiles(path, [_profile("first", password="${SECRET:UPSTREAM}")])
    context = multiprocessing.get_context("spawn")
    entered, release = context.Event(), context.Event()
    cli_attempted, attempted, acquired = context.Event(), context.Event(), context.Event()
    workers = [
        context.Process(target=_parallel_save, args=(path, "cli", entered, release, cli_attempted)),
        context.Process(target=_additional_writer, args=(path, role, attempted, acquired)),
    ]
    try:
        workers[0].start()
        assert entered.wait(15)
        workers[1].start()
        assert attempted.wait(15)
        assert not acquired.wait(0.2)
        release.set()
        for worker in workers:
            worker.join(15)
            assert worker.exitcode == 0
    finally:
        release.set()
        _stop_workers(workers)
    saved = load_yaml_file(path)
    assert saved["system"]["timezone"] == "Europe/Moscow"
    assert saved["web"]["admin_password"] == "${SECRET:ADMIN}"
    assert saved["upstream"]["profiles"][0]["password"] == "${SECRET:UPSTREAM}"
    if role == "startup":
        assert saved["certificates"]["server_cert"] == str(path.parent / "issued.crt")
    elif role == "interlink":
        assert saved["interlink"]["domain"] == "latest.example"
    else:
        assert saved["system"]["log_rotation"]["keep_files"] == 3


def test_startup_persistence_uses_provided_manager_and_never_reloads_after_commit(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.main import _persist_certificate_patch

    manager = FileManager()
    writes = []
    original = manager.atomic_write_text

    def write(target: Path, content: str, mode: int = 0o644) -> None:
        writes.append(target)
        original(target, content, mode)

    def no_reload(*_: Any) -> Any:
        pytest.fail("startup must return its validated candidate")

    monkeypatch.setattr(manager, "atomic_write_text", write)
    monkeypatch.setattr("kornode.main.load_config", no_reload)
    config = _persist_certificate_patch(path, {"ca_name": "latest"}, manager)
    assert writes == [path]
    assert config == load_config(path)
    assert config.certificates.ca_name == "latest"


def test_startup_persistence_failure_leaves_yaml_unchanged(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.main import _persist_certificate_patch

    manager = FileManager()
    before = path.read_bytes()

    def fail(*_: Any, **__: Any) -> Any:
        raise OSError("disk full")

    monkeypatch.setattr(manager, "atomic_write_text", fail)
    with pytest.raises(OSError):
        _persist_certificate_patch(path, {"ca_name": "latest"}, manager)
    assert path.read_bytes() == before
    # A failed writer must also release the config lock.
    config, _ = mutate_config(path, lambda raw: raw, write_rendered=False)
    assert config == load_config(path)


def test_interlink_preflight_failure_does_not_install_or_sync(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.services.agent_models import ManagementError
    from kornode.services.interlink import InterlinkService

    installed, synced = [], []
    service = InterlinkService(load_config(path), path, saved=installed.append, sync=synced.append)
    previous, before = service.config, path.read_bytes()

    def fail(*_: Any) -> Any:
        raise OSError("preflight failure")

    monkeypatch.setattr(ConfigService, "render_files", fail)
    with pytest.raises(ManagementError) as error:
        service.set({"domain": "latest.example"})
    assert error.value.status == 500
    assert error.value.error == "not_saved"
    assert path.read_bytes() == before
    assert service.config is previous
    assert not installed and not synced


def test_interlink_sync_failure_reports_saved_but_not_applied(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.services.agent_models import ManagementError
    from kornode.services.interlink import InterlinkService

    installed = []

    def fail(*_: Any) -> Any:
        raise OSError("sensitive sync failure")

    service = InterlinkService(load_config(path), path, saved=installed.append, sync=fail)
    monkeypatch.setattr(ConfigService, "write_rendered_files", lambda *_: [])
    with pytest.raises(ManagementError) as error:
        service.set({"domain": "latest.example"})
    assert error.value.status == 500
    assert error.value.error == "saved_but_not_applied"
    assert error.value.details == {"saved": True, "applied": False}
    assert "sensitive" not in str(error.value)
    assert installed == [service.config]
    assert service.config == load_config(path)
    # The post-apply exception must release the lock as well.
    config, _ = mutate_config(path, lambda raw: raw, write_rendered=False)
    assert config.interlink.domain == "latest.example"


def test_atomic_replace_failure_keeps_source_state_and_cleans_temporary_file(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(path)
    before, previous = path.read_bytes(), request.app.state.config

    def fail(_source: Any, _target: Any) -> Any:
        raise OSError("replace failed")

    with monkeypatch.context() as changes:
        changes.setattr("kornode.services.files.os.replace", fail)
        with pytest.raises(OSError):
            apply_config_patch(request, {"server": {"realm": "failed"}}, write_rendered=False)
    assert path.read_bytes() == before
    assert request.app.state.config is previous
    assert not [
        candidate
        for candidate in path.parent.glob(f".{path.name}.*")
        if candidate.name != f".{path.name}.lock"
    ]
    config, _ = apply_config_patch(
        request,
        {"server": {"realm": "recovered"}},
        write_rendered=False,
    )
    assert config.server.realm == "recovered"


@pytest.fixture
def symlink_config(path: Path) -> tuple[Path, Path]:
    raw = load_yaml_file(path)
    raw["web"] = {
        "enabled": True,
        "admin_password": "${SECRET:ADMIN_PASSWORD}",
        "admin_totp_secret": "${SECRET:ADMIN_TOTP_SECRET}",
    }
    path.write_text(yaml.safe_dump(raw))
    path.with_name(".env").write_text(
        "ADMIN_PASSWORD=target-password\nADMIN_TOTP_SECRET=KRSXG5DSNFXGOIDB\n"
        "KORNODE_WEB__ADMIN_TOTP_ENABLED=false\n"
    )
    directory = path.parent / "supplied"
    directory.mkdir()
    alias = directory / "config.yaml"
    alias.symlink_to(path)
    alias.with_name(".env").write_text(
        "ADMIN_PASSWORD=alias-password\nADMIN_TOTP_SECRET=JBSWY3DPEHPK3PXP\n"
        "KORNODE_WEB__ADMIN_TOTP_ENABLED=true\n"
    )
    return path, alias


def _symlink_client(alias: Path) -> tuple[TestClient, dict[str, str]]:
    import time

    from kornode.services.admin_totp import AdminTotpService

    client = TestClient(create_app(config_path=alias), base_url="https://testserver")
    config = client.app.state.config
    code = AdminTotpService(config)._code_at(config.web.admin_totp_secret, int(time.time()) // 30)
    response = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "alias-password",
            "totp_code": code,
        },
    )
    assert response.status_code == 200, response.text
    return client, {"x-kornode-csrf": response.json()["csrf_token"]}


def test_symlink_timezone_patch_cannot_change_auth_environment(
    symlink_config: tuple[Path, Path],
) -> None:
    target, alias = symlink_config
    client, headers = _symlink_client(alias)
    response = client.patch(
        "/api/config",
        headers=headers,
        json={
            "patch": {"system": {"timezone": "Europe/Moscow"}},
            "write_rendered": False,
        },
    )
    assert response.status_code == 200, response.text
    config = client.app.state.config
    assert config == load_config(alias)
    assert config.web.admin_totp_enabled
    assert config.web.admin_totp_secret == "JBSWY3DPEHPK3PXP"
    assert config.web.admin_password == "alias-password"
    assert not load_config(target).web.admin_totp_enabled
    assert load_config(target).web.admin_password == "target-password"
    assert alias.is_symlink()
    saved = load_yaml_file(target)
    assert saved["web"]["admin_password"] == "${SECRET:ADMIN_PASSWORD}"
    assert saved["web"]["admin_totp_secret"] == "${SECRET:ADMIN_TOTP_SECRET}"
    password_only = TestClient(client.app, base_url="https://testserver")
    assert password_only.get("/api/config", auth=("admin", "alias-password")).status_code == 401
    assert client.get("/api/auth/me").status_code == 200


@pytest.mark.parametrize("endpoint", ["patch", "source", "source/validate", "validate"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("admin_password", "target-password"),
        ("admin_totp_enabled", False),
        ("admin_totp_secret", "KRSXG5DSNFXGOIDB"),
    ],
)
def test_symlink_public_guard_uses_supplied_environment(
    symlink_config: tuple[Path, Path],
    endpoint: str,
    field: str,
    value: Any,
) -> None:
    target, alias = symlink_config
    client, headers = _symlink_client(alias)
    source = client.get("/api/config/source").json()
    before = target.read_bytes()
    raw = yaml.safe_load(source["content"])
    raw["web"][field] = value
    if endpoint == "patch":
        response = client.patch(
            "/api/config",
            headers=headers,
            json={
                "patch": {"web": {field: value}},
                "write_rendered": False,
            },
        )
    elif endpoint == "validate":
        response = client.post("/api/config/validate", headers=headers, json=raw)
    else:
        response = client.post(
            f"/api/config/{endpoint}",
            headers=headers,
            json={
                "content": yaml.safe_dump(raw),
                "etag": source["etag"],
                "write_rendered": False,
            },
        )
    assert response.status_code == 403, response.text
    assert target.read_bytes() == before
    assert client.app.state.config == load_config(alias)
    assert alias.is_symlink()


def test_alias_source_versions_share_bytes_and_reject_stale_other_alias_save(
    symlink_config: tuple[Path, Path],
) -> None:
    target, alias = symlink_config
    client, headers = _symlink_client(alias)
    target_client = TestClient(create_app(config_path=target))
    original = client.get("/api/config/source")
    canonical = target_client.get("/api/config/source", auth=("admin", "target-password"))
    assert original.status_code == canonical.status_code == 200
    assert original.headers["etag"] == canonical.headers["etag"] == source_etag(alias)
    assert original.json()["content"] == canonical.json()["content"]
    assert original.json()["path"] == str(alias)
    changed = target_client.patch(
        "/api/config",
        auth=("admin", "target-password"),
        json={
            "patch": {"server": {"realm": "saved through target"}},
            "write_rendered": False,
        },
    )
    assert changed.status_code == 200
    stale = client.post(
        "/api/config/source",
        headers=headers,
        json={
            "content": original.json()["content"],
            "etag": original.json()["etag"],
            "write_rendered": False,
        },
    )
    assert stale.status_code == 412
    assert load_config(alias).server.realm == "saved through target"
    assert alias.is_symlink()


@pytest.mark.parametrize("entry_point", ["cli", "startup", "callback"])
def test_symlink_cli_startup_and_raw_callbacks_keep_supplied_environment(
    symlink_config: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    entry_point: str,
) -> None:
    from kornode.main import _persist_certificate_patch
    from kornode.services.config_collections import raw_collection

    _target, alias = symlink_config
    with alias.with_name(".env").open("a") as stream:
        stream.write(
            'KORNODE_UPSTREAM__PROFILES=[{"name":"alias","server":"vpn.example.com",'
            '"username":"user","password":"${SECRET:ADMIN_PASSWORD}"}]\n'
        )
    if entry_point == "cli":
        monkeypatch.setitem(STATE, "config_path", alias)
        monkeypatch.setitem(STATE, "env_file", None)
        config = save_config_patch({"system": {"timezone": "Europe/Moscow"}}, write_rendered=False)
    elif entry_point == "startup":
        config = _persist_certificate_patch(alias, {"ca_name": "alias-ca"}, FileManager())
    else:

        def mutation(raw: dict[str, Any]) -> dict[str, Any]:
            profiles = raw_collection(raw, alias, "upstream", "profiles")
            assert profiles[0]["name"] == "alias"
            assert profiles[0]["password"] == "${SECRET:ADMIN_PASSWORD}"
            return deep_merge(raw, {"upstream": {"profiles": profiles}})

        config, _ = mutate_config(alias, mutation, write_rendered=False)
    assert config == load_config(alias)
    assert config.web.admin_totp_enabled
    assert config.web.admin_password == "alias-password"
    assert config.upstream.profiles[0].password == "alias-password"
    assert alias.is_symlink()


def test_public_guard_and_committed_candidate_share_environment_snapshot(
    symlink_config: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.api import routes_config

    _target, alias = symlink_config
    client, headers = _symlink_client(alias)
    original_guard = routes_config._validate_public_candidate
    guarded = []

    def guard(candidate: Any, previous: Any, path: Path) -> Any:
        result = original_guard(candidate, previous, path)
        guarded.append(result)
        alias.with_name(".env").write_text(
            "ADMIN_PASSWORD=rotated-password\nADMIN_TOTP_SECRET=KRSXG5DSNFXGOIDB\n"
            "KORNODE_WEB__ADMIN_TOTP_ENABLED=false\n"
        )
        return result

    monkeypatch.setattr(routes_config, "_validate_public_candidate", guard)
    response = client.patch(
        "/api/config",
        headers=headers,
        json={
            "patch": {"system": {"timezone": "Europe/Moscow"}},
            "write_rendered": False,
        },
    )
    assert response.status_code == 200, response.text
    assert client.app.state.config == guarded[0]
    assert client.app.state.config.web.admin_totp_enabled
    assert client.app.state.config.web.admin_password == "alias-password"
    # The snapshot is transaction-scoped, not a process-wide environment cache.
    assert load_config(alias).web.admin_password == "rotated-password"
    assert not load_config(alias).web.admin_totp_enabled


def test_explicit_env_file_is_shared_by_raw_callback_and_candidate(
    symlink_config: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.services.config_collections import raw_collection

    _target, alias = symlink_config
    explicit = alias.parent / "custom.env"
    explicit.write_text(
        "ADMIN_PASSWORD=explicit-password\nADMIN_TOTP_SECRET=JBSWY3DPEHPK3PXP\n"
        "KORNODE_WEB__ADMIN_TOTP_ENABLED=true\n"
        'KORNODE_UPSTREAM__PROFILES=[{"name":"explicit","server":"vpn.example.com",'
        '"username":"user"}]\n'
    )

    def mutation(raw: dict[str, Any]) -> dict[str, Any]:
        profiles = raw_collection(raw, alias, "upstream", "profiles")
        assert profiles[0]["name"] == "explicit"
        return deep_merge(raw, {"upstream": {"profiles": profiles}})

    config, _ = mutate_config(alias, mutation, env_file=explicit, write_rendered=False)
    assert config == load_config(alias, env_file=explicit)
    assert config.web.admin_password == "explicit-password"
    assert config.web.admin_totp_enabled
    monkeypatch.setitem(STATE, "config_path", alias)
    monkeypatch.setitem(STATE, "env_file", explicit)
    cli_config = save_config_patch({"system": {"timezone": "Europe/Moscow"}}, write_rendered=False)
    assert cli_config == load_config(alias, env_file=explicit)
    assert cli_config.web.admin_password == "explicit-password"
    assert cli_config.web.admin_totp_enabled
    assert alias.is_symlink()


def test_alternate_alias_validation_inside_callback_is_rejected(
    symlink_config: tuple[Path, Path],
) -> None:
    target, alias = symlink_config
    before = target.read_bytes()

    def mutation(raw: dict[str, Any]) -> dict[str, Any]:
        validate_config_data(raw, target)
        return raw

    with pytest.raises(ValueError, match="alternate configuration alias"):
        mutate_config(alias, mutation, write_rendered=False)
    assert target.read_bytes() == before


@pytest.mark.parametrize("when", ["waiting-for-lock", "inside-callback"])
def test_retargeted_symlink_is_rejected_before_commit(
    symlink_config: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    when: str,
) -> None:
    import fcntl

    from kornode.services.config_store import ConfigVersionConflict, config_lock

    target, alias = symlink_config
    other = target.with_name("other.yaml")
    other.write_bytes(target.read_bytes())
    original = target.read_bytes()

    def retarget() -> None:
        alias.unlink()
        alias.symlink_to(other)

    def mutation(raw: dict[str, Any]) -> dict[str, Any]:
        if when == "inside-callback":
            retarget()
        return deep_merge(raw, {"server": {"realm": "must not commit"}})

    if when == "inside-callback":
        with pytest.raises(ConfigVersionConflict):
            mutate_config(alias, mutation, write_rendered=False)
    else:
        attempted = Event()
        original_lock = fcntl.flock

        def observed_lock(fd: Any, operation: int) -> Any:
            if operation == fcntl.LOCK_EX:
                attempted.set()
            return original_lock(fd, operation)

        with ThreadPoolExecutor(max_workers=1) as pool:
            with config_lock(target):
                monkeypatch.setattr(fcntl, "flock", observed_lock)
                future = pool.submit(mutate_config, alias, mutation, write_rendered=False)
                assert attempted.wait(5)
                retarget()
            with pytest.raises(ConfigVersionConflict):
                future.result(timeout=5)
    assert target.read_bytes() == original
    assert other.read_bytes() == original


def test_public_source_validation_reads_one_environment_snapshot(
    symlink_config: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kornode.config import env

    _target, alias = symlink_config
    client, headers = _symlink_client(alias)
    source = client.get("/api/config/source").json()
    original_parse = env.parse_dotenv_file
    reads = []

    def changing_environment(path: Path | None) -> dict[str, str]:
        reads.append(path)
        values = original_parse(path)
        if len(reads) > 1:
            values["KORNODE_WEB__ADMIN_TOTP_ENABLED"] = "false"
            values["ADMIN_PASSWORD"] = "different-password"
        return values

    monkeypatch.setattr(env, "parse_dotenv_file", changing_environment)
    response = client.post(
        "/api/config/source/validate", headers=headers, json={"content": source["content"]}
    )
    assert response.status_code == 200, response.text
    assert response.json()["config"]["web"]["admin_totp_enabled"]
    assert reads == [alias.with_name(".env")]


def test_concurrent_alias_saves_share_lock_and_only_one_source_version_wins(
    symlink_config: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fcntl
    from threading import Lock

    from kornode.services.config_store import ConfigVersionConflict, config_lock

    target, alias = symlink_config
    version = source_etag(target)
    both_attempted, counter_lock = Event(), Lock()
    attempts = []
    original_lock = fcntl.flock

    def observed_lock(fd: Any, operation: int) -> Any:
        if operation == fcntl.LOCK_EX:
            with counter_lock:
                attempts.append(fd)
                if len(attempts) == 2:
                    both_attempted.set()
        return original_lock(fd, operation)

    def save(path: Path) -> Any:
        return mutate_config(
            path,
            lambda raw: deep_merge(raw, {"server": {"realm": path.parent.name}}),
            write_rendered=False,
            expected_etag=version,
        )

    winners, conflicts = [], []
    with ThreadPoolExecutor(max_workers=2) as pool:
        with config_lock(target):
            monkeypatch.setattr(fcntl, "flock", observed_lock)
            futures = [(path, pool.submit(save, path)) for path in (target, alias)]
            assert both_attempted.wait(5)
        for path, future in futures:
            try:
                config, _ = future.result(timeout=5)
            except ConfigVersionConflict:
                conflicts.append(path)
            else:
                winners.append(path)
                assert config == load_config(path)
    assert len(winners) == len(conflicts) == 1
    assert load_yaml_file(target)["server"]["realm"] == winners[0].parent.name
    assert source_etag(alias) == source_etag(target) != version
    assert alias.is_symlink()
