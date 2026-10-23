"""Certificate API writes/render/reload participate in the shared config transaction."""

from __future__ import annotations

import fcntl
import threading
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api import routes_certificates
from kornode.api.app import create_app
from kornode.config.loader import deep_merge, load_config
from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.config import ConfigService
from kornode.services.config_store import mutate_config
from kornode.services.server import ServerService
from kornode.services.server_certificates import ServerCertificatePaths, ServerCertificateService

AUTH = ("admin", "secret")


@pytest.fixture
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, Path]:
    monkeypatch.setenv("CERT_API_ADMIN", "secret")
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "system": {
                    key: str(tmp_path / key)
                    for key in ("data_dir", "log_dir", "generated_dir", "secrets_dir")
                },
                "web": {"enabled": True, "admin_password": "${SECRET:CERT_API_ADMIN}"},
            }
        )
    )
    monkeypatch.setattr(ConfigService, "render_files", lambda *_: [])
    monkeypatch.setattr(ConfigService, "write_rendered_files", lambda *_: [])
    return TestClient(create_app(config_path=path)), path


def assert_locked(path: Path) -> None:
    # A separate open file description must be unable to acquire the same inode.
    with (
        path.with_name(f".{path.name}.lock").open("a") as handle,
        pytest.raises(BlockingIOError),
    ):
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_certificate_save_serializes_with_other_writers_and_preserves_raw_refs(
    panel: tuple[TestClient, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, path = panel
    locked, release, contender, done = (threading.Event() for _ in range(4))
    failures: list[BaseException] = []
    responses = []

    def edit(raw: dict[str, Any]) -> dict[str, Any]:
        locked.set()
        assert release.wait(5)
        return deep_merge(raw, {"system": {"project_name": "concurrent-save"}})

    def other_writer() -> None:
        try:
            mutate_config(path, edit, write_rendered=False)
        except BaseException as exc:
            failures.append(exc)

    real_mutate = routes_certificates.mutate_config

    def tracked_mutate(*args: Any, **kwargs: Any) -> tuple[AppConfig, list[str]]:
        contender.set()
        return real_mutate(*args, **kwargs)

    monkeypatch.setattr(routes_certificates, "mutate_config", tracked_mutate)

    def save_certificate() -> None:
        try:
            responses.append(
                client.post(
                    "/api/certificates/settings",
                    auth=AUTH,
                    json={"mode": "auto", "ca_name": "Changed CA"},
                )
            )
        except BaseException as exc:
            failures.append(exc)
        finally:
            done.set()

    writer = threading.Thread(target=other_writer)
    writer.start()
    assert locked.wait(5)
    saver = threading.Thread(target=save_certificate)
    saver.start()
    try:
        assert contender.wait(5)
        assert not done.wait(0.1)
    finally:
        release.set()
        writer.join(5)
        saver.join(5)
    assert not writer.is_alive() and not saver.is_alive()
    assert not failures
    assert responses[0].status_code == 200, responses[0].text
    raw = yaml.safe_load(path.read_text())
    assert raw["system"]["project_name"] == "concurrent-save"
    assert raw["certificates"]["ca_name"] == "Changed CA"
    assert raw["web"]["admin_password"] == "${SECRET:CERT_API_ADMIN}"
    assert client.app.state.config.system.project_name == "concurrent-save"


@pytest.mark.parametrize("fail_reload", [False, True])
def test_activation_renders_once_then_reloads_authoritative_candidate_inside_lock(
    panel: tuple[TestClient, Path], monkeypatch: pytest.MonkeyPatch, fail_reload: bool
) -> None:
    client, path = panel
    material = ServerCertificatePaths(
        path.parent / "server.crt", path.parent / "server.key", path.parent / "ca.crt"
    )
    monkeypatch.setattr(
        ServerCertificateService, "save_external_material", lambda *_a, **_k: material
    )
    rendered: list[AppConfig] = []
    reloaded: list[AppConfig] = []

    def render(service: ConfigService, config: AppConfig) -> list[Path]:
        assert_locked(path)
        assert service.strict_apply
        assert client.app.state.config is config
        rendered.append(config)
        return []

    def reload(service: ServerService, *, dry_run: bool = False) -> CommandResult:
        assert_locked(path)
        assert not dry_run
        assert service.config is rendered[-1]
        reloaded.append(service.config)
        if fail_reload:
            raise RuntimeError("private-key-material-must-not-escape")
        return CommandResult(("supervisor-rpc", "signalProcess", "ocserv", "HUP"), 0, "", "")

    monkeypatch.setattr(ConfigService, "write_rendered_files", render)
    monkeypatch.setattr(ServerService, "reload", reload)
    # There must be no post-commit load/apply of an independently read snapshot.
    monkeypatch.setattr(routes_certificates, "load_config", lambda *_: pytest.fail("stale reload"))
    response = client.post(
        "/api/certificates/external",
        auth=AUTH,
        data={"reload": "true"},
        files={
            "server_cert": ("server.crt", b"certificate"),
            "server_key": ("server.key", b"key"),
            "ca_cert": ("ca.crt", b"ca"),
        },
    )
    assert response.status_code == (500 if fail_reload else 200), response.text
    assert len(rendered) == len(reloaded) == 1
    assert load_config(path).certificates.server_cert == material.server_cert
    if fail_reload:
        assert response.json()["detail"]["status"] == "saved_but_not_applied"
        assert response.json()["detail"]["saved"] is True
        assert "private-key-material" not in response.text


def test_certificate_preflight_failure_does_not_persist_or_reload(
    panel: tuple[TestClient, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, path = panel
    original = path.read_bytes()

    def fail(*_: object) -> None:
        raise RuntimeError("private-value-must-not-escape")

    monkeypatch.setattr(ConfigService, "render_files", fail)
    monkeypatch.setattr(ServerService, "reload", lambda *_a, **_k: pytest.fail("unexpected reload"))
    response = client.post(
        "/api/certificates/settings", auth=AUTH, json={"mode": "auto", "ca_name": "Do not save"}
    )
    assert response.status_code == 500
    assert response.json()["detail"]["status"] == "not_saved"
    assert path.read_bytes() == original
    assert "private-value" not in response.text


def test_renewal_rereads_latest_config_and_renders_reloads_under_shared_lock(
    panel: tuple[TestClient, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, path = panel
    applied = []

    def renew(*_a: object, **_k: object) -> CommandResult:
        mutate_config(
            path,
            lambda raw: deep_merge(raw, {"system": {"project_name": "changed-during-acme"}}),
            write_rendered=False,
        )
        return CommandResult(("certbot", "renew"), 0, "", "")

    def render(_service: ConfigService, config: AppConfig) -> list[Path]:
        assert_locked(path)
        assert config.system.project_name == "changed-during-acme"
        assert client.app.state.config is config
        applied.append(config)
        return []

    def reload(service: ServerService, *, dry_run: bool = False) -> CommandResult:
        assert_locked(path)
        assert service.config is applied[-1]
        return CommandResult(("supervisor-rpc", "signalProcess", "ocserv", "HUP"), 0, "", "")

    monkeypatch.setattr(ServerCertificateService, "renew_letsencrypt", renew)
    monkeypatch.setattr(ConfigService, "write_rendered_files", render)
    monkeypatch.setattr(ServerService, "reload", reload)
    response = client.post("/api/certificates/letsencrypt/renew", auth=AUTH, json={})
    assert response.status_code == 200, response.text
    assert len(applied) == 1
