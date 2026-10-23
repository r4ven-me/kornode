"""GUI integration contracts for source versions, server actions and CA errors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.api.routes_server import ocserv_apply_result
from kornode.config.loader import load_config
from kornode.services.command import CommandResult
from kornode.services.config import ConfigService
from kornode.services.server import ServerService
from kornode.services.server_certificates import ServerCertificateService

AUTH = ("admin", "secret")


@pytest.fixture
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, Path]:
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
    monkeypatch.setattr(ConfigService, "write_rendered_files", lambda *_: [])
    return TestClient(create_app(config_path=path)), path


@pytest.mark.parametrize("transport", ["header", "body"])
def test_source_version_round_trip_and_conflicts_do_not_overwrite(
    panel: tuple[TestClient, Path], transport: str
) -> None:
    client, path = panel
    source = client.get("/api/config/source", auth=AUTH)
    initial_etag = etag = source.json()["etag"]
    assert etag == source.headers["ETag"]
    candidate = yaml.safe_load(source.json()["content"])
    candidate["system"]["project_name"] = "source-editor"
    content = yaml.safe_dump(candidate)
    original = path.read_bytes()
    missing = client.post(
        "/api/config/source", auth=AUTH, json={"content": content, "write_rendered": False}
    )
    assert missing.status_code == 428
    assert path.read_bytes() == original

    # A structured save changes the source while the editor retains its old draft.
    changed = client.post(
        "/api/config/general-settings", auth=AUTH, json={"project_name": "another-administrator"}
    )
    assert changed.status_code == 200, changed.text
    latest = path.read_bytes()
    stale = client.post(
        "/api/config/source",
        auth=AUTH,
        headers={"If-Match": etag},
        json={"content": content, "write_rendered": False},
    )
    assert stale.status_code == 412
    assert path.read_bytes() == latest
    source = client.get("/api/config/source", auth=AUTH)
    etag = source.json()["etag"]
    assert etag != initial_etag
    assert etag == source.headers["ETag"]
    options = {"content": content, "write_rendered": False}
    headers = {"If-Match": etag} if transport == "header" else {}
    if transport == "body":
        options["etag"] = etag
    saved = client.post("/api/config/source", auth=AUTH, headers=headers, json=options)
    assert saved.status_code == 200, saved.text
    assert saved.json()["etag"] == saved.headers["ETag"]
    assert saved.json()["etag"] != etag
    assert client.get("/api/config/source", auth=AUTH).json()["etag"] == saved.json()["etag"]
    assert load_config(path).system.project_name == "source-editor"
    assert load_config(path).web.admin_password == "secret"


@pytest.mark.parametrize(
    "rpc,action",
    [
        ("startProcess", "start"),
        ("stopProcess", "stop"),
        ("restartProcess", "restart"),
        ("signalProcess", "reload"),
    ],
)
def test_ocserv_apply_result_reports_the_actual_action(rpc: str, action: str) -> None:
    result = CommandResult(("supervisor-rpc", rpc, "ocserv"), 0, "done", "", True)
    actual = ocserv_apply_result(result)
    assert actual is not None
    assert actual["argv"] == ["korctl", "server", action]
    assert actual["dry_run"] is True
    assert actual["stdout"] == "done"


def test_ocserv_apply_result_does_not_call_a_failed_status_query_a_reload() -> None:
    result = CommandResult(("supervisor-rpc", "getProcessInfo", "ocserv"), 1, "", "unavailable")
    actual = ocserv_apply_result(result)
    assert actual is not None
    assert actual["argv"] == list(result.argv)
    assert actual["returncode"] == 1
    assert ocserv_apply_result(None) is None


def test_enabled_transitions_apply_even_when_reload_is_false(
    panel: tuple[TestClient, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, path = panel
    applied = []

    def apply(service: ServerService, previous: str) -> CommandResult:
        applied.append(service.config.server.enabled)
        rpc = "startProcess" if service.config.server.enabled else "stopProcess"
        return CommandResult(("supervisor-rpc", rpc, "ocserv"), 0, "done", "")

    monkeypatch.setattr(ServerService, "apply_config_change", apply)
    for enabled, action in ((True, "start"), (False, "stop")):
        response = client.post(
            "/api/server/settings", auth=AUTH, json={"enabled": enabled, "reload": False}
        )
        assert response.status_code == 200, response.text
        assert response.json()["reload"]["argv"] == ["korctl", "server", action]
        assert load_config(path).server.enabled is enabled
    assert applied == [True, False]
    response = client.post(
        "/api/server/settings",
        auth=AUTH,
        json={"enabled": False, "max_clients": 100, "reload": False},
    )
    assert response.status_code == 200
    assert response.json()["reload"] is None
    assert applied == [True, False]


@pytest.mark.parametrize("material", ["partial-key", "partial-cert", "invalid-pair"])
def test_letsencrypt_ca_errors_are_actionable_safe_and_preserve_material(
    panel: tuple[TestClient, Path], monkeypatch: pytest.MonkeyPatch, material: str
) -> None:
    client, path = panel
    config = load_config(path)
    key, crt = config.cert_path("ca.key"), config.cert_path("ca.crt")
    key.parent.mkdir(parents=True, exist_ok=True)
    if material != "partial-cert":
        key.write_text("private-key-content-must-not-be-returned")
    if material != "partial-key":
        crt.write_text("invalid-ca-content-must-not-be-returned")
    originals = {p: p.read_bytes() for p in (key, crt) if p.exists()}
    original_config = path.read_bytes()
    monkeypatch.setattr(
        ServerCertificateService,
        "issue_letsencrypt",
        lambda *_a, **_k: CommandResult(("certbot",), 0, "issued", ""),
    )
    response = client.post(
        "/api/certificates/letsencrypt/issue",
        auth=AUTH,
        json={"email": "admin@example.com", "domains": ["vpn.example.com"]},
    )
    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "certificate authority is incomplete or invalid" in detail
    assert "Restore" in detail and "explicitly regenerate" in detail
    assert "private-key-content" not in response.text
    assert "invalid-ca-content" not in response.text
    assert str(key.parent) not in response.text
    assert path.read_bytes() == original_config
    assert {p: p.read_bytes() for p in (key, crt) if p.exists()} == originals


def test_signing_path_save_never_opens_or_creates_key_material(
    panel: tuple[TestClient, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, config_path = panel
    existing = config_path.parent / "existing-signing.pem"
    missing = config_path.parent / "new" / "signing.pem"
    material = b"private-material-never-returned"
    existing.write_bytes(material)
    open_path = Path.open

    def guarded_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path in (existing, missing):
            pytest.fail("settings save must never open a signing key")
        return open_path(path, *args, **kwargs)

    def forbid_render(*_a: object, **_k: object) -> None:
        pytest.fail("control settings must not render runtime files")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", guarded_open)
        patch.setattr(ConfigService, "write_rendered_files", forbid_render)
        for selected in (existing, missing):
            response = client.post(
                "/api/web-config/control-settings", auth=AUTH, json={"signing_key": str(selected)}
            )
            assert response.status_code == 200, response.text
            assert response.json()["control"]["signing_key"] == str(selected)
            assert response.json()["written"] == []
            assert "private-material" not in response.text
    assert existing.read_bytes() == material
    assert not missing.exists()
    original = config_path.read_bytes()
    response = client.post(
        "/api/web-config/control-settings",
        auth=AUTH,
        json={
            "signing_key": (
                "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"
            )
        },
    )
    assert response.status_code == 422
    assert "private-material" not in response.text
    assert config_path.read_bytes() == original
