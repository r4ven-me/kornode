from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from tests.test_hub_backup import PASSWORD  # noqa: F401
from tests.test_hub_backup import hub as hub
from typer.testing import CliRunner

from kornode.api.app import create_app
from kornode.cli import app
from kornode.config.models import AppConfig


def client_for(hub: Any) -> TestClient:
    config = hub.config.model_dump(mode="json")
    config["web"]["admin_password"] = "admin-password"
    return TestClient(create_app(AppConfig.model_validate(config)), base_url="https://testserver")


def headers() -> dict[str, str]:
    return {"X-Kornode-Backup-Passphrase": base64.b64encode(PASSWORD.encode()).decode()}


def test_admin_auth_csrf_and_no_store(hub: Any) -> None:
    client = client_for(hub)
    for path in ("backup", "restore"):
        response = client.post("/api/hub/" + path)
        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"
    login = client.post("/api/auth/login", json={"username": "admin", "password": "admin-password"})
    for path in ("backup", "restore"):
        assert client.post("/api/hub/" + path).status_code == 403
    csrf = {"X-Kornode-CSRF": login.json()["csrf_token"]}
    response = client.post("/api/hub/backup", json={"passphrase": PASSWORD}, headers=csrf)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert ".knbackup" in response.headers["content-disposition"]
    assert PASSWORD.encode() not in response.content
    before = hub.config.cert_path("ca.key").read_bytes()
    preview = client.post(
        "/api/hub/restore", content=response.content, headers={**csrf, **headers()}
    )
    assert preview.status_code == 200 and preview.json()["dry_run"]
    refused = client.post(
        "/api/hub/restore?dry_run=false", content=response.content, headers={**csrf, **headers()}
    )
    assert refused.status_code == 422
    result = client.post(
        "/api/hub/restore?dry_run=false&confirm=restore",
        content=response.content,
        headers={**csrf, **headers()},
    )
    assert result.status_code == 200 and result.json()["staged"]
    assert Path(result.json()["config_path"]).is_file()
    assert before == hub.config.cert_path("ca.key").read_bytes()
    audit = (hub.config.system.log_dir / "audit.jsonl").read_text()
    assert PASSWORD not in audit and headers()["X-Kornode-Backup-Passphrase"] not in audit


@pytest.mark.parametrize(
    "body", [b'{"passphrase":"secret"', b'"secret"', b'{"passphrase":42}', b"x" * 8193]
)
def test_api_invalid_input_is_bounded_and_never_echoed(hub: Any, body: bytes) -> None:
    response = client_for(hub).post(
        "/api/hub/backup", auth=("admin", "admin-password"), content=body
    )
    assert response.status_code in (413, 422)
    assert "secret" not in response.text and response.headers["cache-control"] == "no-store"


def test_restore_oversize_rejected_before_decryption(
    hub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("kornode.api.routes_hub.MAX_ARCHIVE", 32)
    response = client_for(hub).post(
        "/api/hub/restore", auth=("admin", "admin-password"), headers=headers(), content=b"x" * 33
    )
    assert response.status_code == 413


def test_cli_backup_restore_without_web_and_without_secret_output(hub: Any, tmp_path: Path) -> None:
    config = tmp_path / "hub.yaml"
    config.write_text(yaml.safe_dump(hub.config.model_dump(mode="json")))
    password_file = tmp_path / "passphrase"
    password_file.write_text(PASSWORD + "\n")
    password_file.chmod(0o600)
    output = tmp_path / "backup.knbackup"
    runner = CliRunner()
    prefix = ["--config", str(config), "hub"]
    backup = runner.invoke(
        app,
        [
            *prefix,
            "backup",
            "--out",
            str(output),
            "--passphrase-file",
            str(password_file),
            "--json",
        ],
    )
    assert backup.exit_code == 0, backup.output
    assert json.loads(backup.stdout)["encrypted"]
    target = tmp_path / "restored"
    args = [
        *prefix,
        "restore",
        str(output),
        "--passphrase-file",
        str(password_file),
        "--target",
        str(target),
        "--json",
    ]
    refused = runner.invoke(app, args)
    assert refused.exit_code == 2 and not target.exists()
    preview = runner.invoke(app, [*args, "--dry-run"])
    assert preview.exit_code == 0 and json.loads(preview.stdout)["dry_run"] and not target.exists()
    restored = runner.invoke(app, [*args, "--yes"])
    assert restored.exit_code == 0 and json.loads(restored.stdout)["staged"]
    for result in (backup, refused, preview, restored):
        assert PASSWORD not in result.output and "PRIVATE KEY" not in result.output
    assert hub.config.web.enabled is False


def test_cli_json_never_prompts_for_passphrase(hub: Any, tmp_path: Path) -> None:
    config = tmp_path / "hub.yaml"
    config.write_text(yaml.safe_dump(hub.config.model_dump(mode="json")))
    result = CliRunner().invoke(app, ["--config", str(config), "hub", "backup", "--json"])
    assert result.exit_code == 2 and json.loads(result.stdout)["error"] == "passphrase_required"
