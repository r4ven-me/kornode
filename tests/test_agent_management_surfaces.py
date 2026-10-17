from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.test_agent_management import world as world  # noqa: F401
from typer.testing import CliRunner

from kornode.api.app import create_app
from kornode.cli import app
from kornode.config.models import AppConfig


def client_for(world: Any) -> TestClient:
    env, service, _, _ = world
    data = env.config.model_dump(mode="json")
    data["web"]["admin_password"] = "admin-secret"
    application = create_app(AppConfig.model_validate(data))
    application.state.agent_management = service
    return TestClient(application, base_url="https://testserver")


def test_api_auth_crud_and_no_store(world: Any) -> None:
    client = client_for(world)
    checked = 0
    params = dict(
        name="branch", source="wg", upstream="office", username="alice", version=1, command_id="cmd"
    )
    for path, operations in client.app.openapi()["paths"].items():
        if not path.startswith(("/api/agents", "/api/control")):
            continue
        for method in operations.keys() & {"get", "post", "put", "patch", "delete"}:
            response = client.request(method, path.format(**params))
            assert response.status_code == 401, (method, path, response.text)
            assert response.headers["cache-control"] == "no-store"
            checked += 1
    assert checked == 32
    auth = ("admin", "admin-secret")
    created = client.post("/api/agents", auth=auth, json={"name": "branch"})
    assert created.status_code == 200 and created.json()["token"] == "one-time-token"
    assert created.headers["cache-control"] == "no-store"
    listed = client.get("/api/agents", auth=auth).json()
    assert "one-time-token" not in json.dumps(listed)
    assert client.get("/api/agents/branch", auth=auth).json()["id"] == 2
    patched = client.patch("/api/agents/branch", auth=auth, json={"description": "changed"})
    assert patched.status_code == 200 and patched.json()["description"] == "changed"
    assert client.request("DELETE", "/api/agents/branch", auth=auth, json={"dry_run": True}).json()[
        "dry_run"
    ]


def test_api_cookie_mutation_requires_csrf_and_validation_hides_secrets(world: Any) -> None:
    client = client_for(world)
    login = client.post("/api/auth/login", json={"username": "admin", "password": "admin-secret"})
    assert login.status_code == 200
    params = dict(
        name="branch", source="wg", upstream="office", username="alice", version=1, command_id="cmd"
    )
    for path, operations in client.app.openapi()["paths"].items():
        if path.startswith(("/api/agents", "/api/control")):
            for method in operations.keys() & {"post", "put", "patch", "delete"}:
                response = client.request(method, path.format(**params), json={})
                assert response.status_code == 403, (method, path, response.text)
    headers = {"X-Kornode-CSRF": login.json()["csrf_token"]}
    invalid = client.post(
        "/api/agents",
        headers=headers,
        json={"name": "SECRET-invalid-NAME", "password": "sensitive-value"},
    )
    assert invalid.status_code == 422
    assert "sensitive-value" not in invalid.text and "SECRET-invalid-NAME" not in invalid.text
    malformed = client.post("/api/agents", headers=headers, content='{"secret":"private-value"')
    assert malformed.status_code == 422 and "private-value" not in malformed.text
    oversized = client.post("/api/agents", headers=headers, content=b"x" * (1024 * 1024 + 1))
    assert oversized.status_code == 413 and oversized.headers["cache-control"] == "no-store"


def test_cli_calls_shared_service_and_confirms_destruction(
    world: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import yaml

    env, service, _, _ = world
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump(env.config.model_dump(mode="json")))
    monkeypatch.setattr("kornode.cli_agents.AgentService", lambda config: service)
    runner = CliRunner()
    prefix = ["--config", str(config), "agent"]
    result = runner.invoke(app, [*prefix, "create", "branch", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["agent"]["id"] == 2
    listed = runner.invoke(app, [*prefix, "list", "--json"])
    assert listed.exit_code == 0 and "one-time-token" not in listed.stdout
    refused = runner.invoke(app, [*prefix, "delete", "branch", "--json"])
    assert refused.exit_code == 2
    assert service.show("branch")
    preview = runner.invoke(app, [*prefix, "delete", "branch", "--dry-run", "--json"])
    assert preview.exit_code == 0 and json.loads(preview.stdout)["revoke_first"]
    deleted = runner.invoke(app, [*prefix, "delete", "branch", "--yes", "--json"])
    assert deleted.exit_code == 0
