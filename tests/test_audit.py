from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.config.models import AppConfig
from kornode.services.audit import AuditService


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "log_dir": tmp_path / "logs",
                "secrets_dir": tmp_path / "secrets",
            },
            "web": {"admin_password": "secret"},
        }
    )


def test_audit_service_writes_restrictive_json_lines(tmp_path: Path) -> None:
    service = AuditService(_config(tmp_path))

    service.record(
        actor="admin",
        action="POST /api/config/render",
        outcome="success",
        source_ip="127.0.0.1",
    )

    path = tmp_path / "logs" / "audit.jsonl"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["actor"] == "admin"
    assert payload["action"] == "POST /api/config/render"
    assert path.stat().st_mode & 0o777 == 0o600


def test_mutating_api_request_is_audited_without_credentials(tmp_path: Path) -> None:
    config = _config(tmp_path)
    client = TestClient(create_app(config))

    response = client.post("/api/config/render", auth=("admin", "secret"))

    assert response.status_code == 200
    content = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8")
    assert '"actor":"admin"' in content
    assert '"action":"POST /api/config/render"' in content
    assert "secret" not in content


def test_mutation_succeeds_even_when_the_audit_log_write_fails(tmp_path: Path) -> None:
    # Regression test: AuditService.record() was called unconditionally with
    # no exception handling in the security_headers middleware, AFTER the
    # mutating action already fully executed. A write failure (disk full,
    # permissions, a read-only mount) used to propagate as an unhandled 500
    # through Starlette's BaseHTTPMiddleware, giving the client no
    # indication the underlying action actually succeeded.
    config = _config(tmp_path)
    client = TestClient(create_app(config))
    audit_path = tmp_path / "logs" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    # Pre-create the log path AS A DIRECTORY: os.open(..., O_WRONLY) on it
    # raises IsADirectoryError (an OSError subclass), simulating a write
    # failure without needing to mock internals.
    audit_path.mkdir()

    response = client.post("/api/config/render", auth=("admin", "secret"))

    assert response.status_code == 200
