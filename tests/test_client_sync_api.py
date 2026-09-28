from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.services.sessions import SessionRecord, SessionService


def _client(config_path: Path, tmp_path: Path) -> TestClient:
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  log_dir: {tmp_path}/logs
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
server:
  routes:
    - 10.20.0.0/16
  search_domains:
    - corp.example.com
identity:
  config_per_user_dir: {tmp_path}/generated/config-per-user
web:
  enabled: true
  admin_password: secret
auth:
  password:
    enabled: true
""",
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=config_path))


def _fake_sessions(monkeypatch: pytest.MonkeyPatch, records: list[SessionRecord]) -> None:
    monkeypatch.setattr(SessionService, "list_sessions", lambda self: records)


def test_client_routing_requires_vpn_source_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)
    _fake_sessions(monkeypatch, [SessionRecord(username="alice", vpn_ip="10.10.10.5")])

    # TestClient requests come from "testclient" host outside the VPN subnet.
    response = client.get("/api/client/routing")

    assert response.status_code == 403


def test_client_routing_merges_server_group_and_user_lists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    _fake_sessions(monkeypatch, [SessionRecord(username="alice", vpn_ip="10.10.10.5")])

    passwd = tmp_path / "secrets" / "ocpasswd"
    passwd.parent.mkdir(parents=True, exist_ok=True)
    passwd.write_text("alice:devops:$5$fakesalt$fakehash\n", encoding="utf-8")
    group_dir = tmp_path / "generated" / "config-per-group"
    group_dir.mkdir(parents=True, exist_ok=True)
    (group_dir / "devops").write_text(
        "route = 192.168.25.0/24\nsplit-dns = devops.example.com\n",
        encoding="utf-8",
    )
    user_dir = tmp_path / "generated" / "config-per-user"
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "alice").write_text(
        "route = 203.0.113.0/24\nsplit-dns = kernel.org\n",
        encoding="utf-8",
    )

    response = client.get(
        "/api/client/routing",
        headers={"X-Forwarded-For": "ignored"},
    )
    # Source address is not in the VPN subnet in tests; patch the check by
    # calling the handler through a client bound to a VPN address instead.
    assert response.status_code == 403

    vpn_client = TestClient(client.app, client=("10.10.10.5", 50000))
    response = vpn_client.get("/api/client/routing")

    assert response.status_code == 200
    payload = response.json()
    assert payload["username"] == "alice"
    assert payload["routes"] == ["10.20.0.0/16", "192.168.25.0/24", "203.0.113.0/24"]
    assert payload["split_dns"] == ["corp.example.com", "devops.example.com", "kernel.org"]
    assert len(payload["version"]) == 16

    repeat = vpn_client.get("/api/client/routing").json()
    assert repeat["version"] == payload["version"]


def test_client_routing_rejects_unknown_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)
    _fake_sessions(monkeypatch, [])

    vpn_client = TestClient(client.app, client=("10.10.10.5", 50000))
    assert vpn_client.get("/api/client/routing").status_code == 403


def test_client_routing_needs_no_admin_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)
    _fake_sessions(monkeypatch, [SessionRecord(username="bob", vpn_ip="10.10.10.7")])

    vpn_client = TestClient(client.app, client=("10.10.10.7", 50000))
    response = vpn_client.get("/api/client/routing")

    assert response.status_code == 200
    assert response.json()["username"] == "bob"
