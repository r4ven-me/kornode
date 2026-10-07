from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app


def _client(config_path: Path, tmp_path: Path) -> TestClient:
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  log_dir: {tmp_path}/logs
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
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


def test_upstream_settings_saves_failover_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/settings",
        auth=("admin", "secret"),
        json={
            "enabled": False,
            "check_interval": 10,
            "check_threshold": 5,
            "failover": True,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["check_interval"] == 10
    assert saved["upstream"]["check_threshold"] == 5
    assert saved["upstream"]["failover"] is True


def test_upstream_settings_saves_check_settle_seconds(tmp_path: Path) -> None:
    # check_settle_seconds previously had no GUI/API control at all -- an
    # admin could only change it by hand-editing the raw YAML tab, per
    # AGENTS.md's "every AppConfig field needs a structured control" rule.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/settings",
        auth=("admin", "secret"),
        json={"enabled": False, "check_settle_seconds": 30},
    )

    assert response.status_code == 200
    assert response.json()["upstream"]["check_settle_seconds"] == 30
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["check_settle_seconds"] == 30


def test_upstream_settings_saves_connect_on_boot(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/settings",
        auth=("admin", "secret"),
        json={"enabled": False, "connect_on_boot": False},
    )

    assert response.status_code == 200
    assert response.json()["upstream"]["connect_on_boot"] is False
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["connect_on_boot"] is False


def test_upstream_profile_saves_host_routing_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "finance",
            "server": "vpn.example.com",
            "auth_type": "password",
            "username": "user",
            "password": "secret",
            "route_clients_enabled": False,
            "route_host_enabled": True,
            "host_routes": ["10.90.0.0/16"],
            "host_domains": ["finance-internal.corp"],
            "enable": True,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    profile = saved["upstream"]["profiles"][0]
    assert profile["route_clients_enabled"] is False
    assert profile["route_host_enabled"] is True
    assert profile["host_routes"] == ["10.90.0.0/16"]
    assert profile["host_domains"] == ["finance-internal.corp"]


def test_upstream_settings_response_masks_profile_camouflage_secret(tmp_path: Path) -> None:
    # Regression test: this endpoint's response used its own separate
    # exclude set (password/cert_pass/cert_file_base64/key_file_base64)
    # that never included camouflage_secret, leaking it in plaintext here
    # even after the other /api/upstream/* endpoints were fixed.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "password",
            "username": "user",
            "password": "pw",
            "camouflage_secret": "camo-secret",
        },
    )

    response = client.post(
        "/api/upstream/settings",
        auth=("admin", "secret"),
        json={"enabled": True, "check_interval": 10},
    )

    assert response.status_code == 200
    payload = response.json()
    assert "camo-secret" not in str(payload)
    assert payload["upstream"]["profiles"][0]["camouflage_secret"] == "***"


def test_upstream_profile_saves_cert_pass_but_never_returns_it(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
            "cert_pass": "super-secret",
            "server_cert_pin": "pin-sha256:abc123",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert "super-secret" not in str(payload)
    assert payload["profiles"][0]["server_cert_pin"] == "pin-sha256:abc123"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][0]["cert_pass"] == "super-secret"


def test_upstream_profile_edit_without_secrets_preserves_them(tmp_path: Path) -> None:
    # Regression test: editing a profile via the UI can never re-send a
    # write-only secret (the GET response never returns it), so omitting it
    # must keep the previously saved value instead of wiping it out.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
            "cert_pass": "super-secret",
        },
    )

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
            "check_host": "1.1.1.1",
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][0]["cert_pass"] == "super-secret"
    assert saved["upstream"]["profiles"][0]["check_host"] == "1.1.1.1"


def test_upstream_profile_saves_camouflage_secret_but_never_returns_it(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "password",
            "username": "user",
            "password": "pw",
            "camouflage_secret": "camo-secret",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert "camo-secret" not in str(payload)
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][0]["camouflage_secret"] == "camo-secret"


def test_upstream_profile_response_masks_base64_cert_and_key_material(tmp_path: Path) -> None:
    # cert_file_base64/key_file_base64 don't match is_secret_key()'s generic
    # name pattern (password/token/secret/etc.) at all, so _safe_profile_dump()
    # needs an explicit override for them alongside the generic check.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "p12",
            "cert_file_base64": "aGVsbG8=",
            "key_file_base64": "d29ybGQ=",
        },
    )

    assert response.status_code == 200
    profile = response.json()["profiles"][0]
    assert profile["cert_file_base64"] == "***"
    assert profile["key_file_base64"] == "***"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][0]["cert_file_base64"] == "aGVsbG8="
    assert saved["upstream"]["profiles"][0]["key_file_base64"] == "d29ybGQ="


def test_upstream_profile_edit_without_camouflage_secret_preserves_it(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "password",
            "username": "user",
            "password": "pw",
            "camouflage_secret": "camo-secret",
        },
    )

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "password",
            "username": "user",
            "check_host": "1.1.1.1",
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][0]["camouflage_secret"] == "camo-secret"


def test_upstream_profile_edit_can_switch_cert_source_from_path_to_base64(
    tmp_path: Path,
) -> None:
    # Explicitly switching source modes must not be treated as "left blank":
    # providing cert_file_base64 drops the old cert_file path.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
        },
    )

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "p12",
            "cert_file_base64": "aGVsbG8=",
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][0]["cert_file_base64"] == "aGVsbG8="
    assert saved["upstream"]["profiles"][0].get("cert_file") is None


def test_delete_upstream_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
        },
    )

    response = client.delete("/api/upstream/profiles/primary", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json()["profiles"] == []
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"] == []
    assert saved["upstream"]["active_profile"] is None
    assert saved["upstream"]["enabled"] is False


def test_delete_upstream_profile_reassigns_active_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    for name in ("primary", "backup"):
        client.post(
            "/api/upstream/profiles",
            auth=("admin", "secret"),
            json={
                "name": name,
                "server": "vpn.upstream.example.com",
                "auth_type": "p12",
                "cert_file": "/certs/client.p12",
            },
        )

    response = client.delete("/api/upstream/profiles/backup", auth=("admin", "secret"))

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert [item["name"] for item in saved["upstream"]["profiles"]] == ["primary"]
    assert saved["upstream"]["active_profile"] == "primary"


def test_set_profile_enabled_persists_the_flag(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.upstream.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
        },
    )

    response = client.post(
        "/api/upstream/profiles/primary/enabled",
        auth=("admin", "secret"),
        json={"enabled": False},
    )

    assert response.status_code == 200
    assert response.json()["profiles"][0]["enabled"] is False
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][0]["enabled"] is False


def test_set_profile_enabled_does_not_touch_other_profiles(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    for name in ("primary", "backup"):
        client.post(
            "/api/upstream/profiles",
            auth=("admin", "secret"),
            json={
                "name": name,
                "server": "vpn.upstream.example.com",
                "auth_type": "p12",
                "cert_file": "/certs/client.p12",
            },
        )

    response = client.post(
        "/api/upstream/profiles/backup/enabled",
        auth=("admin", "secret"),
        json={"enabled": False},
    )

    assert response.status_code == 200
    by_name = {item["name"]: item["enabled"] for item in response.json()["profiles"]}
    assert by_name == {"primary": True, "backup": False}


def test_set_profile_enabled_rejects_unknown_profile(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.post(
        "/api/upstream/profiles/ghost/enabled",
        auth=("admin", "secret"),
        json={"enabled": False},
    )

    assert response.status_code == 404


def test_upstream_status_reports_not_connected_by_default(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.get("/api/upstream/status", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json()["connected"] is False


def test_upstream_disconnect_is_a_noop_when_not_connected(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post("/api/upstream/disconnect", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json()["stdout"] == "not connected"


def test_upstream_profile_connect_endpoint_dry_run(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "backup",
            "server": "backup.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
            "interface": "oc-backup0",
        },
    )

    response = client.post(
        "/api/upstream/profiles/backup/connect",
        auth=("admin", "secret"),
        json={"dry_run": True},
    )

    assert response.status_code == 200
    assert response.json()["dry_run"] is True

    profiles = client.get("/api/upstream", auth=("admin", "secret")).json()
    assert profiles[0]["interface"] == "oc-backup0"


def test_upstream_profile_disconnect_endpoint_noop(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "backup",
            "server": "backup.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
        },
    )

    response = client.post("/api/upstream/profiles/backup/disconnect", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json()["stdout"] == "not connected"


def test_upstream_status_includes_connections_list(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.example.com",
            "auth_type": "p12",
            "cert_file": "/certs/client.p12",
        },
    )

    payload = client.get("/api/upstream/status", auth=("admin", "secret")).json()

    assert payload["connected"] is False
    assert payload["local_ip"] is None
    assert payload["connections"][0]["profile"] == "primary"
    assert payload["connections"][0]["connected"] is False


def test_upstream_profile_saves_routes_and_domains(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "finance",
            "server": "finance.example.com",
            "auth_type": "password",
            "username": "user",
            "routes": ["10.50.0.0/16"],
            "domains": ["finance-internal.corp"],
            "routes_urls": ["https://lists.example.com/finance-routes.txt"],
            "domains_urls": ["https://lists.example.com/finance-domains.txt"],
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    profile = saved["upstream"]["profiles"][0]
    assert profile["routes"] == ["10.50.0.0/16"]
    assert profile["domains"] == ["finance-internal.corp"]
    assert profile["routes_urls"] == ["https://lists.example.com/finance-routes.txt"]
    assert profile["domains_urls"] == ["https://lists.example.com/finance-domains.txt"]


def test_profile_relay_source_status_and_refresh_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config.yaml"
    route_url = "https://lists.example.com/routes.txt"
    domain_url = "https://lists.example.com/domains.txt"
    client = _client(config_path, tmp_path)
    saved = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "finance",
            "server": "finance.example.com",
            "username": "user",
            "routes_urls": [route_url],
            "domains_urls": [domain_url],
        },
    )
    assert saved.status_code == 200

    status = client.get(
        "/api/upstream/profiles/finance/routes-sources/status",
        auth=("admin", "secret"),
    )
    assert status.status_code == 200
    assert "files" not in status.json()
    assert status.json()["urls"][0]["url"] == route_url

    unknown = client.get(
        "/api/upstream/profiles/missing/routes-sources/status",
        auth=("admin", "secret"),
    )
    assert unknown.status_code == 404
    unsaved = client.post(
        "/api/upstream/profiles/finance/routes-sources/refresh",
        auth=("admin", "secret"),
        json={"url": "https://lists.example.com/other.txt", "preview": True},
    )
    assert unsaved.status_code == 400

    monkeypatch.setattr(
        "kornode.services.external_lists.fetch_url_text",
        lambda url, **kwargs: (
            "10.70.0.0/16\ninvalid\n" if url == route_url else "corp.example.com\ninvalid_domain!\n"
        ),
    )
    route_refresh = client.post(
        "/api/upstream/profiles/finance/routes-sources/refresh",
        auth=("admin", "secret"),
        json={"url": route_url, "preview": True},
    )
    domain_refresh = client.post(
        "/api/upstream/profiles/finance/domains-sources/refresh",
        auth=("admin", "secret"),
        json={"url": domain_url, "preview": True},
    )

    assert route_refresh.status_code == 200
    assert route_refresh.json()["status"] == "previewed"
    assert route_refresh.json()["valid"] == 1
    assert route_refresh.json()["skipped"] == 1
    assert route_refresh.json()["saved"] is False
    assert domain_refresh.status_code == 200
    assert domain_refresh.json()["valid"] == 1


def test_editing_an_existing_profile_does_not_change_the_active_one(tmp_path: Path) -> None:
    # Regression test: adding routes/domains to a profile (making it a named
    # target) is unrelated to which profile is active/default -- saving the
    # edit form for it must not silently steer active_profile away from
    # whatever the admin already had selected.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "primary",
            "server": "vpn.example.com",
            "auth_type": "password",
            "username": "u",
        },
    )
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "finance",
            "server": "finance.example.com",
            "auth_type": "password",
            "username": "u",
        },
    )
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["active_profile"] == "primary"

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "finance",
            "server": "finance.example.com",
            "auth_type": "password",
            "username": "u",
            "routes": ["10.50.0.0/16"],
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["active_profile"] == "primary"
    assert saved["upstream"]["profiles"][1]["routes"] == ["10.50.0.0/16"]


def _two_profile_client(config_path: Path, tmp_path: Path) -> TestClient:
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  log_dir: {tmp_path}/logs
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
web:
  enabled: true
  admin_password: secret
upstream:
  active_profile: first
  profiles:
    - name: first
      server: first.example.com
      username: user
      password: secret
      routing_offset: 7
    - name: second
      server: second.example.com
      username: user
      password: secret
""",
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=config_path))


def test_editing_a_profile_keeps_its_position_in_the_list(tmp_path: Path) -> None:
    # Tunnel interface and fwmark/table offsets are derived from list
    # position, so an edit must not move the profile to the end.
    config_path = tmp_path / "config.yaml"
    client = _two_profile_client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={"name": "first", "server": "new.example.com", "username": "user"},
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    profiles = saved["upstream"]["profiles"]
    assert [item["name"] for item in profiles] == ["first", "second"]
    assert profiles[0]["server"] == "new.example.com"


def test_editing_a_profile_without_routing_offset_preserves_it(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _two_profile_client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={"name": "first", "server": "first.example.com", "username": "user"},
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][0]["routing_offset"] == 7


def test_profile_routing_offset_can_be_set_and_cleared(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _two_profile_client(config_path, tmp_path)

    set_response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "second",
            "server": "second.example.com",
            "username": "user",
            "routing_offset": 9,
        },
    )
    assert set_response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][1]["routing_offset"] == 9

    clear_response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "second",
            "server": "second.example.com",
            "username": "user",
            "routing_offset": None,
        },
    )
    assert clear_response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][1]["routing_offset"] is None


def test_profile_routing_offset_rejects_collisions(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _two_profile_client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "second",
            "server": "second.example.com",
            "username": "user",
            "routing_offset": 7,
        },
    )

    assert response.status_code >= 400
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["upstream"]["profiles"][1].get("routing_offset") is None


def test_fetch_pin_returns_the_presented_certificate_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kornode.api import routes_upstream
    from kornode.services.cert_pin import CertificatePin

    calls: list[tuple[str, int]] = []

    def fake_fetch(host: str, port: int) -> CertificatePin:
        calls.append((host, port))
        return CertificatePin(pin="pin-sha256:REMOTE", sha256="sha256:ab")

    monkeypatch.setattr(routes_upstream, "fetch_server_pin", fake_fetch)
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.post(
        "/api/upstream/fetch-pin",
        auth=("admin", "secret"),
        json={"server": " vpn.example.com ", "port": 8443},
    )

    assert response.status_code == 200
    assert response.json() == {"pin": "pin-sha256:REMOTE", "sha256": "sha256:ab"}
    assert calls == [("vpn.example.com", 8443)]


def test_fetch_pin_unreachable_server_is_a_client_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kornode.api import routes_upstream

    def refuse(host: str, port: int) -> None:
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(routes_upstream, "fetch_server_pin", refuse)
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.post(
        "/api/upstream/fetch-pin",
        auth=("admin", "secret"),
        json={"server": "vpn.example.com"},
    )

    assert response.status_code == 400
    assert "connection refused" in response.json()["detail"]


def test_upstream_profile_saves_server_routing_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "office",
            "server": "vpn.example.com",
            "username": "user",
            "password": "secret",
            "route_host_enabled": True,
            "accept_server_routes": True,
            "sync_url": "https://10.10.10.1:8443/",
            "sync_interval": 120,
            "sync_verify_tls": True,
            "enable": True,
        },
    )

    assert response.status_code == 200
    profile = yaml.safe_load(config_path.read_text(encoding="utf-8"))["upstream"]["profiles"][0]
    assert profile["accept_server_routes"] is True
    assert profile["sync_url"] == "https://10.10.10.1:8443"
    assert profile["sync_interval"] == 120
    assert profile["sync_verify_tls"] is True


def test_upstream_status_reports_server_routing_per_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "office",
            "server": "vpn.example.com",
            "username": "user",
            "password": "secret",
            "route_host_enabled": True,
            "accept_server_routes": True,
            "enable": True,
        },
    )

    status = client.get("/api/upstream/status", auth=("admin", "secret")).json()

    server_routing = status["connections"][0]["server_routing"]
    assert server_routing["active"] is True
    assert server_routing["routes"] == []


def test_upstream_profile_sync_requires_sync_url(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "office",
            "server": "vpn.example.com",
            "username": "user",
            "password": "secret",
            "enable": True,
        },
    )

    response = client.post("/api/upstream/profiles/office/sync", auth=("admin", "secret"))
    missing = client.post("/api/upstream/profiles/nope/sync", auth=("admin", "secret"))

    assert response.status_code == 400
    assert missing.status_code == 404


def test_save_external_interface_profile_requires_interface_field(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={"name": "wg", "kind": "external_interface"},
    )

    # UpstreamProfileConfig.model_validate raises a pydantic ValidationError
    # (a ValueError subclass), caught by the app's generic ValueError
    # handler and surfaced as 400.
    assert response.status_code == 400


def test_save_external_interface_profile_omits_server_and_auth_requirements(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={"name": "wg", "kind": "external_interface", "interface": "wg0"},
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    profile = saved["upstream"]["profiles"][0]
    assert profile["kind"] == "external_interface"
    assert profile["interface"] == "wg0"
    assert profile.get("server") is None


def test_upstream_profile_connect_endpoint_external_interface_is_a_noop_success(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={"name": "wg", "kind": "external_interface", "interface": "wg0"},
    )

    response = client.post(
        "/api/upstream/profiles/wg/connect",
        auth=("admin", "secret"),
        json={"dry_run": True},
    )

    assert response.status_code == 200
    assert response.json()["dry_run"] is True


def test_upstream_profile_sync_rejects_external_interface_profile(tmp_path: Path) -> None:
    # sync_url is validator-forbidden for external_interface, so it's
    # always empty for this kind -- the existing generic "no sync_url" 400
    # already covers it with zero extra branching.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={"name": "wg", "kind": "external_interface", "interface": "wg0"},
    )

    response = client.post("/api/upstream/profiles/wg/sync", auth=("admin", "secret"))

    assert response.status_code == 400


def test_upstream_profile_response_includes_kind_field(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "finance",
            "server": "vpn.example.com",
            "auth_type": "password",
            "username": "user",
        },
    )

    profiles = client.get("/api/upstream", auth=("admin", "secret")).json()

    assert profiles[0]["kind"] == "openconnect"


def test_saving_a_profile_leaves_global_upstream_enabled_alone(tmp_path: Path) -> None:
    # Regression: saving a second profile with the global toggle off switched
    # upstream.enabled off for every profile, the tunnels came down, and the
    # panel (reachable only over the tunnel) became unreachable. Profile saves
    # must not touch the global toggle -- that is POST /api/upstream/settings.
    config_path = tmp_path / "config.yaml"
    _client(config_path, tmp_path)  # writes the base config
    upstream = {
        "upstream": {
            "enabled": True,
            "active_profile": "office",
            "profiles": [
                {
                    "name": "office",
                    "server": "vpn.example.com",
                    "auth_type": "password",
                    "username": "user",
                    "password": "secret",
                }
            ],
        }
    }
    config_path.write_text(
        config_path.read_text(encoding="utf-8") + yaml.safe_dump(upstream), encoding="utf-8"
    )
    client = TestClient(create_app(config_path=config_path))

    response = client.post(
        "/api/upstream/profiles",
        auth=("admin", "secret"),
        json={
            "name": "art-ext",
            "server": "203.0.113.5",
            "auth_type": "password",
            "username": "user",
            "password": "secret",
            "enable": False,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))["upstream"]
    assert saved["enabled"] is True
    assert [item["name"] for item in saved["profiles"]] == ["office", "art-ext"]
