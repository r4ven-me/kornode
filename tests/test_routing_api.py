from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.services.command import CommandResult


def _ok_result() -> CommandResult:
    return CommandResult(("true",), 0, "", "", dry_run=False)


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
routing:
  split:
    routes_file: {tmp_path}/routes.txt
    domains_file: {tmp_path}/domains.txt
  host_split:
    routes_file: {tmp_path}/host-routes.txt
    domains_file: {tmp_path}/host-domains.txt
""",
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=config_path))


def test_routing_settings_saves_new_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={
            "client_policy": "full",
            "main_interface": "eth0",
            "fwmark": "0x1234",
            "table_id": 1500,
            "nft_prefix": "korvus",
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["routing"]["main_interface"] == "eth0"
    assert saved["routing"]["fwmark"] == "0x1234"
    assert saved["routing"]["table_id"] == 1500
    assert saved["routing"]["nft_prefix"] == "korvus"


def test_routing_settings_saves_host_traffic_flag(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={
            "client_policy": "split",
            "tunnel_dns": True,
            "host_policy": "full",
        },
    )

    assert response.status_code == 200
    assert response.json()["routing"]["host_policy"] == "full"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["routing"]["host_policy"] == "full"


def test_routing_settings_saves_client_policy_off(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={"client_policy": "off"},
    )

    assert response.status_code == 200
    assert response.json()["routing"]["client_policy"] == "off"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["routing"]["client_policy"] == "off"


def test_routing_settings_rejects_unknown_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={"client_policy": "maybe"},
    )

    assert response.status_code == 422


def test_routing_routes_bulk_set_replaces_the_whole_list(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    client.post("/api/routing/routes", auth=("admin", "secret"), json={"value": "10.1.0.0/16"})

    response = client.put(
        "/api/routing/routes",
        auth=("admin", "secret"),
        json={"items": ["10.20.0.0/16", "203.0.113.5"]},
    )

    assert response.status_code == 200
    assert response.json() == ["10.20.0.0/16", "203.0.113.5"]
    assert client.get("/api/routing/routes", auth=("admin", "secret")).json() == [
        "10.20.0.0/16",
        "203.0.113.5",
    ]


def test_routing_routes_bulk_set_rejects_invalid_entries_without_saving_anything(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.post("/api/routing/routes", auth=("admin", "secret"), json={"value": "10.1.0.0/16"})

    response = client.put(
        "/api/routing/routes",
        auth=("admin", "secret"),
        json={"items": ["10.20.0.0/16", "not-a-route"]},
    )

    assert response.status_code == 400
    assert client.get("/api/routing/routes", auth=("admin", "secret")).json() == ["10.1.0.0/16"]


def test_routing_domains_bulk_set_replaces_the_whole_list(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.put(
        "/api/routing/domains",
        auth=("admin", "secret"),
        json={"items": ["corp.example.com", "internal.example"]},
    )

    assert response.status_code == 200
    assert response.json() == ["corp.example.com", "internal.example"]


def test_routing_settings_saves_static_file_and_url_lists(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    static_routes = str(tmp_path / "static-routes.txt")
    static_domains = str(tmp_path / "static-domains.txt")

    response = client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={
            "client_policy": "full",
            "routes_files": [static_routes],
            "routes_urls": ["https://lists.example.com/routes.txt"],
            "domains_files": [static_domains],
            "domains_urls": ["https://lists.example.com/domains.txt"],
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["routing"]["split"]["routes_files"] == [static_routes]
    assert saved["routing"]["split"]["routes_urls"] == ["https://lists.example.com/routes.txt"]
    assert saved["routing"]["split"]["domains_files"] == [static_domains]
    assert saved["routing"]["split"]["domains_urls"] == ["https://lists.example.com/domains.txt"]


def test_routing_routes_status_reports_files_and_urls(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    static_routes = tmp_path / "static-routes.txt"
    static_routes.write_text("10.40.0.0/16\n", encoding="utf-8")
    client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={"client_policy": "full", "routes_files": [str(static_routes)]},
    )

    response = client.get("/api/routing/routes/status", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json()["files"] == [
        {"path": str(static_routes), "exists": True, "count": 1}
    ]
    assert response.json()["urls"] == []


def test_routing_routes_refresh_rejects_unsaved_url(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/routing/routes/refresh",
        auth=("admin", "secret"),
        json={"url": "https://unsaved.example.com/x"},
    )

    assert response.status_code == 400


def test_routing_routes_refresh_fetches_and_caches(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    url = "https://lists.example.com/routes.txt"
    client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={"client_policy": "full", "routes_urls": [url]},
    )

    with patch(
        "kornode.services.external_lists.fetch_url_text",
        return_value="10.60.0.0/16\ngarbage\n",
    ):
        response = client.post(
            "/api/routing/routes/refresh",
            auth=("admin", "secret"),
            json={"url": url},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "refreshed"
    assert payload["valid"] == 1
    assert payload["skipped"] == 1
    assert payload["saved"] is True
    assert client.get("/api/routing/routes", auth=("admin", "secret")).json() == [
        "10.60.0.0/16"
    ]


def test_routing_domains_refresh_preview_does_not_persist(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    url = "https://lists.example.com/domains.txt"
    client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={"client_policy": "full", "domains_urls": [url]},
    )

    with patch(
        "kornode.services.external_lists.fetch_url_text",
        return_value="corp.example.com\n",
    ):
        response = client.post(
            "/api/routing/domains/refresh",
            auth=("admin", "secret"),
            json={"url": url, "preview": True},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "previewed"
    assert response.json()["saved"] is False
    assert client.get("/api/routing/domains", auth=("admin", "secret")).json() == []


def test_routing_host_routes_bulk_set_is_independent_of_client_routes(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    client.put(
        "/api/routing/routes", auth=("admin", "secret"), json={"items": ["10.1.0.0/16"]}
    )

    response = client.put(
        "/api/routing/host-routes",
        auth=("admin", "secret"),
        json={"items": ["10.2.0.0/16"]},
    )

    assert response.status_code == 200
    assert response.json() == ["10.2.0.0/16"]
    assert client.get("/api/routing/routes", auth=("admin", "secret")).json() == [
        "10.1.0.0/16"
    ]
    assert client.get("/api/routing/host-routes", auth=("admin", "secret")).json() == [
        "10.2.0.0/16"
    ]


def test_routing_host_domains_bulk_set_rejects_invalid_entries(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.put(
        "/api/routing/host-domains",
        auth=("admin", "secret"),
        json={"items": ["not a domain!"]},
    )

    assert response.status_code == 400
    assert client.get("/api/routing/host-domains", auth=("admin", "secret")).json() == []


def test_routing_settings_saves_host_static_file_and_url_lists(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    static_routes = str(tmp_path / "static-host-routes.txt")

    response = client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={
            "client_policy": "full",
            "host_routes_files": [static_routes],
            "host_routes_urls": ["https://lists.example.com/host-routes.txt"],
            "host_domains_files": [],
            "host_domains_urls": ["https://lists.example.com/host-domains.txt"],
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["routing"]["host_split"]["routes_files"] == [static_routes]
    assert saved["routing"]["host_split"]["routes_urls"] == [
        "https://lists.example.com/host-routes.txt"
    ]
    assert saved["routing"]["host_split"]["domains_urls"] == [
        "https://lists.example.com/host-domains.txt"
    ]


def test_routing_host_routes_status_reports_files_and_urls(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    static_routes = tmp_path / "static-host-routes.txt"
    static_routes.write_text("10.50.0.0/16\n", encoding="utf-8")
    client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={"client_policy": "full", "host_routes_files": [str(static_routes)]},
    )

    response = client.get("/api/routing/host-routes/status", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json()["files"] == [
        {"path": str(static_routes), "exists": True, "count": 1}
    ]
    assert response.json()["urls"] == []


def test_routing_host_routes_refresh_rejects_unsaved_url(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/routing/host-routes/refresh",
        auth=("admin", "secret"),
        json={"url": "https://unsaved.example.com/x"},
    )

    assert response.status_code == 400


def test_routing_host_domains_refresh_fetches_and_caches(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)
    url = "https://lists.example.com/host-domains.txt"
    client.post(
        "/api/routing/settings",
        auth=("admin", "secret"),
        json={"client_policy": "full", "host_domains_urls": [url]},
    )

    with patch(
        "kornode.services.external_lists.fetch_url_text",
        return_value="corp-internal.example\n",
    ):
        response = client.post(
            "/api/routing/host-domains/refresh",
            auth=("admin", "secret"),
            json={"url": url},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "refreshed"
    assert payload["saved"] is True
    assert client.get("/api/routing/host-domains", auth=("admin", "secret")).json() == [
        "corp-internal.example"
    ]


def test_routing_settings_tunnel_dns_starts_dnsmasq_and_reapplies_nft(tmp_path: Path) -> None:
    # Regression: toggling split tunnel_dns on the Upstream page used to change
    # dns_tunnel_active() without starting dnsmasq or reapplying nftables.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    with (
        patch("kornode.services.apply.ServerService.process_action") as process_action,
        patch("kornode.services.apply.ServerService.reload") as reload,
        patch("kornode.api.routes_routing.NftablesService.apply", return_value=[]) as nft_apply,
        patch("kornode.services.apply.InternalDnsService.ensure_listen_address"),
        patch("kornode.services.apply.SessionService.list_sessions", return_value=[]),
        patch("kornode.api.routes_routing.HostDnsService.apply") as host_apply,
    ):
        process_action.return_value = _ok_result()
        reload.return_value = _ok_result()
        host_apply.return_value.as_dict.return_value = {}
        response = client.post(
            "/api/routing/settings",
            auth=("admin", "secret"),
            json={
                "client_policy": "split",
                "host_policy": "off",
                "tunnel_dns": True,
                "host_dns": "off",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "saved_and_applied"
    assert body["reconnect_required"] is True
    process_action.assert_called_once_with("restart", "dnsmasq")
    reload.assert_called_once()
    nft_apply.assert_called_once()
