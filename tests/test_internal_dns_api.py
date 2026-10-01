from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.services import internal_dns
from kornode.services.command import CommandResult


@pytest.fixture(autouse=True)
def _no_real_loopback_changes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    # Enabling the DNS tunnel runs `ip addr replace <listen>/32 dev lo`; under
    # root on a dev box that would really add the address to the host's lo.
    calls: list[str] = []

    def fake_ensure_listen_address(
        self: internal_dns.InternalDnsService, *, dry_run: bool = False
    ) -> CommandResult:
        calls.append(self.config.internal_dns.listen)
        return CommandResult(("ip", "addr", "replace"), 0, "", "", dry_run=dry_run)

    monkeypatch.setattr(
        internal_dns.InternalDnsService, "ensure_listen_address", fake_ensure_listen_address
    )
    return calls


def _client(config_path: Path, tmp_path: Path, extra: str = "") -> TestClient:
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
{extra}""",
        encoding="utf-8",
    )
    return TestClient(create_app(config_path=config_path))


def test_internal_dns_status_defaults(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.get("/api/internal-dns/status", auth=("admin", "secret"))

    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] == {
        "resolver_enabled": False,
        "blocklist_enabled": False,
        "local_records_enabled": False,
    }
    assert payload["effective"]["dnsmasq_active"] is False
    assert payload["effective_reasons"] == []
    assert payload["client_dns"] == ["1.1.1.1", "8.8.8.8"]
    assert payload["total"] == 0


def test_internal_dns_settings_enable_switches_client_dns(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/internal-dns/settings",
        auth=("admin", "secret"),
        json={
            "server_dns": ["9.9.9.9"],
            "resolver_enabled": True,
            "listen": "10.10.10.2",
            "port": 5353,
            "blocklist_enabled": True,
            "local_records_enabled": False,
            "blocklist_domains": ["Ads.Example.COM"],
            "blocklist_urls": ["https://lists.example.com/hosts.txt"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved_and_applied"
    assert payload["reconnect_required"] is True
    assert payload["internal_dns"]["resolver_enabled"] is True
    assert payload["internal_dns"]["blocklist_enabled"] is True
    assert payload["internal_dns"]["effective_reasons"] == [
        "resolver_enabled",
        "blocklist_enabled",
    ]
    assert payload["internal_dns"]["client_dns"] == ["10.10.10.2"]
    assert payload["internal_dns"]["blocklist_domains"] == ["ads.example.com"]

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["server"]["dns"] == ["9.9.9.9"]
    assert saved["routing"]["split"] == {"tunnel_dns": False}
    assert saved["internal_dns"]["resolver_enabled"] is True
    assert saved["internal_dns"]["listen"] == "10.10.10.2"
    assert saved["internal_dns"]["port"] == 5353
    assert saved["internal_dns"]["blocklist_enabled"] is True
    assert saved["internal_dns"]["blocklist_urls"] == ["https://lists.example.com/hosts.txt"]

    generated_dnsmasq = tmp_path / "generated" / "dnsmasq.conf"
    assert generated_dnsmasq.exists()
    assert "dnsmasq-blocklist.conf" in generated_dnsmasq.read_text(encoding="utf-8")
    blocklist_conf = tmp_path / "generated" / "dnsmasq-blocklist.conf"
    assert "address=/ads.example.com/0.0.0.0" in blocklist_conf.read_text(encoding="utf-8")

    ocserv_conf = (tmp_path / "generated" / "ocserv.conf").read_text(encoding="utf-8")
    assert "dns = 10.10.10.2" in ocserv_conf


def test_internal_dns_settings_saves_cache_size_log_queries_and_local_records(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/internal-dns/settings",
        auth=("admin", "secret"),
        json={
            "resolver_enabled": False,
            "blocklist_enabled": False,
            "local_records_enabled": True,
            "cache_size": 1000,
            "log_queries": True,
            "local_records": ["nas.corp.local 10.11.11.5"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["internal_dns"]["cache_size"] == 1000
    assert payload["internal_dns"]["log_queries"] is True
    assert payload["internal_dns"]["local_records"] == ["nas.corp.local 10.11.11.5"]

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["internal_dns"]["cache_size"] == 1000
    assert saved["internal_dns"]["log_queries"] is True
    assert saved["internal_dns"]["local_records"] == ["nas.corp.local 10.11.11.5"]


def test_local_record_change_does_not_reconnect_clients(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(
        config_path,
        tmp_path,
        extra="""
internal_dns:
  resolver_enabled: true
""",
    )

    response = client.post(
        "/api/internal-dns/settings",
        auth=("admin", "secret"),
        json={
            "resolver_enabled": True,
            "local_records_enabled": True,
            "local_records": ["nas.corp.local 10.11.11.5"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["reconnect_required"] is False
    assert payload["internal_dns"]["local_records"] == ["nas.corp.local 10.11.11.5"]


def test_default_upstreams_saved_and_does_not_reconnect_clients(tmp_path: Path) -> None:
    # default_upstreams only changes what the built-in resolver forwards to,
    # not what's pushed to connected VPN clients -- same category as
    # local_records above, so it must not force a reconnect either.
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/internal-dns/settings",
        auth=("admin", "secret"),
        json={"default_upstreams": ["9.9.9.9", "149.112.112.112"]},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["reconnect_required"] is False
    assert payload["internal_dns"]["default_upstreams"] == ["9.9.9.9", "149.112.112.112"]

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["internal_dns"]["default_upstreams"] == ["9.9.9.9", "149.112.112.112"]


def test_forward_domains_change_reconnects_clients_and_feeds_split_dns(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/internal-dns/settings",
        auth=("admin", "secret"),
        json={
            "forward_upstreams": ["127.207.207.1"],
            "forward_domains": ["r4ven.lan"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["reconnect_required"] is True
    assert payload["internal_dns"]["effective_reasons"] == ["forward_domains"]

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["internal_dns"]["forward_upstreams"] == ["127.207.207.1"]
    assert saved["internal_dns"]["forward_domains"] == ["r4ven.lan"]

    ocserv_conf = (tmp_path / "generated" / "ocserv.conf").read_text(encoding="utf-8")
    assert "split-dns = r4ven.lan" in ocserv_conf


def test_internal_dns_settings_rejects_bad_url(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.post(
        "/api/internal-dns/settings",
        auth=("admin", "secret"),
        json={"blocklist_enabled": False, "blocklist_urls": ["ftp://lists.example.com/x"]},
    )

    assert response.status_code == 400
    assert "HTTP(S)" in response.json()["detail"]


def test_internal_dns_settings_rejects_invalid_domains(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.post(
        "/api/internal-dns/settings",
        auth=("admin", "secret"),
        json={"blocklist_enabled": False, "blocklist_domains": ["not a domain"]},
    )

    assert response.status_code == 400


def test_internal_dns_refresh_preview_and_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config.yaml"
    url = "https://lists.example.com/hosts.txt"
    client = _client(
        config_path,
        tmp_path,
        extra=f"""
internal_dns:
  blocklist_enabled: true
  blocklist_urls:
    - {url}
""",
    )
    monkeypatch.setattr(
        internal_dns,
        "_fetch_blocklist_text",
        lambda url: "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\nbad line here\n",
    )

    preview = client.post(
        "/api/internal-dns/blocklist/refresh",
        auth=("admin", "secret"),
        json={"url": url, "preview": True},
    )
    assert preview.status_code == 200
    body = preview.json()
    assert body["status"] == "previewed"
    assert body["valid"] == 2
    assert body["skipped"] == 1
    assert body["saved"] is False
    assert body["sample"] == ["ads.example.com", "tracker.example.net"]

    applied = client.post(
        "/api/internal-dns/blocklist/refresh",
        auth=("admin", "secret"),
        json={"url": url},
    )
    assert applied.status_code == 200
    assert applied.json()["saved"] is True
    blocklist_conf = tmp_path / "generated" / "dnsmasq-blocklist.conf"
    content = blocklist_conf.read_text(encoding="utf-8")
    assert "address=/ads.example.com/0.0.0.0" in content
    assert "address=/tracker.example.net/0.0.0.0" in content

    listing = client.get("/api/internal-dns/blocklist?limit=1", auth=("admin", "secret"))
    assert listing.status_code == 200
    assert listing.json()["total"] == 2
    assert len(listing.json()["domains"]) == 1


def test_internal_dns_refresh_without_url_fails(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.post(
        "/api/internal-dns/blocklist/refresh",
        auth=("admin", "secret"),
        json={},
    )

    assert response.status_code == 422


def test_internal_dns_refresh_rejects_url_not_saved(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.post(
        "/api/internal-dns/blocklist/refresh",
        auth=("admin", "secret"),
        json={"url": "https://unsaved.example.com/hosts.txt"},
    )

    assert response.status_code == 400
    assert "not one of the saved" in response.json()["detail"]


def test_internal_dns_status_lists_multiple_files_and_urls(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    blocklist_file = tmp_path / "extra.txt"
    blocklist_file.write_text("extra.example.com\n", encoding="utf-8")
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/internal-dns/settings",
        auth=("admin", "secret"),
        json={
            "blocklist_enabled": True,
            "blocklist_files": [str(blocklist_file)],
            "blocklist_urls": [
                "https://lists.example.com/a.txt",
                "https://lists.example.com/b.txt",
            ],
        },
    )
    assert response.status_code == 200

    status = client.get("/api/internal-dns/status", auth=("admin", "secret"))
    assert status.status_code == 200
    payload = status.json()
    assert len(payload["blocklist_files"]) == 1
    assert payload["blocklist_files"][0]["path"] == str(blocklist_file)
    assert payload["blocklist_files"][0]["exists"] is True
    assert payload["blocklist_files"][0]["count"] == 1
    assert [entry["url"] for entry in payload["blocklist_urls"]] == [
        "https://lists.example.com/a.txt",
        "https://lists.example.com/b.txt",
    ]
    assert all(entry["count"] == 0 for entry in payload["blocklist_urls"])
    assert all(entry["meta"] is None for entry in payload["blocklist_urls"])


def test_internal_dns_requires_auth(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)
    assert client.get("/api/internal-dns/status").status_code == 401
