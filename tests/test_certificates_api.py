from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app


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


def test_certificate_settings_renames_ca(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/certificates/settings",
        auth=("admin", "secret"),
        json={"mode": "auto", "ca_name": "Acme VPN CA"},
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["certificates"]["ca_name"] == "Acme VPN CA"
    assert saved["certificates"]["mode"] == "auto"


def test_certificate_settings_reverting_to_external_without_paths_fails(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/certificates/settings",
        auth=("admin", "secret"),
        json={"mode": "external", "ca_name": "Acme VPN CA"},
    )

    assert response.status_code == 400


def test_letsencrypt_settings_saves_interval_with_unit(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/certificates/letsencrypt/settings",
        auth=("admin", "secret"),
        json={
            "enabled": False,
            "email": "admin@example.com",
            "domains": ["vpn.example.com"],
            "renew_reload": True,
            "auto_renew_enabled": True,
            "auto_renew_interval": 2,
            "auto_renew_interval_unit": "weeks",
            "http01_address": None,
            "http01_port": 80,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["certificates"]["letsencrypt"]["auto_renew_interval"] == 2
    assert saved["certificates"]["letsencrypt"]["auto_renew_interval_unit"] == "weeks"


def test_letsencrypt_settings_saves_custom_http01_address_and_port(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/certificates/letsencrypt/settings",
        auth=("admin", "secret"),
        json={
            "enabled": False,
            "email": "admin@example.com",
            "domains": ["vpn.example.com"],
            "renew_reload": True,
            "auto_renew_enabled": True,
            "auto_renew_interval": 7,
            "auto_renew_interval_unit": "days",
            "http01_address": "203.0.113.5",
            "http01_port": 8080,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["certificates"]["letsencrypt"]["http01_address"] == "203.0.113.5"
    assert saved["certificates"]["letsencrypt"]["http01_port"] == 8080


def test_letsencrypt_settings_blank_http01_address_stays_null(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    client = _client(config_path, tmp_path)

    response = client.post(
        "/api/certificates/letsencrypt/settings",
        auth=("admin", "secret"),
        json={
            "enabled": False,
            "email": "admin@example.com",
            "domains": ["vpn.example.com"],
            "renew_reload": True,
            "auto_renew_enabled": True,
            "auto_renew_interval": 7,
            "auto_renew_interval_unit": "days",
            "http01_address": None,
            "http01_port": 80,
        },
    )

    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["certificates"]["letsencrypt"]["http01_address"] is None
    # The effective (resolved) config in the response fills the blank address in
    # from server.listen, per AppConfig's root validator.
    effective = response.json()["config"]
    assert (
        effective["certificates"]["letsencrypt"]["http01_address"] == effective["server"]["listen"]
    )


def test_list_revoked_certificates_empty_by_default(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.get("/api/certificates/ca/revoked", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json() == {"certificates": []}


@pytest.mark.skipif(
    shutil.which("certtool") is None,
    reason="needs GnuTLS certtool (gnutls-bin) to build a real CA and CRL",
)
def test_list_revoked_certificates_after_revoke(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)
    regenerate = client.post(
        "/api/certificates/ca/regenerate", auth=("admin", "secret"), json={}
    )
    assert regenerate.status_code == 200
    # create_user_certificate only validates the username's shape, not that a
    # user record already exists, so this doesn't need a real ocpasswd (which
    # this test environment doesn't have installed) via /api/users first.
    create_cert = client.post("/api/users/alice/cert", auth=("admin", "secret"))
    assert create_cert.status_code == 200

    revoke = client.delete("/api/users/alice/cert", auth=("admin", "secret"))
    assert revoke.status_code == 200

    response = client.get("/api/certificates/ca/revoked", auth=("admin", "secret"))

    assert response.status_code == 200
    certificates = response.json()["certificates"]
    assert len(certificates) == 1
    assert certificates[0]["subject"] == "CN=alice"
    assert certificates[0]["serial"]


def test_server_pin_reports_the_active_certificate_pin(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures"
    client = _client(
        tmp_path / "config.yaml",
        tmp_path,
        extra=f"""
certificates:
  mode: external
  server_cert: {fixtures / "test-server.pem"}
  server_key: {fixtures / "test-server.key"}
  ca_cert: {fixtures / "test-server.pem"}
""",
    )

    response = client.get("/api/certificates/server-pin", auth=("admin", "secret"))

    assert response.status_code == 200
    assert response.json()["pin"] == "pin-sha256:bkNrvtXA+3ZD7n3iUJDkGuRZhhmQmhE6xv92QL3QRDc="
    assert response.json()["sha256"].startswith("sha256:")


def test_server_pin_without_a_certificate_is_a_client_error(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    response = client.get("/api/certificates/server-pin", auth=("admin", "secret"))

    assert response.status_code == 400
    assert "server certificate not found" in response.json()["detail"]


def test_certificate_info_endpoints_report_missing_certificate(tmp_path: Path) -> None:
    client = _client(tmp_path / "config.yaml", tmp_path)

    paths = (
        "/api/certificates/ca/info",
        "/api/certificates/server/info",
        "/api/certificates/letsencrypt/info",
    )
    for path in paths:
        response = client.get(path, auth=("admin", "secret"))
        assert response.status_code == 200
        assert response.json()["certificate"] is None


@pytest.mark.skipif(
    shutil.which("certtool") is None,
    reason="needs GnuTLS certtool (gnutls-bin) to parse the fixture certificate",
)
def test_server_certificate_info_reports_parsed_fields(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures"
    client = _client(
        tmp_path / "config.yaml",
        tmp_path,
        extra=f"""
certificates:
  mode: external
  server_cert: {fixtures / "test-server.pem"}
  server_key: {fixtures / "test-server.key"}
  ca_cert: {fixtures / "test-server.pem"}
""",
    )

    response = client.get("/api/certificates/server/info", auth=("admin", "secret"))

    assert response.status_code == 200
    certificate = response.json()["certificate"]
    assert certificate is not None
    assert certificate["subject"]
    assert certificate["not_before"]
    assert certificate["not_after"]
