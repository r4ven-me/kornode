from __future__ import annotations

import base64
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from kornode.api.app import create_app
from kornode.config.models import AppConfig
from kornode.services.secrets import (
    collect_config_secrets,
    is_secret_key,
    mask_text,
    redact_value,
    sanitized_validation_errors,
)


def test_mask_text_redacts_secret_assignments_without_hiding_paths() -> None:
    rendered = "\n".join(
        [
            "password=kornodectl-local",
            "camouflage_secret = tunnel-word",
            "cert-pass: bundle-pass",
            "secrets_dir=/var/lib/kornode/secrets",
        ]
    )

    masked = mask_text(rendered)

    assert "password=***" in masked
    assert "cert-pass: ***" in masked
    assert "secrets_dir=/var/lib/kornode/secrets" in masked
    assert "kornodectl-local" not in masked
    assert "bundle-pass" not in masked

    # camouflage_secret is a shared TLS camouflage password, not a per-user
    # credential; the UI displays it in plain text instead of masking it.
    assert "camouflage_secret = tunnel-word" in masked


def test_is_secret_key_treats_camouflage_secret_as_secret_structurally() -> None:
    # Regression test: is_secret_key()/redact_value() operate on structured
    # config dicts, where "camouflage_secret" is the actual field name of
    # UpstreamProfileConfig.camouflage_secret -- a genuinely sensitive
    # shared credential for reaching the upstream server. This is a
    # DIFFERENT field from server.camouflage.secret (structural key
    # "secret", intentionally shown in plaintext) that only *coincidentally*
    # shares its name with that field's rendered ocserv.conf directive
    # ("camouflage_secret = ..."). The two must not be conflated: the
    # ocserv.conf-directive exemption belongs only to mask_text()'s
    # rendered-text masking (see the test above), never to this structural
    # check -- otherwise AppConfig.model_dump_safe() (used by e.g. GET
    # /api/config) would leak it in plaintext.
    assert is_secret_key("camouflage_secret") is True
    assert redact_value("shhh", key="camouflage_secret") == "***"


def test_model_dump_safe_masks_upstream_profile_camouflage_secret() -> None:
    config = AppConfig.model_validate(
        {
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "primary",
                        "server": "vpn.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "password": "pw-secret",
                        "camouflage_secret": "camo-leak-me",
                    }
                ],
            },
        }
    )

    dumped = config.model_dump_safe()

    profile = dumped["upstream"]["profiles"][0]
    assert profile["camouflage_secret"] == "***"
    assert profile["password"] == "***"


@pytest.mark.parametrize("key", ["key_file_base64", "cert_file_base64"])
def test_inline_credentials_are_masked_and_collected(key: str) -> None:
    value = base64.b64encode(b"inline-sensitive-material").decode()
    assert is_secret_key(key)
    assert redact_value({key: value}) == {key: "***"}
    assert value in collect_config_secrets({"upstream": {"profiles": [{key: value}]}})
    assert value not in mask_text(f"{key}: {value}")
    assert redact_value({key: None}) == {key: None}


def test_inline_credentials_masked_on_all_safe_config_surfaces(tmp_path: Path) -> None:
    cert = base64.b64encode(b"inline-certificate-material").decode()
    key = base64.b64encode(b"inline-private-key-material").decode()
    config = AppConfig.model_validate(
        {
            "system": {
                field: str(tmp_path / field)
                for field in ("data_dir", "generated_dir", "log_dir", "secrets_dir")
            },
            "web": {"admin_password": "secret"},
            "upstream": {
                "profiles": [
                    {
                        "name": "primary",
                        "server": "vpn.example.com",
                        "auth_type": "cert",
                        "cert_file_base64": cert,
                        "key_file_base64": key,
                    }
                ]
            },
        }
    )
    safe = config.model_dump_safe()["upstream"]["profiles"][0]
    assert safe["cert_file_base64"] == safe["key_file_base64"] == "***"
    data = config.model_dump(mode="json")
    path = tmp_path / "config.yaml"
    source = yaml.safe_dump(data)
    path.write_text(source, encoding="utf-8")
    client = TestClient(create_app(config_path=path))
    source_response = client.get("/api/config/source", auth=("admin", "secret"))
    assert source_response.status_code == 200
    responses = [
        client.get("/api/config", auth=("admin", "secret")),
        client.get("/api/config/validate", auth=("admin", "secret")),
        source_response,
        client.post("/api/config/validate", auth=("admin", "secret"), json=data),
        client.post(
            "/api/config/source/validate", auth=("admin", "secret"), json={"content": source}
        ),
        client.post(
            "/api/config/source",
            auth=("admin", "secret"),
            json={
                "content": source,
                "write_rendered": False,
                "etag": source_response.json()["etag"],
            },
        ),
        client.patch(
            "/api/config",
            auth=("admin", "secret"),
            json={"patch": {"system": {"timezone": "UTC"}}, "write_rendered": False},
        ),
    ]
    for response in responses:
        assert response.status_code == 200, response.text
        assert cert not in response.text
        assert key not in response.text
    # Safe YAML round-tripping must retain masked inline credentials on disk.
    current_source = client.get("/api/config/source", auth=("admin", "secret")).json()
    masked_source = current_source["content"]
    saved = client.post(
        "/api/config/source",
        auth=("admin", "secret"),
        json={
            "content": masked_source,
            "write_rendered": False,
            "etag": current_source["etag"],
        },
    )
    assert saved.status_code == 200
    stored = yaml.safe_load(path.read_text())["upstream"]["profiles"][0]
    assert stored["cert_file_base64"] == cert
    assert stored["key_file_base64"] == key


@pytest.mark.parametrize(
    ("key", "value"), [("admin_totp_enabled", True), ("enroll_token_ttl_minutes", 60)]
)
def test_auth_policy_metadata_is_not_masked(key: str, value: bool | int) -> None:
    assert not is_secret_key(key)
    assert redact_value({key: value}) == {key: value}
    assert collect_config_secrets({key: value}) == []


def test_validation_sanitizer_preserves_safe_ip_error_category() -> None:
    errors = [
        {
            "type": "value_error",
            "loc": ("body", "dns"),
            "input": ["secret-value"],
            "msg": "Value error, 'secret-value' does not appear to be an IPv4 or IPv6 address",
            "ctx": {"error": ValueError("secret-value")},
        }
    ]
    assert sanitized_validation_errors(errors) == [
        {
            "type": "value_error",
            "loc": ["body", "dns"],
            "msg": "Input should be a valid IP address",
        }
    ]


@pytest.mark.parametrize(
    "message",
    [
        "internal_dns.blocklist_urls entries must be HTTP(S) URLs",
        "internal_dns.blocklist_urls entries must not contain whitespace",
        "internal_dns.forward_upstreams and internal_dns.forward_domains "
        "must either both be configured or both be empty",
        "identity.oidc.providers.issuer_url must be an HTTP(S) URL",
        "web.trusted_proxies entries must be IP addresses or CIDR networks",
    ],
)
def test_validation_sanitizer_preserves_exact_safe_messages(message: str) -> None:
    for prefix in ("", "Value error, "):
        errors = [
            {
                "type": "value_error",
                "loc": ("internal_dns", "blocklist_urls"),
                "msg": prefix + message,
                "input": ["input-secret"],
                "ctx": {"error": ValueError("context-secret")},
            }
        ]
        assert sanitized_validation_errors(errors) == [
            {
                "type": "value_error",
                "loc": ["internal_dns", "blocklist_urls"],
                "msg": message,
            }
        ]


@pytest.mark.parametrize(
    "message",
    [
        "Value error, internal_dns.blocklist_urls entries must be HTTP(S) URLs: leaked-secret",
        "Value error, leaked-secret: internal_dns.blocklist_urls entries must be HTTP(S) URLs",
    ],
)
def test_validation_sanitizer_does_not_allow_safe_message_substrings(message: str) -> None:
    errors = [{"type": "value_error", "loc": ("internal_dns", "blocklist_urls"), "msg": message}]
    assert sanitized_validation_errors(errors) == [
        {
            "type": "value_error",
            "loc": ["internal_dns", "blocklist_urls"],
            "msg": "Invalid value",
        }
    ]


def test_validation_sanitizer_discards_input_context_and_custom_message() -> None:
    errors = [
        {
            "loc": ("body", "password"),
            "type": "value_error",
            "input": {"password": "input-secret"},
            "msg": "Value error: msg-secret",
            "ctx": {"error": ValueError("context-secret")},
        }
    ]
    assert sanitized_validation_errors(errors) == [
        {"loc": ["body", "password"], "type": "value_error", "msg": "Invalid value"}
    ]
