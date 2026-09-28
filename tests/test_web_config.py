from __future__ import annotations

import pytest
from pydantic import ValidationError

from kornode.config.models import AppConfig


def test_web_public_bind_requires_tls_or_explicit_insecure_opt_in() -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate(
            {
                "web": {
                    "enabled": True,
                    "listen": "0.0.0.0",
                    "tls": False,
                }
            }
        )


def test_web_public_bind_allows_explicit_insecure_local_testing_opt_in() -> None:
    config = AppConfig.model_validate(
        {
            "web": {
                "enabled": True,
                "listen": "0.0.0.0",
                "tls": False,
                "allow_insecure_http": True,
                "admin_password": "secret",
            }
        }
    )

    assert config.web.allow_insecure_http is True


def test_web_enabled_requires_admin_password() -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"web": {"enabled": True}})


def test_web_uses_https_by_default() -> None:
    config = AppConfig.model_validate({})

    assert config.web.tls is True
    assert config.web_tls_cert_path() == config.cert_path("server.crt")
    assert config.web_tls_key_path() == config.cert_path("server.key")


def test_web_tls_paths_must_be_configured_together() -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"web": {"tls_cert": "/run/certs/panel.crt"}})


def test_web_trusted_proxies_accept_ip_and_cidr() -> None:
    config = AppConfig.model_validate(
        {"web": {"trusted_proxies": ["127.0.0.1", "172.18.0.0/16"]}}
    )

    assert config.web.trusted_proxies == ["127.0.0.1", "172.18.0.0/16"]


def test_web_trusted_proxies_reject_hostnames() -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"web": {"trusted_proxies": ["proxy.internal"]}})
