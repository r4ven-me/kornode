from __future__ import annotations

from pathlib import Path

import pytest

from kornode.config.loader import load_config


def test_internal_dns_listen_follows_a_customized_ipv4_network(tmp_path: Path) -> None:
    # internal_dns.listen must stay inside server.ipv4_network -- see
    # AppConfig.migrate_legacy_dns_keys. The hardcoded model default
    # (10.10.10.1) only matches the default subnet, so a deployment that
    # only customizes ipv4_network must still get a reachable listen address
    # automatically, not a validation error for an unrelated-looking field.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={"server": {"ipv4_network": "10.77.0.0/24"}},
        environ={},
    )

    assert config.internal_dns.listen == "10.77.0.1"


def test_explicit_internal_dns_listen_overrides_the_computed_default(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "server": {"ipv4_network": "10.77.0.0/24"},
            "internal_dns": {"listen": "10.77.0.5"},
        },
        environ={},
    )

    assert config.internal_dns.listen == "10.77.0.5"


def test_malformed_ipv4_network_still_raises_its_own_error(tmp_path: Path) -> None:
    # The listen-address computation swallows a bad CIDR string rather than
    # raising from inside the "before" validator -- server.ipv4_network's
    # own field_validator must still be the one to report it.
    with pytest.raises(ValueError, match="ipv4_network"):
        load_config(
            tmp_path / "missing.yaml",
            cli_overrides={"server": {"ipv4_network": "not-a-cidr"}},
            environ={},
        )


def test_load_config_defaults_when_file_is_missing(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.yaml", environ={})

    assert config.server.port == 443
    assert config.web.enabled is False
    assert config.routing.client_policy == "full"
    assert config.system.log_rotation.enabled is False
    assert config.certificates.letsencrypt.auto_renew_interval == 7
    assert config.certificates.letsencrypt.auto_renew_interval_unit == "days"


def test_load_config_defaults_for_new_server_tuning_fields(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.yaml", environ={})

    assert config.server.dpd == 90
    assert config.server.mobile_dpd == 1800
    assert config.server.isolate_workers is True
    assert config.server.try_mtu_discovery is True
    assert config.server.predictable_ips is True
    assert config.server.deny_roaming is False
    assert config.server.ping_leases is False
    assert config.server.dtls_legacy is True
    assert config.server.client_bypass_protocol is False
    assert config.server.rate_limit_ms == 200
    assert config.server.server_stats_reset_time == 604800
    assert config.server.switch_to_tcp_timeout == 25
    assert config.server.auth_timeout == 240
    assert config.server.cookie_timeout == 600
    assert config.server.ban_time == 300
    assert config.server.max_ban_score == 80
    assert config.server.ban_reset_time == 1200
    assert config.server.rekey_time == 172800
    assert config.server.rekey_method == "ssl"
    assert config.server.cert_user_oid == "2.5.4.3"
    assert config.server.tls_priorities is None


def test_auto_renew_interval_units_convert_to_seconds(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
certificates:
  letsencrypt:
    auto_renew_interval: 2
    auto_renew_interval_unit: months
""",
        encoding="utf-8",
    )

    le = load_config(config_path, environ={}).certificates.letsencrypt

    assert le.auto_renew_interval_seconds == 2 * 30 * 86400


def test_secret_refs_resolve_from_dotenv(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    env_path = tmp_path / ".env"
    config_path.write_text(
        """
web:
  admin_password: "${SECRET:ADMIN_PASSWORD}"
""",
        encoding="utf-8",
    )
    env_path.write_text("ADMIN_PASSWORD=from-dotenv\n", encoding="utf-8")

    config = load_config(config_path, env_file=env_path, environ={})

    assert config.web.admin_password == "from-dotenv"


def test_single_segment_kornode_secret_name_is_not_treated_as_override(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    env_path = tmp_path / ".env"
    config_path.write_text(
        """
web:
  admin_password: "${SECRET:KORNODE_ADMIN_PASSWORD}"
""",
        encoding="utf-8",
    )
    env_path.write_text("KORNODE_ADMIN_PASSWORD=from-dotenv\n", encoding="utf-8")

    config = load_config(config_path, env_file=env_path, environ={})

    assert config.web.admin_password == "from-dotenv"
