from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kornode.config.loader import load_config
from kornode.config.models import AddressOverlapError, AppConfig


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

    assert config.node.id == 1
    assert config.fabric.enabled is False
    assert config.fabric.enroll_pool == "10.99.255.240/28"
    assert config.server.port == 443
    assert config.web.enabled is False
    assert config.routing.client_policy == "full"
    assert config.system.log_rotation.enabled is False
    assert config.certificates.letsencrypt.auto_renew_interval == 7
    assert config.certificates.letsencrypt.auto_renew_interval_unit == "days"


def test_fabric_enabled_derives_server_network_and_dns_listen(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={"fabric": {"enabled": True}},
        environ={},
    )

    assert config.node.id == 1
    assert config.server.ipv4_network == "10.100.1.0/24"
    assert config.internal_dns.listen == "10.100.1.1"


def test_fabric_uses_node_id_for_derived_addresses(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={"node": {"id": 7}, "fabric": {"enabled": True}},
        environ={},
    )

    assert config.server.ipv4_network == "10.100.7.0/24"
    assert config.internal_dns.listen == "10.100.7.1"


def test_fabric_env_overrides_work(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        environ={
            "KORNODE_NODE__ID": "9",
            "KORNODE_FABRIC__ENABLED": "true",
            "KORNODE_FABRIC__CLIENT_POOL": '"10.110.{id}.0/24"',
        },
    )

    assert config.node.id == 9
    assert config.fabric.client_pool == "10.110.{id}.0/24"
    assert config.server.ipv4_network == "10.110.9.0/24"
    assert config.internal_dns.listen == "10.110.9.1"


def test_explicit_server_network_overrides_fabric_derived_default(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "fabric": {"enabled": True},
            "server": {"ipv4_network": "10.120.1.0/24"},
            "internal_dns": {"listen": "10.120.1.1"},
        },
        environ={},
    )

    assert config.server.ipv4_network == "10.120.1.0/24"
    assert config.internal_dns.listen == "10.120.1.1"


def test_explicit_server_network_rejects_fabric_overlap(tmp_path: Path) -> None:
    with pytest.raises(AddressOverlapError) as exc_info:
        load_config(
            tmp_path / "missing.yaml",
            cli_overrides={
                "fabric": {"enabled": True, "reserved": ["10.120.0.0/16"]},
                "server": {"ipv4_network": "10.120.1.0/24"},
                "internal_dns": {"listen": "10.120.1.1"},
            },
            environ={},
        )

    assert exc_info.value.conflicts[0].to_dict() == {
        "prefix": "10.120.1.0/24",
        "node": 1,
        "with": "10.120.0.0/16",
        "owner": "fabric.reserved",
    }


def test_explicit_server_network_rejects_enroll_pool_overlap(tmp_path: Path) -> None:
    with pytest.raises(AddressOverlapError) as exc_info:
        load_config(
            tmp_path / "missing.yaml",
            cli_overrides={
                "fabric": {"enabled": True, "enroll_pool": "10.120.1.0/24"},
                "server": {"ipv4_network": "10.120.1.0/24"},
                "internal_dns": {"listen": "10.120.1.1"},
            },
            environ={},
        )

    assert exc_info.value.conflicts[0].to_dict() == {
        "prefix": "10.120.1.0/24",
        "node": 1,
        "with": "10.120.1.0/24",
        "owner": "fabric.enroll_pool",
    }


@pytest.mark.parametrize(
    ("auth", "message"),
    [
        (
            {"password": {"enabled": False}, "oidc": {"enabled": True}},
            "fabric.enabled requires auth.password.enabled",
        ),
        (
            {"password": {"enabled": True}, "certificate": {"enabled": True}},
            "auth.certificate.enabled cannot be combined with fabric.enabled",
        ),
        (
            {"password": {"enabled": True}, "oidc": {"enabled": True}},
            "auth.oidc.enabled cannot be combined with fabric.enabled",
        ),
        (
            {
                "password": {"enabled": True},
                "otp": {"enabled": True, "ocserv_oath_auth": True},
            },
            "auth.otp.ocserv_oath_auth cannot be combined with fabric.enabled",
        ),
    ],
)
def test_fabric_auth_rejects_forbidden_combinations(
    auth: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        AppConfig.model_validate({"fabric": {"enabled": True}, "auth": auth})


def test_fabric_auth_accepts_password_only() -> None:
    config = AppConfig.model_validate(
        {
            "fabric": {"enabled": True},
            "auth": {"password": {"enabled": True}},
        }
    )

    assert config.fabric.enabled is True


def test_fabric_disabled_does_not_apply_d43_auth_restrictions() -> None:
    config = AppConfig.model_validate(
        {
            "fabric": {"enabled": False},
            "auth": {
                "password": {"enabled": False},
                "certificate": {"enabled": True},
                "oidc": {"enabled": True},
                "otp": {"enabled": True, "ocserv_oath_auth": True},
            },
        }
    )

    assert config.fabric.enabled is False


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


@pytest.mark.parametrize("value", ['eth0" accept', "a" * 16, "eth 0"])
def test_routing_main_interface_must_be_auto_or_an_ifname(tmp_path: Path, value: str) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({"routing": {"main_interface": value}}), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid network interface name"):
        load_config(config)


def test_routing_main_interface_accepts_auto_and_an_ifname(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("routing:\n  main_interface: ens3\n", encoding="utf-8")

    assert load_config(config).routing.main_interface == "ens3"
    assert load_config(tmp_path / "missing.yaml").routing.main_interface == "auto"


def test_control_defaults_and_signing_key_follows_data_dir(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={"system": {"data_dir": str(tmp_path / "data")}},
        environ={},
    )

    assert config.control.enabled is False
    assert config.control.port == 8444
    assert config.control.signing_key == tmp_path / "data" / "control" / "signing.ed25519"


def test_control_requires_fabric(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="control.enabled requires fabric.enabled"):
        load_config(
            tmp_path / "missing.yaml",
            cli_overrides={"control": {"enabled": True}},
            environ={},
        )


def test_control_enabled_with_fabric(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={"fabric": {"enabled": True}, "control": {"enabled": True, "port": 9444}},
        environ={},
    )

    assert config.control.enabled is True
    assert config.control.port == 9444
