from __future__ import annotations

import pytest

from kornode.config.models import AppConfig


def test_split_mode_tunnel_dns_requires_listen_ip_inside_vpn_subnet() -> None:
    # Regression test: this was previously only validated when
    # internal_dns was enabled, even though routing.mode == "split" with
    # split.tunnel_dns also pushes internal_dns.listen to VPN clients as their
    # DNS server (see AppConfig.client_dns_servers()) -- an address outside the
    # VPN subnet would be unreachable for them.
    with pytest.raises(ValueError, match="internal_dns.listen must be inside"):
        AppConfig.model_validate(
            {
                "routing": {"mode": "split", "split": {"tunnel_dns": True}},
                "internal_dns": {"listen": "192.0.2.1"},
            }
        )


def test_split_mode_without_tunnel_dns_does_not_require_listen_ip_inside_vpn_subnet() -> None:
    config = AppConfig.model_validate(
        {
            "routing": {"mode": "split", "split": {"tunnel_dns": False}},
            "internal_dns": {"listen": "192.0.2.1"},
        }
    )

    assert config.internal_dns.listen == "192.0.2.1"


def test_full_mode_does_not_require_listen_ip_inside_vpn_subnet() -> None:
    config = AppConfig.model_validate(
        {"routing": {"mode": "full"}, "internal_dns": {"listen": "192.0.2.1"}}
    )

    assert config.internal_dns.listen == "192.0.2.1"
