from __future__ import annotations

import pytest

from kornode.config.models import AppConfig


def test_split_mode_requires_listen_ip_inside_vpn_subnet() -> None:
    with pytest.raises(ValueError, match="internal_dns.listen must be inside"):
        AppConfig.model_validate(
            {
                "routing": {"client_policy": "split"},
                "internal_dns": {"listen": "192.0.2.1"},
            }
        )


def test_full_mode_also_requires_listen_ip_inside_vpn_subnet() -> None:
    # The built-in resolver is mandatory, not opt-in, whenever the VPN
    # server is enabled (AppConfig.client_dns_servers()) -- full mode is no
    # exception, since it still pushes internal_dns.listen to clients.
    with pytest.raises(ValueError, match="internal_dns.listen must be inside"):
        AppConfig.model_validate(
            {"routing": {"client_policy": "full"}, "internal_dns": {"listen": "192.0.2.1"}}
        )


def test_client_only_deployment_does_not_require_listen_ip_inside_vpn_subnet() -> None:
    # Regression test: server.enabled: false (client-only/middle-client mode,
    # see examples/config.client.yaml) means there are no VPN clients and no
    # real VPN subnet at all -- server.ipv4_network is just an inert default,
    # so internal_dns.listen has nothing to be "inside" of.
    config = AppConfig.model_validate(
        {
            "server": {"enabled": False},
            "internal_dns": {"listen": "192.0.2.1"},
        }
    )

    assert config.internal_dns.listen == "192.0.2.1"


def test_client_only_deployment_does_not_require_check_host_outside_vpn_subnet() -> None:
    # Same reasoning as above, for upstream.check_host: with no VPN server
    # there's no VPN client subnet a check_host could conflict with.
    config = AppConfig.model_validate(
        {
            "server": {"enabled": False},
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "office",
                        "server": "vpn.example.com",
                        "username": "user",
                        "check_host": "10.10.10.5",
                    }
                ],
            },
        }
    )

    assert config.upstream.profiles[0].check_host == "10.10.10.5"


def test_server_mode_still_requires_check_host_outside_vpn_subnet() -> None:
    # Regression guard: the server.enabled-gated relaxation above must not
    # loosen the check for an actual (server.enabled default True) VPN
    # server, where check_host genuinely could collide with its own client
    # pool.
    with pytest.raises(ValueError, match="must not be inside the VPN client subnet"):
        AppConfig.model_validate(
            {
                "upstream": {
                    "enabled": True,
                    "profiles": [
                        {
                            "name": "office",
                            "server": "vpn.example.com",
                            "username": "user",
                            "check_host": "10.10.10.5",
                        }
                    ],
                },
            }
        )
