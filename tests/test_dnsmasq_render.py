from __future__ import annotations

from pathlib import Path

from kornode.config.loader import load_config
from kornode.renderers.dnsmasq import DnsmasqConfigRenderer


def test_dnsmasq_render_contains_domain_nftset(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "split": {
                    "tunnel_dns": True,
                    "domains": ["example.com"],
                },
            }
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "listen-address=10.10.10.1" in rendered
    assert "nftset=/example.com/4#inet#kornode_filter#split_v4" in rendered


def test_dnsmasq_render_ignores_split_domains_when_client_traffic_is_off(
    tmp_path: Path,
) -> None:
    # client_traffic off means the default target never marks client
    # traffic through Upstream at all -- resolving domains into its set (or
    # overriding their DNS server) would be a silent, pointless DNS change.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "client_traffic": False,
                "split": {
                    "tunnel_dns": True,
                    "domains": ["example.com"],
                },
            }
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "example.com" not in rendered


def test_dnsmasq_render_includes_domains_from_domains_file(tmp_path: Path) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("panel-added.example\n", encoding="utf-8")
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "split": {
                    "tunnel_dns": True,
                    "domains": ["example.com"],
                    "domains_file": str(domains_file),
                },
            }
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "server=/example.com/1.1.1.1" in rendered
    assert "server=/panel-added.example/1.1.1.1" in rendered
    assert "nftset=/panel-added.example/4#inet#kornode_filter#split_v4" in rendered


def test_dnsmasq_render_domain_upstream_overrides_split_dns_server(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "split": {"tunnel_dns": True, "domains": ["github.com"]},
            },
            "internal_dns": {
                "forward_upstreams": ["1.1.1.1", "8.8.8.8"],
                "forward_domains": ["GitHub.COM."],
            },
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "server=/github.com/1.1.1.1" in rendered
    assert "server=/github.com/8.8.8.8" in rendered
    assert rendered.count("server=/github.com/") == 2
    assert "nftset=/github.com/4#inet#kornode_filter#split_v4" in rendered


def test_dnsmasq_render_includes_cache_size_and_log_queries(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={"internal_dns": {"cache_size": 500, "log_queries": True}},
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "cache-size=500" in rendered
    assert "log-queries" in rendered


def test_dnsmasq_render_omits_log_queries_by_default(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.yaml", environ={})

    rendered = DnsmasqConfigRenderer().render(config)

    assert "cache-size=150" in rendered
    assert "log-queries" not in rendered


def test_dnsmasq_render_filters_own_listen_address_from_upstreams(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "server": {"dns": ["10.10.10.1", "1.1.1.1"]},
            "routing": {
                "mode": "split",
                "split": {
                    "tunnel_dns": True,
                    "domains": ["corp.example.com"],
                },
            },
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "server=10.10.10.1" not in rendered
    assert "server=1.1.1.1" in rendered
    assert "server=/corp.example.com/1.1.1.1" in rendered


def test_dnsmasq_render_hardening_options(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.yaml", environ={})

    rendered = DnsmasqConfigRenderer().render(config)

    assert "no-negcache" in rendered
    assert "no-resolv" in rendered


def test_dnsmasq_render_includes_local_records(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "internal_dns": {
                "local_records_enabled": True,
                "local_records": ["nas.corp.local 10.11.11.5", "printer 10.11.11.6"],
            }
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "address=/nas.corp.local/10.11.11.5" in rendered
    assert "address=/printer/10.11.11.6" in rendered


def test_dnsmasq_render_feeds_named_target_domains_into_their_own_set(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "finance",
                        "server": "finance.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "domains": ["finance-internal.corp"],
                    }
                ],
            },
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert (
        "nftset=/finance-internal.corp/4#inet#kornode_filter#split_v4_finance_dynamic,"
        "6#inet#kornode_filter#split_v6_finance_dynamic" in rendered
    )
    # No DNS-forwarding override -- that's specific to routing.split.tunnel_dns.
    assert "server=/finance-internal.corp/" not in rendered


def test_dnsmasq_render_ignores_named_target_domains_without_upstream_enabled(
    tmp_path: Path,
) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {
                "enabled": False,
                "profiles": [
                    {
                        "name": "finance",
                        "server": "finance.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "domains": ["finance-internal.corp"],
                    }
                ],
            },
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "finance-internal.corp" not in rendered


def test_dnsmasq_render_feeds_named_target_host_domains_into_their_own_host_set(
    tmp_path: Path,
) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "finance",
                        "server": "finance.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "route_clients_enabled": False,
                        "route_host_enabled": True,
                        "host_domains": ["finance-internal.corp"],
                    }
                ],
            },
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert (
        "nftset=/finance-internal.corp/4#inet#kornode_filter#host_v4_finance_dynamic,"
        "6#inet#kornode_filter#host_v6_finance_dynamic" in rendered
    )


def test_dnsmasq_render_feeds_host_split_domains_into_their_own_set(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "full",
                "host_traffic": True,
                "host_mode": "split",
                "host_split": {"domains": ["intranet.example"]},
            },
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert (
        "nftset=/intranet.example/4#inet#kornode_filter#host_split_v4_dynamic,"
        "6#inet#kornode_filter#host_split_v6_dynamic" in rendered
    )


def test_dnsmasq_render_ignores_host_split_domains_without_host_traffic(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "full",
                "host_mode": "split",
                "host_split": {"domains": ["intranet.example"]},
            },
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "intranet.example" not in rendered
