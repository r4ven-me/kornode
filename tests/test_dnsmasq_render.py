from __future__ import annotations

from pathlib import Path

from kornode.config.loader import load_config
from kornode.renderers.dnsmasq import DnsmasqConfigRenderer


def test_dnsmasq_render_forward_domains_with_multiple_upstreams(tmp_path: Path) -> None:
    # forward_domains/forward_upstreams is the one real DNS-forwarding
    # feature left in dnsmasq.conf.j2 -- one server=/domain/... line per
    # configured upstream.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
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


def test_dnsmasq_render_does_not_mention_split_routing_domains(tmp_path: Path) -> None:
    # routing.split.domains are resolved into their nftables set by
    # DomainResolverService now (see tests/test_domain_resolver.py), not by
    # dnsmasq answering a live query -- dnsmasq doesn't need to know about
    # them at all any more.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"client_policy": "split", "split": {"domains": ["example.com"]}}
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "example.com" not in rendered


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
        cli_overrides={"server": {"dns": ["10.10.10.1", "1.1.1.1"]}},
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "server=10.10.10.1" not in rendered
    assert "server=1.1.1.1" in rendered


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


def test_dnsmasq_render_does_not_mention_named_target_or_host_split_domains(
    tmp_path: Path,
) -> None:
    # A profile's own domains/host_domains and routing.host_split's domains
    # are all resolved by DomainResolverService now -- none of them need
    # anything from dnsmasq (unlike a profile's server-pushed domains, see
    # test_upstream_pushed.py, which still need a server=/domain/... answer
    # override).
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "host_policy": "split",
                "host_split": {"domains": ["intranet.example"]},
            },
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "finance",
                        "server": "finance.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "domains": ["finance-internal.corp"],
                        "route_host_enabled": True,
                        "host_domains": ["finance-host.corp"],
                    }
                ],
            },
        },
        environ={},
    )

    rendered = DnsmasqConfigRenderer().render(config)

    assert "intranet.example" not in rendered
    assert "finance-internal.corp" not in rendered
    assert "finance-host.corp" not in rendered
