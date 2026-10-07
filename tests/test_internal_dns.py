from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.renderers.dnsmasq import DnsmasqConfigRenderer
from kornode.renderers.ocserv import OcservConfigRenderer
from kornode.renderers.supervisor import SupervisorConfigRenderer
from kornode.services import internal_dns
from kornode.services.config import ConfigService
from kornode.services.internal_dns import InternalDnsService, parse_blocklist_text


def _config(tmp_path: Path, overrides: dict[str, Any] | None = None) -> AppConfig:
    base: dict[str, Any] = {
        "system": {
            "data_dir": str(tmp_path / "data"),
            "log_dir": str(tmp_path / "logs"),
            "generated_dir": str(tmp_path / "generated"),
            "secrets_dir": str(tmp_path / "secrets"),
        }
    }
    if overrides:
        from kornode.config.loader import deep_merge

        base = deep_merge(base, overrides)
    return load_config(tmp_path / "missing.yaml", cli_overrides=base, environ={})


def test_parse_blocklist_plain_and_hosts_formats() -> None:
    text = """
# comment
! adblock comment
ads.example.com
0.0.0.0 tracker.example.net telemetry.example.net
127.0.0.1 localhost
::1 ip6-localhost
||banner.example.org^
not a domain line
ads.example.com
"""
    parsed = parse_blocklist_text(text)
    assert parsed.domains == [
        "ads.example.com",
        "tracker.example.net",
        "telemetry.example.net",
        "banner.example.org",
    ]
    assert parsed.skipped == 3  # localhost/ip6-localhost hosts lines and "not a domain line"


def test_parse_blocklist_allows_underscores_and_lowercases() -> None:
    parsed = parse_blocklist_text("Ad_Srv.Example.COM.\n")
    assert parsed.domains == ["ad_srv.example.com"]


def test_merged_blocklist_combines_three_sources(tmp_path: Path) -> None:
    blocklist_file = tmp_path / "blocked.txt"
    blocklist_file.write_text("filed.example.com\nads.example.com\n", encoding="utf-8")
    url = "https://lists.example.com/hosts.txt"
    config = _config(
        tmp_path,
        {
            "internal_dns": {
                "blocklist_domains": ["ads.example.com"],
                "blocklist_files": [str(blocklist_file)],
                "blocklist_urls": [url],
            }
        },
    )
    service = InternalDnsService(config)
    cache_path = service.blocklist_cache_path(url)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("cached.example.com\nads.example.com\n", encoding="utf-8")

    merged = service.merged_blocklist()

    assert merged == ["ads.example.com", "filed.example.com", "cached.example.com"]


def test_merged_blocklist_combines_multiple_files_and_urls(tmp_path: Path) -> None:
    file_a = tmp_path / "a.txt"
    file_a.write_text("a.example.com\n", encoding="utf-8")
    file_b = tmp_path / "b.txt"
    file_b.write_text("b.example.com\n", encoding="utf-8")
    url_a = "https://lists.example.com/a.txt"
    url_b = "https://lists.example.com/b.txt"
    config = _config(
        tmp_path,
        {
            "internal_dns": {
                "blocklist_files": [str(file_a), str(file_b)],
                "blocklist_urls": [url_a, url_b],
            }
        },
    )
    service = InternalDnsService(config)
    for url, domain in ((url_a, "cached-a.example.com"), (url_b, "cached-b.example.com")):
        cache_path = service.blocklist_cache_path(url)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(f"{domain}\n", encoding="utf-8")

    merged = service.merged_blocklist()

    assert merged == [
        "a.example.com",
        "b.example.com",
        "cached-a.example.com",
        "cached-b.example.com",
    ]


def test_url_cache_ignored_when_url_not_configured(tmp_path: Path) -> None:
    config = _config(tmp_path)
    service = InternalDnsService(config)
    cache_path = service.blocklist_cache_path("https://stale.example.com/hosts.txt")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("stale.example.com\n", encoding="utf-8")

    assert service.merged_blocklist() == []


def test_refresh_url_blocklist_validates_and_caches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "https://lists.example.com/hosts.txt"
    config = _config(
        tmp_path,
        {
            "internal_dns": {
                "blocklist_urls": [url],
            }
        },
    )
    monkeypatch.setattr(
        internal_dns,
        "_fetch_blocklist_text",
        lambda url: "0.0.0.0 ads.example.com\ngarbage line here\n",
    )
    service = InternalDnsService(config)

    preview = service.refresh_url_blocklist(url, preview=True)
    assert preview.valid == 1
    assert preview.skipped == 1
    assert not preview.saved
    assert not service.blocklist_cache_path(url).exists()

    result = service.refresh_url_blocklist(url)
    assert result.saved
    assert service.blocklist_cache_path(url).read_text(encoding="utf-8") == "ads.example.com\n"
    meta = service.url_cache_meta(url)
    assert meta is not None
    assert meta["valid"] == 1


def test_refresh_url_blocklist_rejects_url_not_in_configured_list(tmp_path: Path) -> None:
    config = _config(tmp_path)
    with pytest.raises(ValueError, match="does not contain"):
        InternalDnsService(config).refresh_url_blocklist("https://unsaved.example.com/x")


def test_refresh_url_blocklist_rejects_empty_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "https://lists.example.com/hosts.txt"
    config = _config(
        tmp_path,
        {
            "internal_dns": {
                "blocklist_urls": [url],
            }
        },
    )
    monkeypatch.setattr(internal_dns, "_fetch_blocklist_text", lambda url: "# nothing here\n")
    with pytest.raises(ValueError, match="did not contain any valid domain"):
        InternalDnsService(config).refresh_url_blocklist(url)


def test_blocklist_url_must_be_http(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="HTTP\\(S\\)"):
        _config(
            tmp_path,
            {"internal_dns": {"blocklist_urls": ["file:///etc/passwd"]}},
        )


def test_local_records_normalizes_hostname_and_ip(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {"internal_dns": {"local_records": ["  Nas.Corp.Local   10.11.11.5  "]}},
    )

    assert config.internal_dns.local_records == ["Nas.Corp.Local 10.11.11.5"]


def test_local_records_rejects_missing_ip(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="hostname ip"):
        _config(tmp_path, {"internal_dns": {"local_records": ["nas.corp.local"]}})


def test_local_records_rejects_invalid_ip(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _config(tmp_path, {"internal_dns": {"local_records": ["nas.corp.local not-an-ip"]}})


def test_internal_dns_requires_listen_inside_vpn_subnet(tmp_path: Path) -> None:
    # An explicit listen wins over config/loader.py's auto-computed default
    # (see test_config_loader.py), so this is the one way left to still hit
    # the mismatch: listen explicitly set, and wrong for the subnet.
    with pytest.raises(ValueError, match="internal_dns.listen"):
        _config(
            tmp_path,
            {
                "server": {"ipv4_network": "10.99.0.0/24"},
                "internal_dns": {"listen": "10.10.10.1"},
            },
        )


def test_client_dns_becomes_vpn_server_when_server_enabled(tmp_path: Path) -> None:
    # The built-in resolver is mandatory, not opt-in, whenever the VPN
    # server is enabled (the default) -- see AppConfig.client_dns_servers().
    config = _config(tmp_path)
    assert config.dns_tunnel_active()
    assert config.client_dns_servers() == ["10.10.10.1"]

    rendered = OcservConfigRenderer().render(config)
    assert "dns = 10.10.10.1" in rendered
    assert "dns = 1.1.1.1" not in rendered
    assert "tunnel-all-dns = true" in rendered


def test_client_dns_uses_server_dns_when_vpn_server_disabled(tmp_path: Path) -> None:
    # The one case server.dns still matters: no VPN server means no VPN
    # clients to push the built-in resolver to in the first place.
    config = _config(tmp_path, {"server": {"enabled": False}})
    assert not config.dns_tunnel_active()
    rendered = OcservConfigRenderer().render(config)
    assert "dns = 1.1.1.1" in rendered
    assert "tunnel-all-dns" not in rendered


def test_dns_tunnel_active_when_a_named_upstream_target_has_domains(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
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
            }
        },
    )

    assert config.dns_tunnel_active()


def test_dns_tunnel_active_when_forward_domains_configured_alone(tmp_path: Path) -> None:
    # forward_upstreams/forward_domains must start dnsmasq on their own --
    # otherwise the forwarding config they describe is silently dead, since
    # there is no dnsmasq process to do the forwarding. server.enabled is
    # off here so this isn't just "the VPN server already made it mandatory".
    config = _config(
        tmp_path,
        {
            "server": {"enabled": False},
            "internal_dns": {
                "forward_upstreams": ["127.207.207.1"],
                "forward_domains": ["r4ven.lan"],
            },
        },
    )

    assert config.dns_tunnel_active()


def test_dnsmasq_render_includes_blocklist_and_upstreams(tmp_path: Path) -> None:
    config = _config(tmp_path, {"internal_dns": {"blocklist_enabled": True}})
    rendered = DnsmasqConfigRenderer().render(config)
    assert "server=1.1.1.1" in rendered
    assert "server=8.8.8.8" in rendered
    assert "conf-file=" in rendered
    assert "dnsmasq-blocklist.conf" in rendered
    # split DNS lines must not leak into internal-DNS-only mode
    assert "nftset=" not in rendered


def test_legacy_default_upstreams_key_migrates_to_upstreams(tmp_path: Path) -> None:
    # internal_dns.default_upstreams was renamed to upstreams (no more
    # fallback to server.dns) -- see AppConfig.migrate_legacy_dns_keys.
    config = _config(
        tmp_path,
        {
            "server": {"dns": ["1.1.1.1", "8.8.8.8"]},
            "internal_dns": {"default_upstreams": ["9.9.9.9"]},
        },
    )
    assert config.internal_dns.upstreams == ["9.9.9.9"]
    rendered = DnsmasqConfigRenderer().render(config)
    assert "server=9.9.9.9" in rendered
    assert "server=1.1.1.1" not in rendered
    assert "server=8.8.8.8" not in rendered


def test_dnsmasq_render_upstreams_is_independent_of_server_dns(tmp_path: Path) -> None:
    # upstreams has its own real default now; it no longer falls back to
    # server.dns when left unset (that fallback silently broke in subtle
    # ways -- see docs/architecture.md).
    config = _config(tmp_path, {"server": {"dns": ["9.9.9.9"]}})
    assert config.internal_dns.upstreams == ["1.1.1.1", "8.8.8.8"]
    rendered = DnsmasqConfigRenderer().render(config)
    assert "server=1.1.1.1" in rendered
    assert "server=9.9.9.9" not in rendered


def test_rendered_files_include_dnsmasq_and_blocklist(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
            "internal_dns": {
                "blocklist_enabled": True,
                "blocklist_domains": ["ads.example.com", "tracker.example.net"],
            }
        },
    )
    rendered = {str(item.path): item.content for item in ConfigService().render_files(config)}

    blocklist_path = str(InternalDnsService(config).blocklist_conf_path())
    assert blocklist_path in rendered
    assert "address=/ads.example.com/0.0.0.0" in rendered[blocklist_path]
    assert "address=/ads.example.com/::" in rendered[blocklist_path]
    assert "address=/tracker.example.net/0.0.0.0" in rendered[blocklist_path]
    dnsmasq_path = str(config.generated_path("dnsmasq.conf"))
    assert dnsmasq_path in rendered

    supervisor = SupervisorConfigRenderer().render(config)
    assert "[program:dnsmasq]" in supervisor
    assert "autostart=true" in supervisor
    # dnsmasq must start through korctl so the listen IP is assigned to lo first
    assert "command=/usr/local/bin/korctl internal-dns run" in supervisor


def test_ensure_listen_address_assigns_ip_to_loopback(tmp_path: Path) -> None:
    config = _config(tmp_path)
    result = InternalDnsService(config).ensure_listen_address(dry_run=True)
    assert result.argv == ("ip", "addr", "replace", "10.10.10.1/32", "dev", "lo")
    assert result.dry_run


def test_remove_listen_address_command(tmp_path: Path) -> None:
    config = _config(tmp_path)
    result = InternalDnsService(config).remove_listen_address(dry_run=True)
    assert result.argv == ("ip", "addr", "del", "10.10.10.1/32", "dev", "lo")


def test_dnsmasq_argv_uses_generated_conf(tmp_path: Path) -> None:
    config = _config(tmp_path)
    argv = InternalDnsService(config).dnsmasq_argv()
    assert argv[0] == "/usr/sbin/dnsmasq"
    assert argv[1] == f"--conf-file={config.generated_path('dnsmasq.conf')}"
    assert argv[2] == "--keep-in-foreground"


def test_dnsmasq_not_rendered_when_server_disabled(tmp_path: Path) -> None:
    config = _config(tmp_path, {"server": {"enabled": False}})
    rendered_paths = [str(item.path) for item in ConfigService().render_files(config)]
    assert str(config.generated_path("dnsmasq.conf")) not in rendered_paths
    supervisor = SupervisorConfigRenderer().render(config)
    assert "[program:dnsmasq]" in supervisor
    assert "autostart=false" in supervisor


def test_internal_dns_enabled_field_is_not_backward_compatible(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="enabled"):
        _config(tmp_path, {"internal_dns": {"enabled": True}})


def test_server_enabled_alone_activates_dnsmasq_and_client_dns(tmp_path: Path) -> None:
    # The resolver is mandatory, not opt-in, whenever the VPN server itself
    # is enabled -- see AppConfig.dnsmasq_active_reasons()/client_dns_servers().
    config = _config(tmp_path)

    assert config.dnsmasq_active_reasons() == ["server_enabled"]
    assert config.client_dns_servers() == ["10.10.10.1"]


def test_each_internal_dns_feature_activates_dnsmasq_on_its_own(tmp_path: Path) -> None:
    # server.enabled off here so each flag is shown activating dnsmasq by
    # itself, not just riding along with the VPN server's own reason.
    for flag in ("blocklist_enabled", "local_records_enabled"):
        config = _config(tmp_path, {"server": {"enabled": False}, "internal_dns": {flag: True}})

        assert config.dnsmasq_active_reasons() == [flag]
        # No VPN server means no VPN clients to push the resolver to.
        assert config.client_dns_servers() == ["1.1.1.1", "8.8.8.8"]


def test_host_profile_domains_activate_dnsmasq_without_changing_client_dns(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path,
        {
            "server": {"enabled": False},
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "host-only",
                        "server": "vpn.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "route_clients_enabled": False,
                        "route_host_enabled": True,
                        "host_domains": ["host.corp"],
                    }
                ],
            },
        },
    )

    assert config.dnsmasq_active_reasons() == ["profile_host_domains"]
    assert config.client_dns_servers() == ["1.1.1.1", "8.8.8.8"]
    rendered_paths = [str(item.path) for item in ConfigService().render_files(config)]
    assert str(config.generated_path("dnsmasq.conf")) in rendered_paths


def test_blocklist_and_local_records_require_their_own_flags(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
            "internal_dns": {
                "blocklist_domains": ["ads.example.com"],
                "local_records": ["nas.corp.local 10.11.11.5"],
            }
        },
    )

    rendered = DnsmasqConfigRenderer().render(config)
    assert "dnsmasq-blocklist.conf" not in rendered
    assert "address=/nas.corp.local/10.11.11.5" not in rendered
    rendered_paths = [str(item.path) for item in ConfigService().render_files(config)]
    assert str(InternalDnsService(config).blocklist_conf_path()) not in rendered_paths
