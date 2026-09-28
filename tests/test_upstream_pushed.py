"""Server-pushed routing for upstream profiles (the former korclient):
handshake/sync parsing, storage, routing/nftables/dnsmasq integration and
the UpstreamService plumbing around it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kornode.config.models import AppConfig, UpstreamProfileConfig
from kornode.renderers.dnsmasq import DnsmasqConfigRenderer
from kornode.renderers.nftables import NftablesConfigRenderer
from kornode.services.command import CommandResult
from kornode.services.routing import RoutingService
from kornode.services.upstream import UpstreamService
from kornode.services.upstream_pushed import (
    PushedRouting,
    PushedRoutingStore,
    parse_sync_payload,
    parse_vpnc_environment,
)

HANDSHAKE_ENV = {
    "TUNDEV": "oc-middle0",
    "CISCO_SPLIT_INC": "3",
    "CISCO_SPLIT_INC_0_ADDR": "10.20.0.0",
    "CISCO_SPLIT_INC_0_MASKLEN": "16",
    "CISCO_SPLIT_INC_1_ADDR": "not-an-ip",
    "CISCO_SPLIT_INC_1_MASKLEN": "8",
    "CISCO_SPLIT_INC_2_ADDR": "192.0.2.10",
    "CISCO_SPLIT_INC_2_MASKLEN": "32",
    "CISCO_IPV6_SPLIT_INC": "1",
    "CISCO_IPV6_SPLIT_INC_0_ADDR": "2001:db8:10::",
    "CISCO_IPV6_SPLIT_INC_0_MASKLEN": "48",
    "CISCO_SPLIT_DNS": "Corp.Example.com., bad_domain!,git.example.org",
    "INTERNAL_IP4_DNS": "172.16.0.53 junk",
}


class FakeRunner:
    def __init__(self, responses: dict[str, CommandResult] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.responses = responses or {}

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        self.calls.append(argv)
        if argv[0] in self.responses:
            return self.responses[argv[0]]
        if tuple(argv[:5]) == ("nft", "list", "chain", "ip", "filter"):
            return CommandResult(tuple(argv), 1, "", "No such file or directory")
        return CommandResult(tuple(argv), 0, "", "")


def _config(tmp_path: Path, **profile: object) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
                "log_dir": tmp_path / "logs",
            },
            "server": {"ipv4_network": "10.99.0.0/24"},
            "internal_dns": {"listen": "10.99.0.1"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "office",
                        "server": "vpn.example.com",
                        "username": "alice",
                        "route_host_enabled": True,
                        "accept_server_routes": True,
                        **profile,
                    }
                ],
            },
        }
    )


def _store_pushed(config: AppConfig, **pushed: Any) -> None:
    PushedRoutingStore(config).save(config.upstream.profiles[0], PushedRouting(**pushed))


def test_parse_vpnc_environment_collects_routes_domains_and_dns() -> None:
    pushed = parse_vpnc_environment(HANDSHAKE_ENV)

    assert pushed.routes == ["10.20.0.0/16", "192.0.2.10/32", "2001:db8:10::/48"]
    assert pushed.domains == ["corp.example.com", "git.example.org"]
    assert pushed.dns == ["172.16.0.53"]
    assert pushed.source == "handshake"
    assert pushed.interface == "oc-middle0"


def test_parse_vpnc_environment_without_split_lists_is_empty() -> None:
    pushed = parse_vpnc_environment({"TUNDEV": "oc-middle0", "CISCO_SPLIT_INC": "garbage"})

    assert pushed.is_empty()


def test_parse_sync_payload_filters_invalid_entries() -> None:
    routes, domains, version = parse_sync_payload(
        {
            "version": "abc123",
            "routes": ["10.1.0.0/16", 5, "nope", "10.1.0.0/16"],
            "split_dns": ["Intra.Example.com", "bad domain"],
        }
    )

    assert routes == ["10.1.0.0/16"]
    assert domains == ["intra.example.com"]
    assert version == "abc123"


def test_parse_sync_payload_rejects_non_object() -> None:
    with pytest.raises(ValueError):
        parse_sync_payload(["not", "an", "object"])


def test_effective_is_empty_unless_profile_accepts_server_routes(tmp_path: Path) -> None:
    config = _config(tmp_path, accept_server_routes=False)
    _store_pushed(config, routes=["10.20.0.0/16"])

    store = PushedRoutingStore(config)

    assert store.effective(config.upstream.profiles[0]).is_empty()
    assert store.fingerprint() == ""


def test_effective_requires_host_routing(tmp_path: Path) -> None:
    config = _config(tmp_path, route_host_enabled=False)
    _store_pushed(config, routes=["10.20.0.0/16"])

    assert PushedRoutingStore(config).effective(config.upstream.profiles[0]).is_empty()


def test_fingerprint_changes_with_pushed_lists(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = PushedRoutingStore(config)
    assert store.fingerprint() == ""

    _store_pushed(config, routes=["10.20.0.0/16"])
    first = store.fingerprint()
    _store_pushed(config, routes=["10.20.0.0/16"], synced_at=123)
    unchanged = store.fingerprint()
    _store_pushed(config, routes=["10.30.0.0/16"])

    assert first and first == unchanged
    assert store.fingerprint() != first


def test_save_handshake_keeps_sync_pacing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = config.upstream.profiles[0]
    store = PushedRoutingStore(config)
    store.save(profile, PushedRouting(routes=["10.1.0.0/16"], synced_at=500))

    store.save_handshake(profile, parse_vpnc_environment(HANDSHAKE_ENV))

    loaded = store.load(profile)
    assert loaded.synced_at == 500
    assert loaded.routes[0] == "10.20.0.0/16"


def test_store_load_tolerates_a_corrupt_file(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = PushedRoutingStore(config)
    path = store.path(config.upstream.profiles[0])
    path.parent.mkdir(parents=True)
    path.write_text("{not json")

    assert store.load(config.upstream.profiles[0]) == PushedRouting()


def test_sync_url_must_be_http(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        UpstreamProfileConfig(
            name="office", server="vpn.example.com", username="a", sync_url="ftp://x"
        )
    profile = UpstreamProfileConfig(
        name="office", server="vpn.example.com", username="a", sync_url=" https://10.1.1.1:8443/ "
    )
    assert profile.sync_url == "https://10.1.1.1:8443"


def test_list_targets_merges_pushed_lists_into_host_routing(tmp_path: Path) -> None:
    config = _config(tmp_path, host_routes=["198.51.100.0/24"], host_domains=["own.example"])
    _store_pushed(
        config,
        routes=["10.20.0.0/16", "2001:db8:10::/48"],
        domains=["corp.example.com"],
        dns=["172.16.0.53"],
    )

    target = next(
        item
        for item in RoutingService(config).list_targets(default_interface="eth0")
        if item.name == "office"
    )

    assert target.host_routes == ["198.51.100.0/24", "10.20.0.0/16", "172.16.0.53/32"]
    assert target.host_routes_v6 == ["2001:db8:10::/48"]
    assert target.host_domains == ["own.example", "corp.example.com"]
    assert target.server_domains == ["corp.example.com"]
    assert target.server_dns == ["172.16.0.53"]


def test_list_targets_routes_upstream_dns_only_for_pushed_domains(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _store_pushed(config, routes=["10.20.0.0/16"], dns=["172.16.0.53"])

    target = next(
        item
        for item in RoutingService(config).list_targets(default_interface="eth0")
        if item.name == "office"
    )

    assert target.host_routes == ["10.20.0.0/16"]


def test_list_targets_creates_host_target_from_pushed_lists_alone(tmp_path: Path) -> None:
    config = _config(tmp_path)
    names = [t.name for t in RoutingService(config).list_targets(default_interface="eth0")]
    assert names == ["default"]

    _store_pushed(config, routes=["10.20.0.0/16"])

    names = [t.name for t in RoutingService(config).list_targets(default_interface="eth0")]
    assert names == ["default", "office"]


def test_nftables_render_puts_pushed_ipv6_routes_into_the_v6_host_set(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _store_pushed(config, routes=["10.20.0.0/16", "2001:db8:10::/48"])

    rendered = NftablesConfigRenderer().render(config)

    v4_block = rendered.split("set host_v4_office_static {", 1)[1].split("}", 2)
    v6_block = rendered.split("set host_v6_office_static {", 1)[1].split("}", 2)
    assert "10.20.0.0/16" in v4_block[0] + v4_block[1]
    assert "2001:db8:10::/48" not in v4_block[0] + v4_block[1]
    assert "2001:db8:10::/48" in v6_block[0] + v6_block[1]


def test_dnsmasq_render_resolves_pushed_domains_through_upstream_dns(tmp_path: Path) -> None:
    config = _config(tmp_path, host_domains=["own.example"])
    _store_pushed(config, domains=["corp.example.com"], dns=["172.16.0.53"])

    rendered = DnsmasqConfigRenderer().render(config)

    assert "server=/corp.example.com/172.16.0.53" in rendered
    assert "nftset=/corp.example.com/4#inet#kornode_filter#host_v4_office" in rendered
    # The admin's own host domains keep resolving through the normal DNS.
    assert "server=/own.example/" not in rendered
    assert "nftset=/own.example/4#inet#kornode_filter#host_v4_office" in rendered


def test_accepting_server_routes_keeps_dnsmasq_running(tmp_path: Path) -> None:
    assert "profile_server_routes" in _config(tmp_path).dnsmasq_active_reasons()
    assert "profile_server_routes" not in _config(
        tmp_path, accept_server_routes=False
    ).dnsmasq_active_reasons()


def test_record_vpnc_event_stores_handshake_for_the_matching_profile(tmp_path: Path) -> None:
    config = _config(tmp_path)
    service = UpstreamService(config, runner=FakeRunner())

    profile = service.record_vpnc_event("connect", HANDSHAKE_ENV)

    assert profile is not None and profile.name == "office"
    assert service.pushed.load(profile).domains == ["corp.example.com", "git.example.org"]


@pytest.mark.parametrize(
    ("reason", "tundev"),
    [("disconnect", "oc-middle0"), ("pre-init", "oc-middle0"), ("connect", "tun99")],
)
def test_record_vpnc_event_ignores_other_events_and_interfaces(
    tmp_path: Path, reason: str, tundev: str
) -> None:
    config = _config(tmp_path)
    service = UpstreamService(config, runner=FakeRunner())

    assert service.record_vpnc_event(reason, {**HANDSHAKE_ENV, "TUNDEV": tundev}) is None
    assert service.pushed.load(config.upstream.profiles[0]) == PushedRouting()


def test_sync_server_routes_uses_the_profile_tunnel(tmp_path: Path) -> None:
    config = _config(tmp_path, sync_url="https://10.10.10.1:8443")
    body = json.dumps(
        {"version": "v2", "routes": ["10.40.0.0/16"], "split_dns": ["intra.example"]}
    )
    runner = FakeRunner({"curl": CommandResult(("curl",), 0, body, "")})
    service = UpstreamService(config, runner=runner)
    profile = config.upstream.profiles[0]
    service.pushed.save(profile, PushedRouting(dns=["172.16.0.53"], source="handshake"))

    synced = service.sync_server_routes(profile)

    argv = runner.calls[0]
    assert argv[argv.index("--interface") + 1] == "oc-middle0"
    assert "--insecure" in argv
    assert argv[-1] == "https://10.10.10.1:8443/api/client/routing"
    assert synced.routes == ["10.40.0.0/16"]
    assert synced.domains == ["intra.example"]
    assert synced.dns == ["172.16.0.53"]  # kept from the handshake
    assert synced.source == "sync" and synced.version == "v2" and not synced.sync_error


def test_sync_server_routes_verifies_tls_when_asked(tmp_path: Path) -> None:
    config = _config(tmp_path, sync_url="https://panel.example", sync_verify_tls=True)
    runner = FakeRunner({"curl": CommandResult(("curl",), 0, "{}", "")})

    UpstreamService(config, runner=runner).sync_server_routes(config.upstream.profiles[0])

    assert "--insecure" not in runner.calls[0]


def test_sync_failure_keeps_previous_lists_and_records_the_error(tmp_path: Path) -> None:
    config = _config(tmp_path, sync_url="https://10.10.10.1:8443")
    runner = FakeRunner({"curl": CommandResult(("curl",), 22, "", "HTTP 403")})
    service = UpstreamService(config, runner=runner)
    profile = config.upstream.profiles[0]
    service.pushed.save(profile, PushedRouting(routes=["10.20.0.0/16"]))

    synced = service.sync_server_routes(profile)

    assert synced.routes == ["10.20.0.0/16"]
    assert synced.sync_error == "HTTP 403"
    assert synced.synced_at > 0


def test_refresh_server_routes_skips_disconnected_and_recently_synced_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path, sync_url="https://10.10.10.1:8443", sync_interval=60)
    runner = FakeRunner({"curl": CommandResult(("curl",), 0, "{}", "")})
    service = UpstreamService(config, runner=runner)
    profile = config.upstream.profiles[0]

    monkeypatch.setattr(service, "_profile_connected", lambda _profile: False)
    service.refresh_server_routes(now=1_000)
    assert not any(call[0] == "curl" for call in runner.calls)

    monkeypatch.setattr(service, "_profile_connected", lambda _profile: True)
    service.pushed.save(profile, PushedRouting(synced_at=990))
    service.refresh_server_routes(now=1_000)
    assert not any(call[0] == "curl" for call in runner.calls)

    service.refresh_server_routes(now=1_100)
    assert any(call[0] == "curl" for call in runner.calls)


def test_apply_server_routing_only_reloads_on_change(tmp_path: Path) -> None:
    config = _config(tmp_path)
    runner = FakeRunner()
    service = UpstreamService(config, runner=runner)

    assert service.apply_server_routing_if_changed() == []

    _store_pushed(config, routes=["10.20.0.0/16"])
    service.apply_server_routing_if_changed()
    nft_loads = [call for call in runner.calls if call[:2] == ["nft", "-f"]]
    assert len(nft_loads) == 1
    rendered = (tmp_path / "generated" / "nftables.nft").read_text()
    assert "10.20.0.0/16" in rendered

    assert service.apply_server_routing_if_changed() == []


def test_apply_server_routing_retries_after_a_failed_reload(tmp_path: Path) -> None:
    config = _config(tmp_path)
    runner = FakeRunner({"nft": CommandResult(("nft",), 1, "", "boom")})
    service = UpstreamService(config, runner=runner)
    _store_pushed(config, routes=["10.20.0.0/16"])

    service.apply_server_routing_if_changed()

    assert service.pushed.applied_fingerprint() == ""


def test_status_warns_when_upstream_pushes_our_own_subnet(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _store_pushed(config, routes=["10.99.0.0/24"], dns=["10.99.0.1"])

    status = UpstreamService(config, runner=FakeRunner()).server_routing_status(
        config.upstream.profiles[0]
    )

    assert status["routes"] == ["10.99.0.0/24"]
    warnings = status["warnings"]
    assert isinstance(warnings, list) and "server.ipv4_network" in warnings[0]


def test_status_warns_when_host_routing_is_off(tmp_path: Path) -> None:
    config = _config(tmp_path, route_host_enabled=False)

    status = UpstreamService(config, runner=FakeRunner()).server_routing_status(
        config.upstream.profiles[0]
    )

    assert status["active"] is False
    assert status["warnings"]
