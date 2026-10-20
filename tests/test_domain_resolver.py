from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.services.domain_resolver import (
    MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    DnsLookup,
    DomainResolverService,
    domain_groups,
)
from kornode.services.netinputs import resolved_state_dir


def _config(tmp_path: Path, overrides: dict[str, object] | None = None) -> AppConfig:
    base: dict[str, object] = {
        "system": {
            "data_dir": str(tmp_path / "data"),
            "generated_dir": str(tmp_path / "generated"),
            "secrets_dir": str(tmp_path / "secrets"),
        }
    }
    if overrides:
        from kornode.config.loader import deep_merge

        base = deep_merge(base, overrides)
    return load_config(tmp_path / "missing.yaml", cli_overrides=base, environ={})


class FakeLookup(DnsLookup):
    """Answers from a fixed table instead of the network: domain -> (v4, v6, ttl)."""

    def __init__(self, table: dict[str, tuple[list[str], list[str], int | None]]) -> None:
        super().__init__()
        self.table = table
        self.calls: list[tuple[str, tuple[str, ...], str]] = []

    def resolve(
        self, domain: str, nameservers: Sequence[str], rdtype: str
    ) -> tuple[list[str], int | None]:
        self.calls.append((domain, tuple(nameservers), rdtype))
        ips_v4, ips_v6, ttl = self.table.get(domain, ([], [], None))
        return (ips_v4 if rdtype == "A" else ips_v6), ttl


class FakeNet:
    def __init__(self) -> None:
        self.wake_calls = 0

    def wake(self) -> bool:
        self.wake_calls += 1
        return True


def _upstream_enabled() -> dict[str, object]:
    return {
        "upstream": {
            "enabled": True,
            "profiles": [
                {
                    "name": "primary",
                    "server": "vpn.example.com",
                    "auth_type": "password",
                    "username": "user",
                }
            ],
        }
    }


def test_domain_groups_includes_default_target_only_when_client_policy_is_split(
    tmp_path: Path,
) -> None:
    split = domain_groups(
        _config(
            tmp_path,
            {
                **_upstream_enabled(),
                "routing": {"client_policy": "split", "split": {"domains": ["example.com"]}},
            },
        )
    )
    assert any(group.name == "split" for group in split)

    full = domain_groups(
        _config(
            tmp_path,
            {
                **_upstream_enabled(),
                "routing": {"client_policy": "full", "split": {"domains": ["example.com"]}},
            },
        )
    )
    assert not any(group.name == "split" for group in full)


def test_domain_groups_includes_named_target_domains_regardless_of_client_policy(
    tmp_path: Path,
) -> None:
    groups = domain_groups(
        _config(
            tmp_path,
            {
                "routing": {"client_policy": "full"},
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
        )
    )
    matching = [g for g in groups if g.name == "p_finance"]
    assert len(matching) == 1
    assert matching[0].domains == ("finance-internal.corp",)


def test_domain_groups_host_domains_use_profile_dns_when_configured(tmp_path: Path) -> None:
    from kornode.services.upstream_pushed import PushedRouting, PushedRoutingStore

    config = _config(
        tmp_path,
        {
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "office",
                        "server": "office.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "route_host_enabled": True,
                        "accept_server_routes": True,
                        "host_domains": ["own.example"],
                    }
                ],
            }
        },
    )
    PushedRoutingStore(config).save(
        config.upstream.profiles[0],
        PushedRouting(domains=["corp.example.com"], dns=["172.16.0.53"]),
    )

    groups = domain_groups(config)
    host_group = next(g for g in groups if g.name == "p_office_host")
    assert set(host_group.domains) == {"own.example", "corp.example.com"}
    assert host_group.nameservers == ("172.16.0.53",)


def test_domain_groups_includes_global_host_split_only_when_host_policy_is_split(
    tmp_path: Path,
) -> None:
    split = domain_groups(
        _config(
            tmp_path,
            {
                **_upstream_enabled(),
                "routing": {
                    "host_policy": "split",
                    "host_split": {"domains": ["intranet.example"]},
                },
            },
        )
    )
    assert any(g.name == "host_split" and g.domains == ("intranet.example",) for g in split)

    off = domain_groups(
        _config(
            tmp_path,
            {
                **_upstream_enabled(),
                "routing": {
                    "host_policy": "off",
                    "host_split": {"domains": ["intranet.example"]},
                },
            },
        )
    )
    assert not any(g.name == "host_split" for g in off)


def test_refresh_is_a_noop_when_nothing_is_configured_to_resolve(tmp_path: Path) -> None:
    net = FakeNet()
    outcome = DomainResolverService(_config(tmp_path), net=net).refresh()

    assert outcome.resolved == []
    assert not outcome.changed
    assert outcome.next_interval_seconds == MAX_INTERVAL_SECONDS
    assert net.wake_calls == 0


def test_refresh_writes_resolved_addresses_and_wakes_net(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
            **_upstream_enabled(),
            "routing": {"client_policy": "split", "split": {"domains": ["example.com"]}},
        },
    )
    lookup = FakeLookup({"example.com": (["203.0.113.5", "203.0.113.6"], ["2001:db8::1"], 120)})
    net = FakeNet()

    outcome = DomainResolverService(config, lookup=lookup, net=net).refresh()

    assert outcome.changed
    assert outcome.next_interval_seconds == 120
    assert net.wake_calls == 1
    assert (resolved_state_dir(config) / "split.txt").read_text(encoding="utf-8") == (
        "2001:db8::1\n203.0.113.5\n203.0.113.6\n"
    )


def test_refresh_removes_stale_files_when_domain_list_is_now_empty(tmp_path: Path) -> None:
    config = _config(tmp_path)
    stale = resolved_state_dir(config) / "split.txt"
    stale.parent.mkdir(parents=True)
    stale.write_text("203.0.113.5\n", encoding="utf-8")
    net = FakeNet()

    outcome = DomainResolverService(config, lookup=FakeLookup({}), net=net).refresh()

    assert outcome.changed
    assert outcome.resolved == []
    assert not stale.exists()
    assert net.wake_calls == 1


def test_refresh_interval_is_clamped_between_min_and_max(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
            **_upstream_enabled(),
            "routing": {
                "client_policy": "split",
                "split": {"domains": ["short.example", "long.example"]},
            },
        },
    )
    lookup = FakeLookup(
        {
            "short.example": (["203.0.113.1"], [], 5),
            "long.example": (["203.0.113.2"], [], 999999),
        }
    )

    outcome = DomainResolverService(config, lookup=lookup, net=FakeNet()).refresh()

    assert outcome.next_interval_seconds == MIN_INTERVAL_SECONDS


def test_refresh_dry_run_does_not_touch_the_runner_or_filesystem(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
            **_upstream_enabled(),
            "routing": {"client_policy": "split", "split": {"domains": ["example.com"]}},
        },
    )
    lookup = FakeLookup({"example.com": (["203.0.113.5"], [], 60)})
    net = FakeNet()

    outcome = DomainResolverService(config, lookup=lookup, net=net).refresh(dry_run=True)

    assert outcome.changed
    assert net.wake_calls == 0
    assert not resolved_state_dir(config).exists()
