from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

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


class ScriptedAnswer(list[str]):
    def __init__(self, ips: list[str], ttl: int | None) -> None:
        super().__init__(ips)
        self.rrset = SimpleNamespace(ttl=ttl) if ips else None


class ScriptedResolver:
    """Exercise the real DnsLookup wrapper without ever sending DNS packets."""

    def __init__(self) -> None:
        self.table: dict[
            tuple[str, str], tuple[list[str], int | None] | dns.exception.DNSException
        ] = {}
        self.calls: list[tuple[str, str]] = []

    def resolve(self, domain: str, rdtype: str, **kwargs: object) -> ScriptedAnswer:
        self.calls.append((domain, rdtype))
        answer = self.table.get((domain, rdtype), ([], None))
        if isinstance(answer, dns.exception.DNSException):
            raise answer
        return ScriptedAnswer(*answer)


@pytest.fixture
def resolver(monkeypatch: pytest.MonkeyPatch) -> ScriptedResolver:
    scripted = ScriptedResolver()
    monkeypatch.setattr(dns.resolver, "Resolver", lambda **kwargs: scripted)
    return scripted


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


def _split(*domains: str) -> dict[str, object]:
    return {
        **_upstream_enabled(),
        "sets": {"split": {"domains": list(domains)}},
        "egress": [{"from": ["clients"], "to": {"set": "split"}, "via": "upstream:primary"}],
    }


def test_domain_groups_cover_named_sets_and_inline_destinations(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
            **_upstream_enabled(),
            "sets": {
                "corp": {"domains": ["corp.example"]},
                "routes_only": {"routes": ["10.0.0.0/8"]},
            },
            "egress": [
                {"from": ["clients"], "to": {"set": "corp"}, "via": "upstream:primary"},
                {"from": ["clients"], "to": {"set": "routes_only"}, "via": "local"},
                {"from": ["clients"], "to": {"domains": ["inline.example"]}, "via": "local"},
            ],
        },
    )
    groups = {group.name: group.domains for group in domain_groups(config)}
    assert groups == {"corp": ("corp.example",), "rule2": ("inline.example",)}


def test_domain_groups_resolve_through_internal_dns_upstreams(tmp_path: Path) -> None:
    config = _config(tmp_path, _split("example.com"))
    (group,) = domain_groups(config)
    assert group.nameservers == tuple(config.internal_dns.upstreams)


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
            **_split("example.com"),
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
        _split("short.example", "long.example"),
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
            **_split("example.com"),
        },
    )
    lookup = FakeLookup({"example.com": (["203.0.113.5"], [], 60)})
    net = FakeNet()

    outcome = DomainResolverService(config, lookup=lookup, net=net).refresh(dry_run=True)

    assert outcome.changed
    assert net.wake_calls == 0
    assert not resolved_state_dir(config).exists()


@pytest.mark.parametrize(
    "failure",
    [
        dns.exception.Timeout(),
        dns.resolver.NoNameservers("SERVFAIL"),
        dns.resolver.NoResolverConfiguration(),
    ],
    ids=["timeout", "servfail-no-nameservers", "no-resolver-configuration"],
)
def test_success_transient_failure_success_replaces_not_accumulates_snapshot(
    tmp_path: Path, resolver: ScriptedResolver, failure: dns.exception.DNSException
) -> None:
    config = _config(tmp_path, _split("example.com"))
    net = FakeNet()
    path = resolved_state_dir(config) / "split.txt"
    resolver.table[("example.com", "A")] = (["203.0.113.5"], 3600)
    first = DomainResolverService(config, net=net).refresh()
    assert first.changed and first.next_interval_seconds == 3600
    before = (path.read_bytes(), path.stat().st_mtime_ns)

    resolver.table[("example.com", "A")] = failure
    # The watcher constructs a fresh service every cycle. Retention must use
    # the existing snapshot, not accidentally depend on an instance cache.
    second = DomainResolverService(config, net=net).refresh()
    assert second.resolved[0].ips == ["203.0.113.5"]
    assert not second.changed and second.next_interval_seconds == 30
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert net.wake_calls == 1

    resolver.table[("example.com", "A")] = (["203.0.113.9"], 3600)
    third = DomainResolverService(config, net=net).refresh()
    assert third.changed and third.resolved[0].ips == ["203.0.113.9"]
    assert third.next_interval_seconds == 3600
    assert path.read_text() == "203.0.113.9\n" and net.wake_calls == 2

    resolver.table[("example.com", "A")] = failure
    fourth = DomainResolverService(config, net=net).refresh()
    assert fourth.resolved[0].ips == ["203.0.113.9"]  # old success must not reappear
    assert fourth.next_interval_seconds == 30 and not fourth.changed


@pytest.mark.parametrize("negative", ["nxdomain", "noanswer", "empty-rrset"])
def test_authoritative_negatives_remove_previous_addresses(
    tmp_path: Path, resolver: ScriptedResolver, negative: str
) -> None:
    config = _config(tmp_path, _split("example.com"))
    resolver.table[("example.com", "A")] = (["203.0.113.5"], 600)
    resolver.table[("example.com", "AAAA")] = (["2001:db8::5"], 600)
    net = FakeNet()
    DomainResolverService(config, net=net).refresh()
    resolver.table[("example.com", "A")] = (
        dns.resolver.NXDOMAIN()
        if negative == "nxdomain"
        else dns.resolver.NoAnswer()
        if negative == "noanswer"
        else ([], None)
    )
    resolver.table[("example.com", "AAAA")] = (
        dns.exception.Timeout()
        if negative == "nxdomain"
        else dns.resolver.NoAnswer()
        if negative == "noanswer"
        else ([], None)
    )
    calls = len(resolver.calls)
    outcome = DomainResolverService(config, net=net).refresh()
    assert outcome.changed and outcome.resolved[0].ips == []
    assert (resolved_state_dir(config) / "split.txt").read_text() == ""
    assert outcome.next_interval_seconds == MAX_INTERVAL_SECONDS
    assert net.wake_calls == 2
    if negative == "nxdomain":
        assert resolver.calls[calls:] == [("example.com", "A")]  # name-wide, skip AAAA


def test_name_wide_nxdomain_overrides_an_earlier_family_timeout(
    tmp_path: Path, resolver: ScriptedResolver
) -> None:
    config = _config(tmp_path, _split("example.com"))
    resolver.table[("example.com", "A")] = (["203.0.113.5"], 600)
    DomainResolverService(config, net=FakeNet()).refresh()
    resolver.table[("example.com", "A")] = dns.exception.Timeout()
    resolver.table[("example.com", "AAAA")] = dns.resolver.NXDOMAIN()
    outcome = DomainResolverService(config, net=FakeNet()).refresh()
    assert outcome.resolved[0].ips == []
    assert outcome.next_interval_seconds == MAX_INTERVAL_SECONDS


def test_partial_failure_is_a_group_superset_but_never_restores_removed_groups(
    tmp_path: Path, resolver: ScriptedResolver
) -> None:
    config = _config(
        tmp_path,
        {
            **_split("changing.example", "flaky.example"),
            "sets": {
                "split": {"domains": ["changing.example", "flaky.example"]},
                "removed": {"domains": ["removed.example"]},
                "negative": {"domains": ["negative.example"]},
            },
        },
    )
    for index, domain in enumerate(
        ("changing.example", "flaky.example", "removed.example", "negative.example"), 1
    ):
        resolver.table[(domain, "A")] = ([f"203.0.113.{index}"], 600)
    net = FakeNet()
    DomainResolverService(config, net=net).refresh()
    updated = _config(
        tmp_path,
        {
            **_split("flaky.example", "new.example"),
            "sets": {
                "split": {"domains": ["flaky.example", "new.example"]},
                "negative": {"domains": ["negative.example"]},
            },
        },
    )
    resolver.table[("flaky.example", "A")] = dns.exception.Timeout()
    resolver.table[("new.example", "A")] = (["203.0.113.9"], 600)
    resolver.table[("negative.example", "A")] = dns.resolver.NXDOMAIN()
    outcome = DomainResolverService(updated, net=net).refresh()
    groups = {group.name: group.ips for group in outcome.resolved}
    assert groups == {"split": ["203.0.113.1", "203.0.113.2", "203.0.113.9"], "negative": []}
    assert outcome.next_interval_seconds == 30
    assert not (resolved_state_dir(config) / "removed.txt").exists()

    resolver.table[("flaky.example", "A")] = (["203.0.113.8"], 600)
    recovered = DomainResolverService(updated, net=net).refresh()
    assert recovered.resolved[0].ips == ["203.0.113.8", "203.0.113.9"]
    assert recovered.next_interval_seconds == 600
    calls = len(resolver.calls)
    empty = DomainResolverService(_config(tmp_path), net=net).refresh()
    assert empty.resolved == [] and empty.changed
    assert not list(resolved_state_dir(config).glob("*.txt"))
    assert len(resolver.calls) == calls


def test_initial_timeout_keeps_dns_empty_and_current_static_routes_available(
    tmp_path: Path, resolver: ScriptedResolver
) -> None:
    from kornode.net.compile import NodeFacts, dest_members
    from kornode.services.url_lists import UrlListCache

    config = _config(
        tmp_path,
        {
            **_split("example.com"),
            "sets": {
                "split": {
                    "domains": ["example.com"],
                    "routes": ["10.60.0.0/16"],
                    "route_urls": ["https://lists.example/routes.txt"],
                }
            },
        },
    )
    resolver.table[("example.com", "A")] = dns.exception.Timeout()
    resolver.table[("example.com", "AAAA")] = dns.resolver.NoNameservers("SERVFAIL")
    lists = UrlListCache(tmp_path / "url-cache", fetch=lambda url: "192.0.2.0/24\n")
    outcome = DomainResolverService(config, net=FakeNet(), url_lists=lists).refresh()
    assert outcome.resolved[0].ips == ["192.0.2.0/24"]
    assert outcome.next_interval_seconds == 30
    policy = config.egress_policy()
    facts = NodeFacts(
        node_id=1, client_pool=None, resolved={"split": frozenset(outcome.resolved[0].ips)}
    )
    members, _ = dest_members(policy.egress[0], 0, policy, facts)
    assert members == {"10.60.0.0/16", "192.0.2.0/24"}


def test_initial_transient_without_snapshot_stays_empty_and_retries_in_30_seconds(
    tmp_path: Path, resolver: ScriptedResolver
) -> None:
    config = _config(tmp_path, _split("example.com"))
    resolver.table[("example.com", "A")] = dns.exception.Timeout()
    resolver.table[("example.com", "AAAA")] = dns.exception.Timeout()
    net = FakeNet()
    first = DomainResolverService(config, net=net).refresh()
    second = DomainResolverService(config, net=net).refresh()
    assert first.resolved[0].ips == second.resolved[0].ips == []
    assert first.next_interval_seconds == second.next_interval_seconds == 30
    assert first.changed and not second.changed and net.wake_calls == 1
    assert (resolved_state_dir(config) / "split.txt").read_text() == ""


def test_no_configured_nameservers_is_transient_not_authoritative(tmp_path: Path) -> None:
    config = _config(tmp_path, {**_split("example.com"), "internal_dns": {"upstreams": []}})
    directory = resolved_state_dir(config)
    directory.mkdir(parents=True)
    (directory / "split.txt").write_text("203.0.113.5\n")
    outcome = DomainResolverService(config, net=FakeNet()).refresh()
    assert outcome.resolved[0].ips == ["203.0.113.5"]
    assert not outcome.changed and outcome.next_interval_seconds == 30


def test_transient_dns_dry_run_retains_snapshot_without_writes_or_wakes(
    tmp_path: Path, resolver: ScriptedResolver
) -> None:
    config = _config(tmp_path, _split("example.com"))
    resolver.table[("example.com", "A")] = (["203.0.113.5"], 600)
    net = FakeNet()
    service = DomainResolverService(config, net=net)
    service.refresh()
    path = resolved_state_dir(config) / "split.txt"
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    resolver.table[("example.com", "A")] = dns.exception.Timeout()
    outcome = service.refresh(dry_run=True)
    assert outcome.resolved[0].ips == ["203.0.113.5"] and outcome.next_interval_seconds == 30
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert net.wake_calls == 1
