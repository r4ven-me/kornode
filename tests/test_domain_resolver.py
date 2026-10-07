from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.domain_resolver import (
    MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    DnsLookup,
    DomainResolverService,
    domain_groups,
)


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


class RecordingRunner(CommandRunner):
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, extra_secrets
        self.calls.append(tuple(argv))
        return CommandResult(tuple(argv), 0, "", "", dry_run)


def test_domain_groups_includes_default_target_only_when_client_policy_is_split(
    tmp_path: Path,
) -> None:
    split = domain_groups(
        _config(
            tmp_path,
            {"routing": {"client_policy": "split", "split": {"domains": ["example.com"]}}},
        )
    )
    assert any(group.set_v4 == "split_v4_dynamic" for group in split)

    full = domain_groups(
        _config(
            tmp_path,
            {"routing": {"client_policy": "full", "split": {"domains": ["example.com"]}}},
        )
    )
    assert not any(group.set_v4 == "split_v4_dynamic" for group in full)


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
    matching = [g for g in groups if g.set_v4 == "split_v4_finance_dynamic"]
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
    host_group = next(g for g in groups if g.set_v4 == "host_v4_office_dynamic")
    assert set(host_group.domains) == {"own.example", "corp.example.com"}
    assert host_group.nameservers == ("172.16.0.53",)


def test_domain_groups_includes_global_host_split_only_when_host_policy_is_split(
    tmp_path: Path,
) -> None:
    split = domain_groups(
        _config(
            tmp_path,
            {"routing": {"host_policy": "split", "host_split": {"domains": ["intranet.example"]}}},
        )
    )
    assert any(
        g.set_v4 == "host_split_v4_dynamic" and g.domains == ("intranet.example",) for g in split
    )

    off = domain_groups(
        _config(
            tmp_path,
            {"routing": {"host_policy": "off", "host_split": {"domains": ["intranet.example"]}}},
        )
    )
    assert not any(g.set_v4 == "host_split_v4_dynamic" for g in off)


def test_refresh_is_a_noop_when_nothing_is_configured_to_resolve(tmp_path: Path) -> None:
    runner = RecordingRunner()
    outcome = DomainResolverService(_config(tmp_path), runner=runner).refresh()

    assert outcome.result is None
    assert outcome.resolved == []
    assert outcome.next_interval_seconds == MAX_INTERVAL_SECONDS
    assert runner.calls == []


def test_refresh_writes_flush_and_add_for_resolved_domains(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {"routing": {"client_policy": "split", "split": {"domains": ["example.com"]}}},
    )
    lookup = FakeLookup({"example.com": (["203.0.113.5", "203.0.113.6"], ["2001:db8::1"], 120)})
    runner = RecordingRunner()

    outcome = DomainResolverService(config, lookup=lookup, runner=runner).refresh()

    assert outcome.result is not None and outcome.result.ok
    assert outcome.next_interval_seconds == 120
    assert len(runner.calls) == 1
    assert runner.calls[0][:2] == ("nft", "-f")
    script_path = Path(runner.calls[0][2])
    content = script_path.read_text(encoding="utf-8")
    assert "flush set inet kornode_filter split_v4_dynamic" in content
    assert (
        "add element inet kornode_filter split_v4_dynamic { 203.0.113.5, 203.0.113.6 }" in content
    )
    assert "flush set inet kornode_filter split_v6_dynamic" in content
    assert "add element inet kornode_filter split_v6_dynamic { 2001:db8::1 }" in content


def test_refresh_flushes_with_nothing_to_add_when_domain_list_is_now_empty(tmp_path: Path) -> None:
    # A domain removed from config must drop out of its set on the next
    # cycle -- unlike the old dnsmasq nftset= approach, which only ever
    # added IPs and left stale ones behind forever.
    config = _config(tmp_path, {"routing": {"client_policy": "split", "split": {"domains": []}}})
    runner = RecordingRunner()

    outcome = DomainResolverService(config, lookup=FakeLookup({}), runner=runner).refresh()

    assert outcome.result is not None and outcome.result.ok
    content = Path(runner.calls[0][2]).read_text(encoding="utf-8")
    assert "flush set inet kornode_filter split_v4_dynamic" in content
    assert "add element" not in content


def test_refresh_interval_is_clamped_between_min_and_max(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
            "routing": {
                "client_policy": "split",
                "split": {"domains": ["short.example", "long.example"]},
            }
        },
    )
    lookup = FakeLookup(
        {
            "short.example": (["203.0.113.1"], [], 5),
            "long.example": (["203.0.113.2"], [], 999999),
        }
    )

    outcome = DomainResolverService(config, lookup=lookup, runner=RecordingRunner()).refresh()

    assert outcome.next_interval_seconds == MIN_INTERVAL_SECONDS


def test_refresh_dry_run_does_not_touch_the_runner_or_filesystem(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {"routing": {"client_policy": "split", "split": {"domains": ["example.com"]}}},
    )
    lookup = FakeLookup({"example.com": (["203.0.113.5"], [], 60)})
    runner = RecordingRunner()

    outcome = DomainResolverService(config, lookup=lookup, runner=runner).refresh(dry_run=True)

    assert outcome.result is not None and outcome.result.dry_run
    assert runner.calls == []
    assert not config.generated_path("nftables-dynamic-refresh.nft").exists()
