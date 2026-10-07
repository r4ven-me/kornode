"""Pre-resolve configured domains into nftables *_dynamic sets.

Before this module, domain-based routing worked by piggybacking on dnsmasq's
`nftset=` directive (templates/dnsmasq.conf.j2): a *_dynamic set only ever
got an IP the moment dnsmasq itself answered a live query for that domain.
That tied correct routing to which resolver a VPN client or the host
actually used -- a client using its own DNS (or DoH, bypassing dnsmasq
entirely) never populated the set at all, and a domain removed from config
left its old IPs in the set forever (dnsmasq's directive only ever adds).

This service resolves the same domain lists itself, on its own schedule,
independent of any client/host query, and replaces (flush + add, never just
add) each *_dynamic set's contents every cycle -- so a domain dropped from
config also drops out of the set on the next cycle. dnsmasq.conf.j2 no
longer has any nftset= directives.

RUNTIME: writes live nftables set state via `nft -f`. See
NftablesService.apply()'s docstring for why *_dynamic sets are never
touched by a routes/domains-only config refresh -- this is the one thing
that is allowed to touch them, and only them.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import dns.exception
import dns.resolver

from kornode.config.models import AppConfig
from kornode.renderers.nftables import NftablesConfigRenderer
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.files import FileManager
from kornode.services.routing import RoutingService

_LOGGER = logging.getLogger(__name__)

# Deliberately not configurable: this whole module exists to cut down on
# knobs, not add new ones. A cycle costs one or two DNS queries per
# configured domain, so even the floor is cheap.
MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 3600
LOOKUP_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class DomainGroup:
    """One nftables *_dynamic set pair's worth of domains to resolve, and
    which nameservers to resolve them through. domains may be empty -- the
    group is still included so its set gets flushed with nothing to add,
    clearing out whatever an earlier cycle left there."""

    set_v4: str
    set_v6: str
    domains: tuple[str, ...]
    nameservers: tuple[str, ...]


@dataclass
class ResolvedSet:
    set_v4: str
    set_v6: str
    ips_v4: list[str] = field(default_factory=list)
    ips_v6: list[str] = field(default_factory=list)


@dataclass
class RefreshOutcome:
    result: CommandResult | None
    resolved: list[ResolvedSet]
    # How long to wait before the next cycle -- the lowest TTL seen this
    # cycle, clamped to [MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS].
    next_interval_seconds: int


def domain_groups(config: AppConfig) -> list[DomainGroup]:
    """The same domain/nameserver choices dnsmasq.conf.j2's nftset=
    directives used to encode, minus the two that only ever existed to
    answer the client's *own* query a particular way (the default target's
    split domains, and a named target's plain -- non-server-pushed -- host
    domains): those always used the normal upstream DNS already, so
    removing their nftset= directive changes nothing about how they
    resolve for a client, only who populates the nftables set.
    """
    renderer = NftablesConfigRenderer()
    targets, _, _ = renderer.resolve_targets(config)
    upstreams = tuple(config.internal_dns.upstreams)
    groups: list[DomainGroup] = []
    for target in targets:
        if target.name == "default":
            if config.routing.client_policy == "split":
                groups.append(
                    DomainGroup(
                        target.set_v4_dynamic,
                        target.set_v6_dynamic,
                        tuple(target.domains),
                        upstreams,
                    )
                )
            continue
        groups.append(
            DomainGroup(
                target.set_v4_dynamic, target.set_v6_dynamic, tuple(target.domains), upstreams
            )
        )
        if target.host_set_v4_dynamic is not None and target.host_set_v6_dynamic is not None:
            # Simplification: if the profile has its own DNS (pushed by the
            # upstream, see UpstreamProfileConfig.accept_server_routes),
            # resolve ALL of this target's host domains through it, not
            # just the server-pushed subset -- dnsmasq used to split that
            # hair because it needed the subset for a `server=/domain/...`
            # answer override too; that distinction has no equivalent need
            # here, resolving is resolving.
            nameservers = tuple(target.server_dns) if target.server_dns else upstreams
            groups.append(
                DomainGroup(
                    target.host_set_v4_dynamic,
                    target.host_set_v6_dynamic,
                    tuple(target.host_domains),
                    nameservers,
                )
            )
    if config.routing.host_policy == "split":
        host_domains = tuple(RoutingService(config).list_host_domains())
        groups.append(
            DomainGroup(
                "host_split_v4_dynamic", "host_split_v6_dynamic", host_domains, upstreams
            )
        )
    return groups


class DnsLookup:
    """Thin wrapper around dnspython so tests can substitute a fake
    without touching the network."""

    def __init__(self, timeout: float = LOOKUP_TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def resolve(
        self, domain: str, nameservers: Sequence[str], rdtype: str
    ) -> tuple[list[str], int | None]:
        if not nameservers:
            return [], None
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(nameservers)
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        try:
            answer = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
        except dns.exception.DNSException as exc:
            _LOGGER.warning(
                "domain resolve: %s %s via %s failed: %s", domain, rdtype, nameservers, exc
            )
            return [], None
        if answer.rrset is None:
            return [], None
        return [str(rdata) for rdata in answer], answer.rrset.ttl


def _dedup(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _clamp_interval(min_ttl: int | None) -> int:
    if min_ttl is None:
        return MAX_INTERVAL_SECONDS
    return max(MIN_INTERVAL_SECONDS, min(min_ttl, MAX_INTERVAL_SECONDS))


class DomainResolverService:
    def __init__(
        self,
        config: AppConfig,
        *,
        lookup: DnsLookup | None = None,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
    ) -> None:
        self.config = config
        self.lookup = lookup or DnsLookup()
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.renderer = NftablesConfigRenderer()

    @property
    def filter_table(self) -> str:
        return f"{self.config.routing.nft_prefix}_filter"

    def target_path(self) -> Path:
        return self.config.generated_path("nftables-dynamic-refresh.nft")

    def refresh(self, *, dry_run: bool = False) -> RefreshOutcome:
        groups = domain_groups(self.config)
        if not groups:
            return RefreshOutcome(
                result=None, resolved=[], next_interval_seconds=MAX_INTERVAL_SECONDS
            )

        # Only ever touch a *_dynamic set the current config/nftables schema
        # actually expects -- defensive, since domain_groups() is derived
        # from the same targets expected_set_names() uses, but an nft apply
        # may not have run yet (first boot) and a stale/missing set must
        # not turn into a confusing nft error every cycle.
        expected = self.renderer.expected_set_names(self.config)

        resolved: list[ResolvedSet] = []
        min_ttl: int | None = None
        for group in groups:
            if group.set_v4 not in expected and group.set_v6 not in expected:
                continue
            ips_v4: list[str] = []
            ips_v6: list[str] = []
            for domain in group.domains:
                v4, ttl4 = self.lookup.resolve(domain, group.nameservers, "A")
                v6, ttl6 = self.lookup.resolve(domain, group.nameservers, "AAAA")
                ips_v4.extend(v4)
                ips_v6.extend(v6)
                for ttl in (ttl4, ttl6):
                    if ttl is not None and (min_ttl is None or ttl < min_ttl):
                        min_ttl = ttl
            resolved.append(ResolvedSet(group.set_v4, group.set_v6, _dedup(ips_v4), _dedup(ips_v6)))

        interval = _clamp_interval(min_ttl)
        if not resolved:
            return RefreshOutcome(result=None, resolved=[], next_interval_seconds=interval)

        content = self.renderer.render_dynamic_refresh(resolved, self.filter_table)
        if dry_run:
            return RefreshOutcome(
                result=CommandResult(("nft", "-f", str(self.target_path())), 0, content, "", True),
                resolved=resolved,
                next_interval_seconds=interval,
            )
        self.files.atomic_write_text(self.target_path(), content)
        result = self.runner.run(["nft", "-f", str(self.target_path())], timeout=30, check=False)
        return RefreshOutcome(result=result, resolved=resolved, next_interval_seconds=interval)
