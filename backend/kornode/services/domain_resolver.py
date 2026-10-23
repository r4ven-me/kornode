"""Pre-resolve the egress policy's domains for the reconciler.

Domain-based routing never depends on which resolver a VPN client or the
host actually uses for its own lookups (a client with its own DNS or DoH
bypasses dnsmasq entirely): this service resolves every domain of the
policy's destination sets itself, on its own schedule, and records the
addresses per set in `generated_dir/resolved/<set>.txt` (the set name is the
key of NodeFacts.resolved, D-25). Completed lookups replace a group's snapshot;
transient DNS failures retain its previous addresses until a completed cycle.
Removed groups are never retained. Partial failures conservatively retain the
whole group's old snapshot because the files carry no per-domain provenance.

It only changes that input and wakes the reconciler -- kernel state
(nft sets) is kornode.net's business alone.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import dns.exception
import dns.resolver

from kornode.config.models import AppConfig
from kornode.net.model import EgressPolicy, InlineDest
from kornode.services.files import FileManager
from kornode.services.net import NetService
from kornode.services.netinputs import resolved_state_dir
from kornode.services.url_lists import UrlListCache, normalize_domain, normalize_route

_LOGGER = logging.getLogger(__name__)

# Deliberately not configurable: this whole module exists to cut down on
# knobs, not add new ones. A cycle costs one or two DNS queries per
# configured domain, so even the floor is cheap.
MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 3600
LOOKUP_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class DomainGroup:
    """One destination set's domains to resolve (`name` is the set's name in
    the policy) and which nameservers to resolve them through."""

    name: str
    domains: tuple[str, ...]
    nameservers: tuple[str, ...]


@dataclass
class ResolvedSet:
    name: str
    ips: list[str] = field(default_factory=list)


@dataclass
class RefreshOutcome:
    resolved: list[ResolvedSet]
    # Whether any set's addresses differ from what was recorded before.
    changed: bool
    # How long to wait before the next cycle -- the lowest TTL seen this
    # cycle, clamped to [MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS]; a
    # transient DNS failure always requests MIN_INTERVAL_SECONDS.
    next_interval_seconds: int


def domain_groups(
    config: AppConfig,
    policy: EgressPolicy | None = None,
    url_domains: Mapping[str, Sequence[str]] | None = None,
) -> list[DomainGroup]:
    """Every destination with domains, resolved through the internal DNS upstreams: the
    policy's named sets (key = set name; `url_domains` are the domains downloaded from
    its `domain_urls`) and inline rule destinations (key `rule<N>`, the names
    NodeFacts.resolved is read by)."""
    url_domains = url_domains or {}
    policy = policy or config.egress_policy()
    upstreams = tuple(config.internal_dns.upstreams)
    groups = [
        DomainGroup(
            name, tuple(dict.fromkeys([*dest.domains, *url_domains.get(name, ())])), upstreams
        )
        for name, dest in policy.sets.items()
        if dest.domains or url_domains.get(name)
    ]
    groups += [
        DomainGroup(f"rule{index}", tuple(rule.to.domains), upstreams)
        for index, rule in enumerate(policy.egress)
        if isinstance(rule.to, InlineDest) and rule.to.domains
    ]
    return groups


class DnsLookup:
    """Thin wrapper around dnspython so tests can substitute a fake.

    DNS exceptions remain typed: refresh distinguishes authoritative negatives
    from transient failures instead of mistaking an outage for an empty answer.
    """

    def __init__(self, timeout: float = LOOKUP_TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def resolve(
        self, domain: str, nameservers: Sequence[str], rdtype: str
    ) -> tuple[list[str], int | None]:
        if not nameservers:
            # dnspython does not annotate its exception constructors.
            raise dns.resolver.NoResolverConfiguration()  # type: ignore[no-untyped-call]
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(nameservers)
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        answer = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
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
        files: FileManager | None = None,
        net: NetService | None = None,
        url_lists: UrlListCache | None = None,
    ) -> None:
        self.config = config
        self.lookup = lookup or DnsLookup()
        self.files = files or FileManager()
        self.net = net or NetService(config)
        self.url_lists = url_lists or UrlListCache(config.system.generated_dir / "url-lists")

    def state_dir(self) -> Path:
        return resolved_state_dir(self.config)

    def refresh(self, *, dry_run: bool = False) -> RefreshOutcome:
        policy = self.config.egress_policy()
        directory = self.state_dir()
        previous = {
            path.stem: self.files.read_lines(path) for path in sorted(directory.glob("*.txt"))
        }
        url_domains: dict[str, list[str]] = {}
        url_routes: dict[str, list[str]] = {}
        for name, dest in policy.sets.items():
            domains = [
                item
                for url in dest.domain_urls
                for item in self.url_lists.items(url, normalize_domain, dry_run=dry_run)
            ]
            routes = [
                item
                for url in dest.route_urls
                for item in self.url_lists.items(url, normalize_route, dry_run=dry_run)
            ]
            if domains:
                url_domains[name] = domains
            if dest.route_urls:
                url_routes[name] = routes
        groups = domain_groups(self.config, policy, url_domains)
        resolved: list[ResolvedSet] = []
        min_ttl: int | None = None
        transient_failure = False
        for group in groups:
            ips: list[str] = []
            group_failed = False
            for domain in group.domains:
                domain_ips: list[str] = []
                domain_failed = False
                for rdtype in ("A", "AAAA"):
                    try:
                        found, ttl = self.lookup.resolve(domain, group.nameservers, rdtype)
                    except dns.resolver.NXDOMAIN:
                        # NXDOMAIN is name-wide, unlike an empty answer for one
                        # family. Do not let another-family outage mask it.
                        domain_ips = []
                        domain_failed = False
                        break
                    except dns.resolver.NoAnswer:
                        continue
                    except dns.exception.DNSException as exc:
                        domain_failed = True
                        _LOGGER.warning(
                            "domain resolve: %s %s via %s temporarily failed: %s",
                            domain,
                            rdtype,
                            group.nameservers,
                            exc,
                        )
                        continue
                    domain_ips.extend(found)
                    if ttl is not None and (min_ttl is None or ttl < min_ttl):
                        min_ttl = ttl
                ips.extend(domain_ips)
                group_failed |= domain_failed
            if group_failed:
                transient_failure = True
                # Reuse only a still-configured group's snapshot. Rebuilding
                # after a completed cycle removes this conservative superset.
                ips.extend(line for line in previous.get(group.name, []) if line)
            ips.extend(url_routes.pop(group.name, []))
            resolved.append(ResolvedSet(group.name, sorted(_dedup(ips))))
        resolved += [ResolvedSet(name, sorted(_dedup(items))) for name, items in url_routes.items()]

        current = {item.name: item.ips for item in resolved}
        changed = {
            name: [line for line in lines if line] for name, lines in previous.items()
        } != current
        if changed and not dry_run:
            self.files.ensure_dir(directory)
            for name, ips in current.items():
                self.files.atomic_write_text(
                    directory / f"{name}.txt", "".join(f"{ip}\n" for ip in ips)
                )
            for name in previous.keys() - current.keys():
                (directory / f"{name}.txt").unlink(missing_ok=True)
            self.net.wake()
        return RefreshOutcome(
            resolved=resolved,
            changed=changed,
            next_interval_seconds=(
                MIN_INTERVAL_SECONDS if transient_failure else _clamp_interval(min_ttl)
            ),
        )
