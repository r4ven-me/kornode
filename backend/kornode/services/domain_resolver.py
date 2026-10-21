"""Pre-resolve the egress policy's domains for the reconciler.

Domain-based routing never depends on which resolver a VPN client or the
host actually uses for its own lookups (a client with its own DNS or DoH
bypasses dnsmasq entirely): this service resolves every domain of the
policy's destination sets itself, on its own schedule, and records the
addresses per set in `generated_dir/resolved/<set>.txt` (the set name is the
key of NodeFacts.resolved, D-25). The file is rewritten wholesale every
cycle, so a domain dropped from config also drops out on the next one.

It only changes that input and wakes the reconciler -- kernel state
(nft sets) is kornode.net's business alone.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import dns.exception
import dns.resolver

from kornode.config.models import AppConfig
from kornode.net.model import EgressPolicy, InlineDest
from kornode.services.files import FileManager
from kornode.services.net import NetService
from kornode.services.netinputs import resolved_state_dir

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
    # cycle, clamped to [MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS].
    next_interval_seconds: int


def domain_groups(config: AppConfig, policy: EgressPolicy | None = None) -> list[DomainGroup]:
    """Every destination with domains, resolved through the internal DNS upstreams: the
    policy's named sets (key = set name) and inline rule destinations (key `rule<N>`,
    the names NodeFacts.resolved is read by)."""
    policy = policy or config.egress_policy()
    upstreams = tuple(config.internal_dns.upstreams)
    groups = [
        DomainGroup(name, tuple(dest.domains), upstreams)
        for name, dest in policy.sets.items()
        if dest.domains
    ]
    groups += [
        DomainGroup(f"rule{index}", tuple(rule.to.domains), upstreams)
        for index, rule in enumerate(policy.egress)
        if isinstance(rule.to, InlineDest) and rule.to.domains
    ]
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
        files: FileManager | None = None,
        net: NetService | None = None,
    ) -> None:
        self.config = config
        self.lookup = lookup or DnsLookup()
        self.files = files or FileManager()
        self.net = net or NetService(config)

    def state_dir(self) -> Path:
        return resolved_state_dir(self.config)

    def refresh(self, *, dry_run: bool = False) -> RefreshOutcome:
        groups = domain_groups(self.config)
        resolved: list[ResolvedSet] = []
        min_ttl: int | None = None
        for group in groups:
            ips: list[str] = []
            for domain in group.domains:
                for rdtype in ("A", "AAAA"):
                    found, ttl = self.lookup.resolve(domain, group.nameservers, rdtype)
                    ips.extend(found)
                    if ttl is not None and (min_ttl is None or ttl < min_ttl):
                        min_ttl = ttl
            resolved.append(ResolvedSet(group.name, sorted(_dedup(ips))))

        directory = self.state_dir()
        previous = {
            path.stem: self.files.read_lines(path) for path in sorted(directory.glob("*.txt"))
        }
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
            resolved=resolved, changed=changed, next_interval_seconds=_clamp_interval(min_ttl)
        )
