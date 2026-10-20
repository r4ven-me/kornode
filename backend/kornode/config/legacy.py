"""v1 routing keys -> v2 EgressPolicy (docs/spec/10-migration.md).

Pure translation: the caller supplies the already-merged lists (inline
config + runtime files + URL caches + server-pushed routes) through
`LegacyLists`, so this module never touches files or the network. v1's
"default first, named profile overrides win" (last mark wins) becomes
first-match by putting every named-profile rule BEFORE the default rules.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from kornode.config.models import AppConfig, UpstreamProfileConfig, profile_safe_name
from kornode.net.errors import PolicyError
from kornode.net.model import EgressPolicy

_MAX_SLUG = 22  # "upstream:" + slug and "p_<slug>_host" stay within 31 chars


class LegacyLists(Protocol):
    def split_routes(self) -> list[str]: ...

    def split_domains(self) -> list[str]: ...

    def host_split_routes(self) -> list[str]: ...

    def host_split_domains(self) -> list[str]: ...

    def profile_routes(self, profile: UpstreamProfileConfig) -> list[str]: ...

    def profile_domains(self, profile: UpstreamProfileConfig) -> list[str]: ...

    def profile_host_routes(self, profile: UpstreamProfileConfig) -> list[str]: ...

    def profile_host_domains(self, profile: UpstreamProfileConfig) -> list[str]: ...


def profile_slug(name: str) -> str:
    """Exit/set-safe identifier for a v1 profile name (v1 allows names v2's
    `[a-z][a-z0-9_-]{0,30}` doesn't, e.g. a leading digit)."""
    slug = profile_safe_name(name)
    if not re.match(r"[a-z]", slug):
        slug = f"p{slug}"
    return slug[:_MAX_SLUG]


def upstream_exit(profile: UpstreamProfileConfig) -> str:
    return f"upstream:{profile_slug(profile.name)}"


_UNSET: Any = object()


def legacy_policy(
    config: AppConfig,
    lists: LegacyLists,
    active_profile: UpstreamProfileConfig | None = _UNSET,
) -> EgressPolicy:
    """`active_profile` is the runtime-switched active profile (the
    `active-upstream` marker; None = nothing active). Left out, the config's
    own selection is used."""
    routing = config.routing
    upstream = config.upstream
    profiles = list(upstream.profiles)
    slugs = [profile_slug(profile.name) for profile in profiles]
    if len(slugs) != len(set(slugs)):
        raise PolicyError(f"upstream profile names collide after normalisation: {slugs}")

    sets: dict[str, dict[str, Any]] = {}
    egress: list[dict[str, Any]] = []
    if active_profile is _UNSET:
        active_profile = upstream.selected_profile()
    active = active_profile if upstream.enabled else None

    def add_set(name: str, routes: list[str], domains: list[str]) -> bool:
        if not routes and not domains:
            return False
        sets[name] = {"routes": routes, "domains": domains}
        return True

    # Named per-profile targets only exist with upstream enabled (v1
    # invariant), and win over the defaults: they come first.
    if upstream.enabled:
        for profile, slug in zip(profiles, slugs, strict=True):
            via = f"upstream:{slug}"
            if profile.route_clients_enabled and add_set(
                f"p_{slug}", lists.profile_routes(profile), lists.profile_domains(profile)
            ):
                egress.append(
                    {
                        "id": f"p-{slug}"[:31],
                        "from": ["clients"],
                        "to": {"set": f"p_{slug}"},
                        "via": via,
                    }
                )
            if profile.route_host_enabled and add_set(
                f"p_{slug}_host",
                lists.profile_host_routes(profile),
                lists.profile_host_domains(profile),
            ):
                egress.append(
                    {
                        "id": f"p-{slug}-host"[:31],
                        "from": ["host"],
                        "to": {"set": f"p_{slug}_host"},
                        "via": via,
                    }
                )

    if active is None:
        # No usable upstream: clients just get plain NAT, the host is untouched.
        egress.append({"id": "clients-local", "from": ["clients"], "to": "any", "via": "local"})
    else:
        via = upstream_exit(active)
        if routing.client_policy == "full":
            egress.append({"id": "clients-full", "from": ["clients"], "to": "any", "via": via})
        elif routing.client_policy == "split":
            if add_set("split", lists.split_routes(), lists.split_domains()):
                egress.append(
                    {"id": "clients-split", "from": ["clients"], "to": {"set": "split"}, "via": via}
                )
            egress.append({"id": "clients-local", "from": ["clients"], "to": "any", "via": "local"})
        else:
            egress.append({"id": "clients-local", "from": ["clients"], "to": "any", "via": "local"})
        if routing.host_policy == "full":
            egress.append({"id": "host-full", "from": ["host"], "to": "any", "via": via})
        elif routing.host_policy == "split" and add_set(
            "host_split", lists.host_split_routes(), lists.host_split_domains()
        ):
            egress.append(
                {"id": "host-split", "from": ["host"], "to": {"set": "host_split"}, "via": via}
            )

    try:
        return EgressPolicy.model_validate({"sets": sets, "egress": egress})
    except ValueError as exc:
        raise PolicyError(
            f"v1 routing config does not translate to an egress policy: {exc}"
        ) from exc


class InlineLists:
    """LegacyLists from the config's inline lists only (no runtime files,
    URL caches or pushed routes): deterministic, used by golden tests and
    as a fallback when nothing else is available."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def split_routes(self) -> list[str]:
        return list(self.config.routing.split.routes)

    def split_domains(self) -> list[str]:
        return list(self.config.routing.split.domains)

    def host_split_routes(self) -> list[str]:
        return list(self.config.routing.host_split.routes)

    def host_split_domains(self) -> list[str]:
        return list(self.config.routing.host_split.domains)

    def profile_routes(self, profile: UpstreamProfileConfig) -> list[str]:
        return list(profile.routes)

    def profile_domains(self, profile: UpstreamProfileConfig) -> list[str]:
        return list(profile.domains)

    def profile_host_routes(self, profile: UpstreamProfileConfig) -> list[str]:
        return list(profile.host_routes)

    def profile_host_domains(self, profile: UpstreamProfileConfig) -> list[str]:
        return list(profile.host_domains)
