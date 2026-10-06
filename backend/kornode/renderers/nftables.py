from __future__ import annotations

from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig
from kornode.renderers.base import TemplateRenderer
from kornode.services.routing import RoutingTarget


class NftablesConfigRenderer(TemplateRenderer):
    def resolve_targets(
        self, config: AppConfig, outbound_interface: str | None = None
    ) -> tuple[list[RoutingTarget], str, bool]:
        """The default target (whichever profile is active, governed by
        routing.client_policy) plus one target per profile with its own explicit
        routes/domains -- each gets its own fwmark/table/set so several
        profiles can carry different traffic simultaneously. See
        RoutingService.list_targets().

        Also returns the resolved outbound_interface and upstream_active
        flag so render() doesn't need to recompute them, and so callers that
        only need the target list (e.g. NftablesService's stale-target
        cleanup) can get exactly what render() would use without
        duplicating this resolution logic.
        """
        from kornode.services.routing import RoutingService

        selected_profile = config.upstream.selected_profile()
        upstream_active = config.upstream.enabled and selected_profile is not None
        if outbound_interface is None:
            if upstream_active and selected_profile is not None:
                outbound_interface = config.upstream.profile_interface(selected_profile)
            else:
                outbound_interface = config.routing.main_interface

        targets = RoutingService(config).list_targets(default_interface=outbound_interface)
        return targets, outbound_interface, upstream_active

    def render(self, config: AppConfig, outbound_interface: str | None = None) -> str:
        from kornode.services.routing import RoutingService

        targets, outbound_interface, upstream_active = self.resolve_targets(
            config, outbound_interface
        )
        host_split_active = config.routing.host_policy == "split"
        routing_service = RoutingService(config)

        context: dict[str, Any] = {
            "config": config,
            "filter_table": f"{config.routing.nft_prefix}_filter",
            "nat_table": f"{config.routing.nft_prefix}_nat",
            "targets": targets,
            "outbound_interface": outbound_interface,
            # Only marked traffic (full: all client traffic; split: the
            # configured routes/ips/domains) must be forced through the
            # upstream tunnel -- everything else keeps using the host's
            # normal route/masquerade. Meaningless without an actual
            # upstream interface to police, so it's off entirely otherwise.
            # Host traffic (below) only ever follows the default target.
            "upstream_killswitch": upstream_active,
            # Whether the default target's own client-facing marking rule
            # (client_policy: full/split) is rendered at all -- "off" leaves
            # clients on plain host NAT (relying only on explicit per-profile
            # targeting) even though the default target's set stays
            # populated (used by its own killswitch/masquerade context).
            "client_traffic_enabled": config.routing.client_policy != "off",
            # Independent of client_policy: host_policy picks full/split for
            # the HOST's own traffic on its own terms, off its own separate
            # routing.host_split routes/domains -- NOT shared with the
            # client-facing default target's set.
            "host_traffic_enabled": config.routing.host_policy != "off",
            "host_mode": config.routing.host_policy,
            "host_split_routes": routing_service.list_host_routes() if host_split_active else [],
            "host_split_domains": (
                routing_service.list_host_domains() if host_split_active else []
            ),
        }
        return self.render_template("nftables.nft.j2", context)

    def render_static_refresh(
        self, config: AppConfig, outbound_interface: str | None = None
    ) -> str:
        """flush+add script for every target's/host-split's *_static sets --
        never touches any *_dynamic set. See NftablesService.apply() for when
        this is used instead of the full table definition from render().
        """
        from kornode.services.routing import RoutingService

        targets, _, _ = self.resolve_targets(config, outbound_interface)
        host_split_active = config.routing.host_policy == "split"
        context: dict[str, Any] = {
            "filter_table": f"{config.routing.nft_prefix}_filter",
            "targets": targets,
            "host_split_active": host_split_active,
            "host_split_routes": (
                RoutingService(config).list_host_routes() if host_split_active else []
            ),
        }
        return self.render_template("nftables-static-refresh.nft.j2", context)

    def expected_set_names(
        self, config: AppConfig, outbound_interface: str | None = None
    ) -> frozenset[str]:
        """Every *_static/*_dynamic set name the current config should
        produce. NftablesService compares this against what the live table
        actually has to decide whether a surgical static-only refresh is
        safe (the schema already matches) or a full recreate is required
        (first apply, or the target list/host-routing toggles changed since
        the last apply).
        """
        targets, _, _ = self.resolve_targets(config, outbound_interface)
        host_split_active = config.routing.host_policy == "split"
        names: set[str] = set()
        for target in targets:
            names.update(
                {
                    target.set_v4_static,
                    target.set_v4_dynamic,
                    target.set_v6_static,
                    target.set_v6_dynamic,
                }
            )
            for host_set_name in (
                target.host_set_v4_static,
                target.host_set_v4_dynamic,
                target.host_set_v6_static,
                target.host_set_v6_dynamic,
            ):
                if host_set_name is not None:
                    names.add(host_set_name)
        if host_split_active:
            names.update(
                {
                    "host_split_v4_static",
                    "host_split_v4_dynamic",
                    "host_split_v6_static",
                    "host_split_v6_dynamic",
                }
            )
        return frozenset(names)

    def target_path(self, config: AppConfig) -> Path:
        return config.generated_path("nftables.nft")

    def static_refresh_path(self, config: AppConfig) -> Path:
        return config.generated_path("nftables-static-refresh.nft")
