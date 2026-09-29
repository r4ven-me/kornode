from __future__ import annotations

from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig
from kornode.renderers.base import TemplateRenderer


class DnsmasqConfigRenderer(TemplateRenderer):
    def render(self, config: AppConfig) -> str:
        from kornode.services.internal_dns import InternalDnsService
        from kornode.services.routing import RoutingService

        # Gated on client_traffic too: with it off, the default target never
        # marks client traffic through Upstream at all (see nftables.nft.j2),
        # so resolving domains into its set / overriding their DNS server
        # would just be a silent, pointless DNS behavior change.
        split_dns_active = (
            config.routing.client_traffic
            and config.routing.mode == "split"
            and config.routing.split.tunnel_dns
        )
        # server.dns doubles as "DNS pushed to clients" and "dnsmasq upstreams";
        # when tunnel_dns is on, configs often list the dnsmasq address itself
        # there (that IS the client DNS). dnsmasq silently ignores upstreams on
        # a local interface, which would leave split-domain masks pointing at a
        # dropped server — so keep only real upstreams.
        listen = config.internal_dns.listen
        upstream_dns = [dns for dns in config.server.dns if dns != listen]
        local_records = (
            [
                {"host": host, "ip": ip}
                for host, ip in (record.split() for record in config.internal_dns.local_records)
            ]
            if config.internal_dns.local_records_enabled
            else []
        )
        forward_upstreams = config.internal_dns.forward_upstreams
        forward_domains = config.internal_dns.forward_domains
        routing_service = RoutingService(config)
        # Named per-profile targets: resolved via the normal upstream DNS
        # (no server=/domain/... override, unlike split_dns_active below --
        # that override is specifically for routing.split's own tunnel_dns
        # toggle), just fed into that target's own nftables set so matching
        # traffic gets marked and routed to its assigned profile.
        targets = routing_service.list_targets(default_interface=config.routing.main_interface)
        named_targets_with_domains = [
            target for target in targets if target.name != "default" and target.domains
        ]
        # Per-profile HOST domains (UpstreamProfileConfig.host_domains):
        # same idea, fed into that target's own dedicated host_set_v4/v6
        # instead of its client set_v4/v6. The server-pushed part of them
        # (accept_server_routes, target.server_domains) additionally
        # resolves through the upstream's own DNS: split-DNS domains are
        # usually internal names nothing else can answer.
        named_targets_with_host_domains = [
            target for target in targets if target.host_enabled and target.host_domains
        ]
        # The HOST's own split-mode domains (routing.host_split.domains) --
        # a separate list from routing.split's, fed into its own dedicated
        # host_split_v4/v6 set (see nftables.nft.j2), not split_v4/v6.
        host_split_active = config.routing.host_traffic and config.routing.host_mode == "split"
        context: dict[str, Any] = {
            "config": config,
            "upstream_dns": upstream_dns,
            "filter_table": f"{config.routing.nft_prefix}_filter",
            # dnsmasq's nftset= only ever ADDS resolved IPs -- it must target
            # the *_dynamic set (see nftables.nft.j2), never the *_static one
            # a normal apply flushes and rebuilds from config.
            "split_v4_set": "split_v4_dynamic",
            "split_v6_set": "split_v6_dynamic",
            "split_dns_active": split_dns_active,
            "split_domains": routing_service.list_domains() if split_dns_active else [],
            "forward_upstreams": forward_upstreams,
            "forward_domains": forward_domains,
            "forward_domain_names": set(forward_domains),
            "named_targets_with_domains": named_targets_with_domains,
            "named_targets_with_host_domains": named_targets_with_host_domains,
            "host_split_domains": (
                routing_service.list_host_domains() if host_split_active else []
            ),
            "blocklist_conf": InternalDnsService(config).blocklist_conf_path(),
            "local_records": local_records,
        }
        return self.render_template("dnsmasq.conf.j2", context)

    def target_path(self, config: AppConfig) -> Path:
        return config.generated_path("dnsmasq.conf")
