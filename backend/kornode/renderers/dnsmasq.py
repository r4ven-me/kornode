from __future__ import annotations

from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig
from kornode.renderers.base import TemplateRenderer


class DnsmasqConfigRenderer(TemplateRenderer):
    def render(self, config: AppConfig) -> str:
        from kornode.services.internal_dns import InternalDnsService
        from kornode.services.routing import RoutingService

        listen = config.internal_dns.listen
        # internal_dns.upstreams is what the resolver itself forwards
        # unmatched queries to -- independent of server.dns, which has its
        # own separate job (DNS pushed straight to VPN clients when the
        # resolver isn't in play, see client_dns_servers()). dnsmasq
        # silently ignores an upstream on a local interface, so keep only
        # real upstreams if the admin also listed the resolver itself here.
        upstream_dns = [dns for dns in config.internal_dns.upstreams if dns != listen]
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
        # Named per-profile targets' server-pushed domains
        # (UpstreamProfileConfig.accept_server_routes, target.server_domains):
        # these are usually internal-only names nothing but the upstream's
        # own DNS can answer, so they still need a `server=/domain/...`
        # override here -- unlike every other domain list (routing.split's,
        # a profile's own plain domains/host_domains, routing.host_split's),
        # which all resolve through the normal upstream DNS already and
        # need nothing special from dnsmasq. DomainResolverService
        # (services/domain_resolver.py) is what feeds all of those into
        # their nftables *_dynamic sets now, independent of any query
        # dnsmasq itself ever answers.
        targets = routing_service.list_targets(default_interface=config.routing.main_interface)
        named_targets_with_server_domains = [
            target for target in targets if target.host_enabled and target.server_domains
        ]
        context: dict[str, Any] = {
            "config": config,
            "upstream_dns": upstream_dns,
            "forward_upstreams": forward_upstreams,
            "forward_domains": forward_domains,
            "forward_domain_names": set(forward_domains),
            "named_targets_with_server_domains": named_targets_with_server_domains,
            "blocklist_conf": InternalDnsService(config).blocklist_conf_path(),
            "local_records": local_records,
        }
        return self.render_template("dnsmasq.conf.j2", context)

    def target_path(self, config: AppConfig) -> Path:
        return config.generated_path("dnsmasq.conf")
