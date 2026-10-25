from __future__ import annotations

from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig
from kornode.renderers.base import TemplateRenderer


class DnsmasqConfigRenderer(TemplateRenderer):
    def render(self, config: AppConfig) -> str:
        from kornode.services.internal_dns import InternalDnsService

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
        context: dict[str, Any] = {
            "config": config,
            "upstream_dns": upstream_dns,
            "forward_upstreams": forward_upstreams,
            "forward_domains": forward_domains,
            "forward_domain_names": set(forward_domains),
            "blocklist_conf": InternalDnsService(config).blocklist_conf_path(),
            "local_records": local_records,
            "interlink_zone": _interlink_zone(config),
        }
        return self.render_template("dnsmasq.conf.j2", context)

    def target_path(self, config: AppConfig) -> Path:
        return config.generated_path("dnsmasq.conf")


def _interlink_zone(config: AppConfig) -> dict[str, Any]:
    """The hub answers the whole interlink zone from local data (D-66)."""
    from kornode.services.interlink_dns import InterlinkDnsService, dnsmasq_lines

    return {
        "domain": config.interlink.domain,
        "lines": dnsmasq_lines(InterlinkDnsService(config).hub_records()),
    }
