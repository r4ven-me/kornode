"""URL-sourced set lists on the hub: the shared implementation lives in `kornode.net.lists`
(the agent uses it too); DomainResolverService is the only caller."""

from __future__ import annotations

from kornode.net.lists import (
    REFRESH_SECONDS,
    UrlListCache,
    fetch_url_text,
    normalize_domain,
    normalize_route,
    parse_list_text,
)

__all__ = [
    "REFRESH_SECONDS",
    "UrlListCache",
    "fetch_url_text",
    "normalize_domain",
    "normalize_route",
    "parse_list_text",
]
