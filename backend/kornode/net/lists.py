"""URL-sourced set members: download, parse, cache (shared by the hub and the agent).

Stdlib only -- the agent imports this module. A failed download keeps the last
cached copy (a set never silently empties because a list host is down); a list
without a single valid entry is refused rather than applied.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from kornode.net.model import EgressPolicy, InlineDest

_LOGGER = logging.getLogger(__name__)

MAX_LIST_BYTES = 10 * 1024 * 1024
MAX_LIST_ENTRIES = 500_000
FETCH_TIMEOUT_SECONDS = 30
# A resolver cycle can be as short as 30 s; the lists themselves are re-downloaded hourly.
REFRESH_SECONDS = 3600
USER_AGENT = "kornode-url-lists"

_HOSTNAME_RE = re.compile(r"^(\*\.)?([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

Fetcher = Callable[[str], str]


def url_slug(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def fetch_url_text(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be a valid HTTP(S) URL")
    request = urllib.request.Request(  # noqa: S310 - scheme validated above
        url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain, */*"}
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - scheme validated above
            request, timeout=FETCH_TIMEOUT_SECONDS
        ) as response:
            payload: bytes = response.read(MAX_LIST_BYTES + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ValueError(f"failed to download list: {exc}") from exc
    if len(payload) > MAX_LIST_BYTES:
        raise ValueError(f"download exceeds the safety limit of {MAX_LIST_BYTES} bytes")
    return payload.decode("utf-8", errors="replace")


def normalize_route(value: str) -> str:
    return str(ipaddress.ip_network(value, strict=False))


def normalize_domain(value: str) -> str:
    if not _HOSTNAME_RE.match(value):
        raise ValueError(f"invalid domain {value!r}")
    return value.lower()


def parse_list_text(text: str, normalize: Callable[[str], str]) -> list[str]:
    """One entry per line; blank lines and `#`/`!`/`;` comments are skipped, a trailing
    `# comment` is stripped, and a line that fails `normalize` is dropped without
    invalidating the rest (public lists routinely contain a few malformed lines)."""
    items: dict[str, None] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        try:
            items[normalize(fields[0])] = None
        except ValueError:
            continue
        if len(items) > MAX_LIST_ENTRIES:
            raise ValueError(f"list exceeds the safety limit of {MAX_LIST_ENTRIES} entries")
    return list(items)


def atomic_write_lines(path: Path, lines: list[str]) -> None:
    """Write `lines` (one per line) so a reader never sees a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write("".join(f"{line}\n" for line in lines))
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


class UrlListCache:
    def __init__(self, cache_dir: Path, fetch: Fetcher = fetch_url_text) -> None:
        self.cache_dir = cache_dir
        self.fetch = fetch

    def _path(self, url: str) -> Path:
        return self.cache_dir / f"{url_slug(url)}.txt"

    def items(
        self, url: str, normalize: Callable[[str], str], *, dry_run: bool = False
    ) -> list[str]:
        """Entries of the list at `url`: the cache while it is fresh, otherwise a new
        download; the stale cache when the download fails or yields nothing valid."""
        path = self._path(url)
        cached = path.exists()
        if cached and time.time() - path.stat().st_mtime < REFRESH_SECONDS:
            return parse_list_text(path.read_text(encoding="utf-8"), normalize)
        try:
            items = parse_list_text(self.fetch(url), normalize)
            if not items:
                raise ValueError("list did not contain any valid entries")
        except ValueError as exc:
            _LOGGER.warning("url list %s: %s", url, exc)
            if not cached:
                return []
            return parse_list_text(path.read_text(encoding="utf-8"), normalize)
        if not dry_run:
            atomic_write_lines(path, items)
        return items


@dataclass(frozen=True)
class DynamicSet:
    """What a set or inline destination contributes beyond its static routes."""

    domains: tuple[str, ...]
    domain_urls: tuple[str, ...]
    route_urls: tuple[str, ...]


def dynamic_sets(policy: EgressPolicy) -> dict[str, DynamicSet]:
    """Destinations that need resolving, keyed as NodeFacts.resolved is read: the set
    name, or `rule<N>` for an inline destination (D-25)."""
    found = {
        name: DynamicSet(tuple(dest.domains), tuple(dest.domain_urls), tuple(dest.route_urls))
        for name, dest in policy.sets.items()
        if dest.domains or dest.domain_urls or dest.route_urls
    }
    for index, rule in enumerate(policy.egress):
        if isinstance(rule.to, InlineDest) and rule.to.domains:
            found[f"rule{index}"] = DynamicSet(tuple(rule.to.domains), (), ())
    return found


MAX_EXIT_SETS = 64
MAX_EXIT_SET_ADDRESSES = 4096


def parse_exit_sets(value: object, *, strict: bool = False) -> dict[str, frozenset[str]]:
    """Addresses an agent reports for the destinations of its `exit:<n>` rules (D-79),
    keyed like `NodeFacts.resolved`. Lenient reading drops what is not an IPv4 address or
    network (the hub must never fail a pass over an agent's report); strict reading, used
    when the report arrives, raises ValueError instead."""
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_EXIT_SETS:
        if strict:
            raise ValueError("exit_sets must be an object with at most 64 entries")
        return {}
    found: dict[str, frozenset[str]] = {}
    for key, items in value.items():
        if not isinstance(key, str) or not isinstance(items, list):
            if strict:
                raise ValueError("exit_sets entries must map a name to a list")
            continue
        if len(items) > MAX_EXIT_SET_ADDRESSES:
            if strict:
                raise ValueError(f"exit_sets[{key}] has more than {MAX_EXIT_SET_ADDRESSES} items")
            continue
        addresses: set[str] = set()
        for item in items:
            try:
                network = ipaddress.ip_network(str(item), strict=False)
            except ValueError:
                if strict:
                    raise ValueError(f"exit_sets[{key}]: {item!r} is not an address") from None
                continue
            if network.version == 4:
                addresses.add(str(network))
        found[key] = frozenset(addresses)
    return found
