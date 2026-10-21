"""Fetch and cache the URL-sourced lists of egress sets (`route_urls`, `domain_urls`).

Only DomainResolverService calls this: it turns the lists into set elements and
records them in `resolved/<set>.txt`. A failed download keeps the last cached
copy (a set never silently empties because a list host is down); a list with no
valid entries is refused rather than applied.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

from kornode.services.files import FileManager

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


class UrlListCache:
    def __init__(
        self, cache_dir: Path, files: FileManager | None = None, fetch: Fetcher = fetch_url_text
    ) -> None:
        self.cache_dir = cache_dir
        self.files = files or FileManager()
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
            text = self.fetch(url)
            items = parse_list_text(text, normalize)
            if not items:
                raise ValueError("list did not contain any valid entries")
        except ValueError as exc:
            _LOGGER.warning("url list %s: %s", url, exc)
            if not cached:
                return []
            return parse_list_text(path.read_text(encoding="utf-8"), normalize)
        if not dry_run:
            self.files.ensure_dir(self.cache_dir)
            self.files.atomic_write_text(path, "".join(f"{item}\n" for item in items))
        return items
