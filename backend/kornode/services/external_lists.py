from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from kornode.services.files import FileManager

MAX_LIST_BYTES = 10 * 1024 * 1024
MAX_LIST_ENTRIES = 500_000
FETCH_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class ExternalListParseResult:
    items: list[str]
    total_lines: int
    skipped: int


@dataclass(frozen=True)
class ExternalListFetchResult:
    url: str
    total_lines: int
    valid: int
    skipped: int
    sample: list[str]
    saved: bool


def url_slug(url: str) -> str:
    """Filesystem-safe, stable per-URL cache filename stem."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def fetch_url_text(url: str, *, user_agent: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be a valid HTTP(S) URL")
    request = urllib.request.Request(  # noqa: S310 - scheme validated above
        url,
        headers={"User-Agent": user_agent, "Accept": "text/plain, */*"},
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - scheme validated above
            request,
            timeout=FETCH_TIMEOUT_SECONDS,
        ) as response:
            payload: bytes = response.read(MAX_LIST_BYTES + 1)
    except urllib.error.URLError as exc:
        raise ValueError(f"failed to download list: {exc.reason}") from exc
    if len(payload) > MAX_LIST_BYTES:
        raise ValueError(f"download exceeds the safety limit of {MAX_LIST_BYTES} bytes")
    return payload.decode("utf-8", errors="replace")


def parse_list_text(text: str, *, normalize: Callable[[str], str]) -> ExternalListParseResult:
    """Tolerant one-entry-per-line parser shared by every external
    file/URL list source (internal_dns's blocklist_files/urls, routing's
    routes_files/urls and domains_files/urls): blank lines and full-line
    `#`/`!`/`;` comments are skipped, a trailing `# comment` is stripped,
    and a line that fails `normalize` is counted as skipped rather than
    failing the whole fetch -- external lists routinely contain a few
    malformed entries that shouldn't invalidate the rest.
    """
    items: list[str] = []
    seen: set[str] = set()
    total_lines = 0
    skipped = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        total_lines += 1
        comment_index = line.find("#")
        if comment_index != -1:
            line = line[:comment_index].strip()
        candidate = line.split()[0] if line.split() else ""
        if not candidate:
            skipped += 1
            continue
        try:
            normalized = normalize(candidate)
        except ValueError:
            skipped += 1
            continue
        if normalized not in seen:
            items.append(normalized)
            seen.add(normalized)
        if len(items) > MAX_LIST_ENTRIES:
            raise ValueError(f"list exceeds the safety limit of {MAX_LIST_ENTRIES} entries")
    return ExternalListParseResult(items=items, total_lines=total_lines, skipped=skipped)


class ExternalListCache:
    """Per-URL fetch/cache/meta helper: an admin lists a URL, kornode
    fetches and caches its parsed contents, and a CLI/API refresh action
    re-fetches on demand. Shared shape for every "static external list"
    feature (internal_dns's blocklist_urls; routing's routes_urls and
    domains_urls) -- each instance is scoped to its own cache_dir so their
    cached files never collide."""

    def __init__(self, cache_dir: Path, files: FileManager, *, user_agent: str) -> None:
        self.cache_dir = cache_dir
        self.files = files
        self.user_agent = user_agent

    def cache_path(self, url: str) -> Path:
        return self.cache_dir / f"{url_slug(url)}.txt"

    def meta_path(self, url: str) -> Path:
        return self.cache_dir / f"{url_slug(url)}.json"

    def cached_items(self, url: str, *, normalize: Callable[[str], str]) -> list[str]:
        text = "\n".join(self.files.read_lines(self.cache_path(url)))
        return parse_list_text(text, normalize=normalize).items

    def meta(self, url: str) -> dict[str, object] | None:
        path = self.meta_path(url)
        if not path.exists():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return loaded if isinstance(loaded, dict) else None

    def refresh(
        self,
        url: str,
        *,
        normalize: Callable[[str], str],
        preview: bool = False,
    ) -> ExternalListFetchResult:
        text = fetch_url_text(url, user_agent=self.user_agent)
        parsed = parse_list_text(text, normalize=normalize)
        if not parsed.items:
            raise ValueError("list did not contain any valid entries; nothing was applied")
        saved = False
        if not preview:
            cache_path = self.cache_path(url)
            self.files.ensure_dir(cache_path.parent)
            self.files.write_unique_lines(cache_path, parsed.items)
            self.files.atomic_write_text(
                self.meta_path(url),
                json.dumps(
                    {
                        "url": url,
                        "fetched_at": int(time.time()),
                        "valid": len(parsed.items),
                        "skipped": parsed.skipped,
                    }
                )
                + "\n",
            )
            saved = True
        return ExternalListFetchResult(
            url=url,
            total_lines=parsed.total_lines,
            valid=len(parsed.items),
            skipped=parsed.skipped,
            sample=parsed.items[:20],
            saved=saved,
        )
