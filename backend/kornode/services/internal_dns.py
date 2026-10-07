from __future__ import annotations

import hashlib
import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from kornode.config.models import BLOCKLIST_DOMAIN_RE, AppConfig
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.files import FileManager

MAX_BLOCKLIST_BYTES = 10 * 1024 * 1024
MAX_BLOCKLIST_ENTRIES = 500_000
FETCH_TIMEOUT_SECONDS = 30
FETCH_USER_AGENT = "kornode-internal-dns/1.0"

# Hostnames that appear in hosts-format lists but must never be blocked.
HOSTS_FILE_NOISE = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
}


@dataclass(frozen=True)
class BlocklistParseResult:
    domains: list[str]
    total_lines: int
    skipped: int


@dataclass(frozen=True)
class BlocklistFetchResult:
    url: str
    total_lines: int
    valid: int
    skipped: int
    sample: list[str]
    saved: bool


class InternalDnsService:
    def __init__(
        self,
        config: AppConfig,
        files: FileManager | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.config = config
        self.files = files or FileManager()
        self.runner = runner or CommandRunner()

    def blocklist_cache_path(self, url: str) -> Path:
        return self.config.system.data_dir / "internal-dns" / "urls" / f"{_url_slug(url)}.txt"

    def blocklist_meta_path(self, url: str) -> Path:
        return self.config.system.data_dir / "internal-dns" / "urls" / f"{_url_slug(url)}.json"

    def blocklist_conf_path(self) -> Path:
        return self.config.generated_path("dnsmasq-blocklist.conf")

    def inline_domains(self) -> list[str]:
        return list(self.config.internal_dns.blocklist_domains)

    def file_domains(self, path: Path) -> list[str]:
        text = "\n".join(self.files.read_lines(path))
        return parse_blocklist_text(text).domains

    def all_file_domains(self) -> list[str]:
        merged: list[str] = []
        for path in self.config.internal_dns.blocklist_files:
            merged.extend(self.file_domains(path))
        return merged

    def url_cache_domains(self, url: str) -> list[str]:
        text = "\n".join(self.files.read_lines(self.blocklist_cache_path(url)))
        return parse_blocklist_text(text).domains

    def all_url_cache_domains(self) -> list[str]:
        merged: list[str] = []
        for url in self.config.internal_dns.blocklist_urls:
            merged.extend(self.url_cache_domains(url))
        return merged

    def merged_blocklist(self) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        sources = (self.inline_domains(), self.all_file_domains(), self.all_url_cache_domains())
        for source in sources:
            for domain in source:
                if domain not in seen:
                    merged.append(domain)
                    seen.add(domain)
        return merged

    def url_cache_meta(self, url: str) -> dict[str, object] | None:
        path = self.blocklist_meta_path(url)
        if not path.exists():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return loaded if isinstance(loaded, dict) else None

    def status(self) -> dict[str, object]:
        settings = self.config.internal_dns
        files_status = [
            {
                "path": str(path),
                "exists": path.exists(),
                "count": len(self.file_domains(path)) if path.exists() else 0,
            }
            for path in settings.blocklist_files
        ]
        urls_status = [
            {
                "url": url,
                "count": len(self.url_cache_domains(url)),
                "meta": self.url_cache_meta(url),
            }
            for url in settings.blocklist_urls
        ]
        reasons = self.config.dnsmasq_active_reasons()
        # The resolver is mandatory, not opt-in, whenever the VPN server is
        # enabled -- see AppConfig.client_dns_servers(). resolver_active is
        # purely informational now: there's no toggle left to reflect.
        resolver_active = self.config.server.enabled
        configured = {
            "blocklist_enabled": settings.blocklist_enabled,
            "local_records_enabled": settings.local_records_enabled,
        }
        effective = {
            "dnsmasq_active": bool(reasons),
            "resolver_active": resolver_active,
            "blocklist_enabled": settings.blocklist_enabled and bool(reasons),
            "local_records_enabled": settings.local_records_enabled and bool(reasons),
        }
        return {
            "configured": configured,
            "effective": effective,
            "effective_reasons": reasons,
            **configured,
            "resolver_active": resolver_active,
            "server_dns": list(self.config.server.dns),
            "search_domains": list(self.config.server.search_domains),
            "listen": self.config.internal_dns.listen,
            "port": self.config.internal_dns.port,
            "client_dns": self.config.client_dns_servers(),
            "blocklist_domains": self.inline_domains(),
            "blocklist_files": files_status,
            "blocklist_urls": urls_status,
            "total": len(self.merged_blocklist()),
            "cache_size": settings.cache_size,
            "log_queries": settings.log_queries,
            "local_records": list(settings.local_records),
            "upstreams": settings.upstreams,
            "forward_upstreams": settings.forward_upstreams,
            "forward_domains": settings.forward_domains,
        }

    def refresh_url_blocklist(self, url: str, *, preview: bool = False) -> BlocklistFetchResult:
        if url not in self.config.internal_dns.blocklist_urls:
            raise ValueError(f"internal_dns.blocklist_urls does not contain: {url}")
        text = _fetch_blocklist_text(url)
        parsed = parse_blocklist_text(text)
        if not parsed.domains:
            raise ValueError(
                "blocklist URL did not contain any valid domain entries; nothing was applied"
            )
        saved = False
        if not preview:
            cache_path = self.blocklist_cache_path(url)
            self.files.ensure_dir(cache_path.parent)
            self.files.write_unique_lines(cache_path, parsed.domains)
            self.files.atomic_write_text(
                self.blocklist_meta_path(url),
                json.dumps(
                    {
                        "url": url,
                        "fetched_at": int(time.time()),
                        "valid": len(parsed.domains),
                        "skipped": parsed.skipped,
                    }
                )
                + "\n",
            )
            saved = True
        return BlocklistFetchResult(
            url=url,
            total_lines=parsed.total_lines,
            valid=len(parsed.domains),
            skipped=parsed.skipped,
            sample=parsed.domains[:20],
            saved=saved,
        )

    def ensure_listen_address(self, *, dry_run: bool = False) -> CommandResult:
        """Assign the dnsmasq listen IP to the loopback interface (idempotent).

        ocserv never puts the VPN gateway address on a host interface: it
        creates one point-to-point tun device per client, so without this
        step dnsmasq cannot bind to the address and host-originated packets
        to it would follow the default route instead of local delivery.
        """
        listen = self.config.internal_dns.listen
        return self.runner.run(
            ["ip", "addr", "replace", f"{listen}/32", "dev", "lo"],
            check=False,
            dry_run=dry_run,
        )

    def remove_listen_address(self, *, dry_run: bool = False) -> CommandResult:
        listen = self.config.internal_dns.listen
        return self.runner.run(
            ["ip", "addr", "del", f"{listen}/32", "dev", "lo"],
            check=False,
            dry_run=dry_run,
        )

    def dnsmasq_argv(self) -> list[str]:
        return [
            "/usr/sbin/dnsmasq",
            f"--conf-file={self.config.generated_path('dnsmasq.conf')}",
            "--keep-in-foreground",
        ]

    def render_blocklist_conf(self) -> str:
        lines = [
            "# Generated by kornode. Internal DNS blocklist for the project-owned",
            "# dnsmasq instance. Manual edits may be overwritten.",
        ]
        for domain in sorted(self.merged_blocklist()):
            # Both address families: answering only A with 0.0.0.0 would let
            # dual-stack clients slip through via the real AAAA record.
            lines.append(f"address=/{domain}/0.0.0.0")
            lines.append(f"address=/{domain}/::")
        return "\n".join(lines) + "\n"


def parse_blocklist_text(text: str) -> BlocklistParseResult:
    domains: list[str] = []
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
        candidates = _line_candidates(line)
        if not candidates:
            skipped += 1
            continue
        matched = False
        for candidate in candidates:
            domain = candidate.strip().lower().rstrip(".")
            if (
                domain
                and domain not in HOSTS_FILE_NOISE
                and BLOCKLIST_DOMAIN_RE.match(domain)
            ):
                matched = True
                if domain not in seen:
                    domains.append(domain)
                    seen.add(domain)
        if not matched:
            skipped += 1
        if len(domains) > MAX_BLOCKLIST_ENTRIES:
            raise ValueError(
                f"blocklist exceeds the safety limit of {MAX_BLOCKLIST_ENTRIES} entries"
            )
    return BlocklistParseResult(domains=domains, total_lines=total_lines, skipped=skipped)


def _line_candidates(line: str) -> list[str]:
    tokens = line.split()
    if not tokens:
        return []
    first = tokens[0]
    # hosts(5) format: "0.0.0.0 ads.example.com tracker.example.com"
    if _is_ip_address(first):
        return tokens[1:]
    if len(tokens) > 1:
        return []
    # AdBlock-style plain rule: "||ads.example.com^"
    if first.startswith("||") and first.endswith("^"):
        return [first[2:-1]]
    return [first]


def _url_slug(url: str) -> str:
    """Filesystem-safe, stable per-URL cache filename stem."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _fetch_blocklist_text(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("blocklist URL must be a valid HTTP(S) URL")
    request = urllib.request.Request(  # noqa: S310 - scheme validated above
        url,
        headers={"User-Agent": FETCH_USER_AGENT, "Accept": "text/plain, */*"},
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - scheme validated above
            request,
            timeout=FETCH_TIMEOUT_SECONDS,
        ) as response:
            payload: bytes = response.read(MAX_BLOCKLIST_BYTES + 1)
    except urllib.error.URLError as exc:
        raise ValueError(f"failed to download blocklist: {exc.reason}") from exc
    if len(payload) > MAX_BLOCKLIST_BYTES:
        raise ValueError(
            f"blocklist download exceeds the safety limit of {MAX_BLOCKLIST_BYTES} bytes"
        )
    return payload.decode("utf-8", errors="replace")
