from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from kornode.config.loader import load_config
from kornode.services.domain_resolver import DnsLookup, DomainResolverService
from kornode.services.netinputs import resolved_state_dir
from kornode.services.url_lists import (
    REFRESH_SECONDS,
    UrlListCache,
    normalize_domain,
    normalize_route,
    parse_list_text,
)

URL = "https://lists.example.com/routes.txt"


class Fetch:
    def __init__(self, text: str | None) -> None:
        self.text = text
        self.calls = 0

    def __call__(self, url: str) -> str:
        self.calls += 1
        if self.text is None:
            raise ValueError("failed to download list: down")
        return self.text


def test_parse_skips_comments_and_malformed_lines() -> None:
    text = "# c\n\n10.0.0.1/8 # trailing\n; x\nnot-a-net\n192.0.2.0/24\n10.0.0.0/8\n"
    assert parse_list_text(text, normalize_route) == ["10.0.0.0/8", "192.0.2.0/24"]


def test_domains_are_lowercased_and_validated() -> None:
    assert parse_list_text("Example.COM\nbad_domain\n", normalize_domain) == ["example.com"]


def test_fresh_cache_is_not_downloaded_again(tmp_path: Path) -> None:
    fetch = Fetch("192.0.2.0/24\n")
    cache = UrlListCache(tmp_path, fetch=fetch)
    assert cache.items(URL, normalize_route) == ["192.0.2.0/24"]
    assert cache.items(URL, normalize_route) == ["192.0.2.0/24"]
    assert fetch.calls == 1


def test_failed_download_keeps_the_stale_cache(tmp_path: Path) -> None:
    cache = UrlListCache(tmp_path, fetch=Fetch("192.0.2.0/24\n"))
    cache.items(URL, normalize_route)
    path = next(tmp_path.glob("*.txt"))
    old = time.time() - REFRESH_SECONDS - 10
    os.utime(path, (old, old))
    down = UrlListCache(tmp_path, fetch=Fetch(None))
    assert down.items(URL, normalize_route) == ["192.0.2.0/24"]


def test_empty_list_is_not_applied_and_not_cached(tmp_path: Path) -> None:
    cache = UrlListCache(tmp_path, fetch=Fetch("# nothing\nbogus\n"))
    assert cache.items(URL, normalize_route) == []
    assert not list(tmp_path.glob("*.txt"))


def test_dry_run_does_not_write_the_cache(tmp_path: Path) -> None:
    cache = UrlListCache(tmp_path / "c", fetch=Fetch("192.0.2.0/24\n"))
    assert cache.items(URL, normalize_route, dry_run=True) == ["192.0.2.0/24"]
    assert not (tmp_path / "c").exists()


class _Net:
    def wake(self) -> bool:
        return True


class _Lookup(DnsLookup):
    def resolve(  # type: ignore[no-untyped-def]
        self, domain, nameservers, rdtype
    ):
        return (
            (["203.0.113.9"], 60) if (rdtype == "A" and domain == "bad.example.com") else ([], None)
        )


@pytest.mark.parametrize("with_domains", [False, True])
def test_resolver_records_url_routes_and_url_domains(tmp_path: Path, with_domains: bool) -> None:
    sets: dict[str, object] = {"s": {"route_urls": [URL]}}
    if with_domains:
        sets = {"s": {"route_urls": [URL], "domain_urls": ["https://lists.example.com/d.txt"]}}
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "sets": sets,
            "egress": [{"from": ["clients"], "to": {"set": "s"}, "via": "local"}],
        },
        environ={},
    )

    def fetch(url: str) -> str:
        return "bad.example.com\n" if url.endswith("d.txt") else "192.0.2.0/24\n"

    service = DomainResolverService(
        config,
        lookup=_Lookup(),
        net=_Net(),  # type: ignore[arg-type]
        url_lists=UrlListCache(tmp_path / "cache", fetch=fetch),
    )
    assert service.refresh().changed
    lines = (resolved_state_dir(config) / "s.txt").read_text(encoding="utf-8").split()
    assert ("192.0.2.0/24" in lines) and (("203.0.113.9" in lines) is with_domains)
