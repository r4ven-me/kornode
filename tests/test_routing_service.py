from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from kornode.config.models import AppConfig
from kornode.services.routing import RoutingService


def _config(tmp_path: Path, **split_overrides: object) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "routing": {
                "split": {
                    "routes_file": str(tmp_path / "routes.txt"),
                    "domains_file": str(tmp_path / "domains.txt"),
                    **split_overrides,
                }
            },
        }
    )


def test_set_routes_replaces_the_whole_file(tmp_path: Path) -> None:
    service = RoutingService(_config(tmp_path))
    service.add_route("10.1.0.0/16")

    service.set_routes(["10.20.0.0/16", "203.0.113.5"])

    assert service.list_routes() == ["10.20.0.0/16", "203.0.113.5"]


def test_concurrent_add_route_calls_do_not_lose_changes(tmp_path: Path) -> None:
    # Regression test: _add_line() read-modify-writes the whole routes.txt
    # file, and uvicorn serves API requests on parallel threads -- without a
    # lock, concurrent add_route() calls for different CIDRs would each read
    # the same original file and the last write would silently discard the
    # others.
    service = RoutingService(_config(tmp_path))
    routes = [f"10.{i}.0.0/16" for i in range(8)]

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(service.add_route, route) for route in routes]
        for future in futures:
            future.result()

    assert sorted(service.list_routes()) == sorted(routes)


def test_set_routes_normalizes_cidr_and_bare_ips(tmp_path: Path) -> None:
    service = RoutingService(_config(tmp_path))

    service.set_routes(["203.0.113.5", "10.20.0.0/16"])

    assert service.list_routes() == ["203.0.113.5", "10.20.0.0/16"]


def test_set_routes_deduplicates(tmp_path: Path) -> None:
    service = RoutingService(_config(tmp_path))

    service.set_routes(["10.20.0.0/16", "10.20.0.0/16"])

    assert service.list_routes() == ["10.20.0.0/16"]


def test_set_routes_rejects_invalid_entry_and_leaves_existing_list_untouched(
    tmp_path: Path,
) -> None:
    service = RoutingService(_config(tmp_path))
    service.set_routes(["10.20.0.0/16"])

    with pytest.raises(ValueError, match="invalid route or IP"):
        service.set_routes(["not-a-route"])

    assert service.list_routes() == ["10.20.0.0/16"]


def test_set_domains_replaces_the_whole_file(tmp_path: Path) -> None:
    service = RoutingService(_config(tmp_path))
    service.add_domain("old.example.com")

    service.set_domains(["corp.example.com", "internal.example"])

    assert service.list_domains() == ["corp.example.com", "internal.example"]


def test_set_domains_rejects_invalid_entry(tmp_path: Path) -> None:
    service = RoutingService(_config(tmp_path))

    with pytest.raises(ValueError, match="invalid domain"):
        service.set_domains(["not a domain!"])


def test_routes_urls_must_be_http(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="HTTP\\(S\\)"):
        _config(tmp_path, routes_urls=["ftp://lists.example.com/routes.txt"])


def test_domains_urls_must_be_http(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="HTTP\\(S\\)"):
        _config(tmp_path, domains_urls=["not-a-url"])


def test_legacy_routes_files_are_ignored(tmp_path: Path) -> None:
    # routes_files/domains_files (admin-maintained external files kornode
    # just read, on top of the inline list/URLs/managed runtime file) are
    # removed -- see RoutingSplitConfig.drop_legacy_static_files. No
    # automatic migration: the field is simply gone.
    path = tmp_path / "static-routes.txt"
    config = _config(tmp_path, routes_files=[str(path), str(path)])

    assert not hasattr(config.routing.split, "routes_files")


def test_refresh_route_url_validates_caches_and_merges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "https://lists.example.com/routes.txt"
    service = RoutingService(_config(tmp_path, routes_urls=[url]))
    monkeypatch.setattr(
        "kornode.services.external_lists.fetch_url_text",
        lambda url, **kwargs: "10.60.0.0/16\ngarbage\n10.70.0.0/16\n",
    )

    preview = service.refresh_route_url(url, preview=True)
    assert preview.valid == 2
    assert preview.skipped == 1
    assert not preview.saved
    assert not service.route_urls.cache_path(url).exists()

    result = service.refresh_route_url(url)
    assert result.saved
    assert service.list_routes() == ["10.60.0.0/16", "10.70.0.0/16"]
    meta = service.route_urls.meta(url)
    assert meta is not None
    assert meta["valid"] == 2


def test_refresh_route_url_rejects_url_not_in_configured_list(tmp_path: Path) -> None:
    service = RoutingService(_config(tmp_path))

    with pytest.raises(ValueError, match="does not contain"):
        service.refresh_route_url("https://unsaved.example.com/x")


def test_refresh_domain_url_validates_caches_and_merges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "https://lists.example.com/domains.txt"
    service = RoutingService(_config(tmp_path, domains_urls=[url]))
    monkeypatch.setattr(
        "kornode.services.external_lists.fetch_url_text",
        lambda url, **kwargs: "corp.example.com\nnot_a_domain!\n",
    )

    result = service.refresh_domain_url(url)

    assert result.saved
    assert result.valid == 1
    assert result.skipped == 1
    assert service.list_domains() == ["corp.example.com"]


def test_routes_urls_status_reports_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "https://lists.example.com/routes.txt"
    service = RoutingService(_config(tmp_path, routes_urls=[url]))
    monkeypatch.setattr(
        "kornode.services.external_lists.fetch_url_text",
        lambda url, **kwargs: "10.60.0.0/16\n",
    )
    service.refresh_route_url(url)

    urls_status = service.routes_urls_status()
    assert len(urls_status) == 1
    assert urls_status[0]["url"] == url
    assert urls_status[0]["count"] == 1
    assert urls_status[0]["meta"]["valid"] == 1


def test_profile_lists_merge_inline_and_url_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route_url = "https://lists.example.com/profile-routes.txt"
    domain_url = "https://lists.example.com/profile-domains.txt"
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            },
            "upstream": {
                "profiles": [
                    {
                        "name": "finance",
                        "server": "vpn.example.com",
                        "username": "user",
                        "routes": ["10.10.0.0/16"],
                        "domains": ["inline.example.com"],
                        "routes_urls": [route_url],
                        "domains_urls": [domain_url],
                    }
                ]
            },
        }
    )
    service = RoutingService(config)
    profile = config.upstream.profiles[0]

    monkeypatch.setattr(
        "kornode.services.external_lists.fetch_url_text",
        lambda url, **kwargs: (
            "10.30.0.0/16\n10.10.0.0/16\n"
            if url == route_url
            else "url.example.com\ninline.example.com\n"
        ),
    )
    service.refresh_profile_route_url(profile, route_url)
    service.refresh_profile_domain_url(profile, domain_url)

    assert service.list_profile_routes(profile) == ["10.10.0.0/16", "10.30.0.0/16"]
    assert service.list_profile_domains(profile) == ["inline.example.com", "url.example.com"]
