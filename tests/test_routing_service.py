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


def test_routes_files_are_deduplicated(tmp_path: Path) -> None:
    path = tmp_path / "static-routes.txt"
    config = _config(tmp_path, routes_files=[str(path), str(path)])

    assert config.routing.split.routes_files == [path]


def test_list_routes_merges_static_files_alongside_inline_and_runtime(tmp_path: Path) -> None:
    # Mirrors internal_dns's blocklist_files: an admin-managed file whose
    # contents are read/merged in, distinct from the runtime-editable
    # routes_file that korctl routes add/delete manages.
    static_file = tmp_path / "static-routes.txt"
    static_file.write_text("10.40.0.0/16\n# a comment\ngarbage-not-a-route\n", encoding="utf-8")
    service = RoutingService(_config(tmp_path, routes=["10.30.0.0/16"], routes_files=[static_file]))
    service.add_route("10.20.0.0/16")

    assert service.list_routes() == ["10.30.0.0/16", "10.20.0.0/16", "10.40.0.0/16"]


def test_list_domains_merges_static_files(tmp_path: Path) -> None:
    static_file = tmp_path / "static-domains.txt"
    static_file.write_text("corp.example.com\nnot_a_domain!\n", encoding="utf-8")
    service = RoutingService(_config(tmp_path, domains_files=[static_file]))

    assert service.list_domains() == ["corp.example.com"]


def test_file_routes_tolerates_malformed_lines_instead_of_raising(tmp_path: Path) -> None:
    static_file = tmp_path / "static-routes.txt"
    static_file.write_text("10.40.0.0/16\nnot-a-route\n10.50.0.0/16\n", encoding="utf-8")
    service = RoutingService(_config(tmp_path))

    assert service.file_routes(static_file) == ["10.40.0.0/16", "10.50.0.0/16"]


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


def test_routes_files_and_urls_status_report_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    static_file = tmp_path / "static-routes.txt"
    static_file.write_text("10.40.0.0/16\n", encoding="utf-8")
    missing_file = tmp_path / "missing.txt"
    url = "https://lists.example.com/routes.txt"
    service = RoutingService(
        _config(tmp_path, routes_files=[static_file, missing_file], routes_urls=[url])
    )
    monkeypatch.setattr(
        "kornode.services.external_lists.fetch_url_text",
        lambda url, **kwargs: "10.60.0.0/16\n",
    )
    service.refresh_route_url(url)

    files_status = service.routes_files_status()
    assert {"path": str(static_file), "exists": True, "count": 1} in files_status
    assert {"path": str(missing_file), "exists": False, "count": 0} in files_status

    urls_status = service.routes_urls_status()
    assert len(urls_status) == 1
    assert urls_status[0]["url"] == url
    assert urls_status[0]["count"] == 1
    assert urls_status[0]["meta"]["valid"] == 1
