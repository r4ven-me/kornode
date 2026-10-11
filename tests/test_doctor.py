from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.test_upstream_service import _spawn_fake_openconnect

from kornode import cli
from kornode.api.app import create_app
from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.doctor import DoctorService
from kornode.services.upstream import UpstreamService
from kornode.services.upstream_pushed import PushedRouting, PushedRoutingStore


class FakeRunner:
    def __init__(self, responses: dict[tuple[str, ...], CommandResult]) -> None:
        self.responses = responses
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], **kwargs: Any) -> CommandResult:
        self.calls.append(list(argv))
        for pattern, result in self.responses.items():
            if tuple(argv[: len(pattern)]) == pattern:
                return result
        return CommandResult(argv=tuple(argv), returncode=0, stdout="", stderr="")


def _config(tmp_path: Path, **extra: object) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
                "log_dir": tmp_path / "logs",
            },
            **extra,
        }
    )


def _ok(stdout: str = "") -> CommandResult:
    return CommandResult(argv=(), returncode=0, stdout=stdout, stderr="")


def _fail(stderr: str = "") -> CommandResult:
    return CommandResult(argv=(), returncode=1, stdout="", stderr=stderr)


SYSCTL_OK = {
    ("sysctl", "-n", "net.ipv4.ip_forward"): _ok("1"),
    ("sysctl", "-n", "net.ipv4.conf.all.src_valid_mark"): _ok("1"),
    ("sysctl", "-n", "net.ipv4.conf.all.rp_filter"): _ok("2"),
    ("sysctl", "-n", "net.ipv4.conf.default.rp_filter"): _ok("2"),
}


def test_sysctl_check_passes_when_all_values_match(tmp_path: Path) -> None:
    runner = FakeRunner({**SYSCTL_OK, ("ip",): _ok("[]"), ("nft",): _ok(), ("uname",): _ok()})
    service = DoctorService(_config(tmp_path), runner=runner)

    results = service.run()

    assert results["sysctl"].ok


def test_sysctl_check_fails_when_a_value_is_wrong(tmp_path: Path) -> None:
    bad = {**SYSCTL_OK, ("sysctl", "-n", "net.ipv4.ip_forward"): _ok("0")}
    runner = FakeRunner({**bad, ("ip",): _ok("[]"), ("nft",): _ok(), ("uname",): _ok()})
    service = DoctorService(_config(tmp_path), runner=runner)

    results = service.run()

    assert not results["sysctl"].ok
    assert "net.ipv4.ip_forward" in results["sysctl"].stderr


def test_overlapping_subnets_ignores_own_pool_route(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            **SYSCTL_OK,
            ("ip", "route", "show", "table", "all"): _ok("10.10.10.0/24 dev lo\n"),
            ("ip",): _ok("[]"),
            ("nft",): _ok(),
            ("uname",): _ok(),
        }
    )
    service = DoctorService(_config(tmp_path), runner=runner)

    results = service.run()

    assert results["overlapping-subnets"].ok


def test_overlapping_subnets_detects_conflicting_route(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            **SYSCTL_OK,
            ("ip", "route", "show", "table", "all"): _ok("10.10.10.128/25 dev docker0\n"),
            ("ip",): _ok("[]"),
            ("nft",): _ok(),
            ("uname",): _ok(),
        }
    )
    service = DoctorService(_config(tmp_path), runner=runner)

    results = service.run()

    assert not results["overlapping-subnets"].ok
    assert "10.10.10.128/25" in results["overlapping-subnets"].stderr


def test_overlapping_subnets_detects_pushed_route_conflict(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        upstream={
            "enabled": True,
            "profiles": [
                {
                    "name": "primary",
                    "server": "vpn.example.com",
                    "auth_type": "password",
                    "username": "user",
                }
            ],
        },
    )
    profile = config.upstream.profiles[0]
    PushedRoutingStore(config).save(profile, PushedRouting(routes=["10.10.10.64/28"]))
    runner = FakeRunner(
        {
            **SYSCTL_OK,
            ("ip", "route", "show", "table", "all"): _ok(""),
            ("ip",): _ok("[]"),
            ("nft",): _ok(),
            ("uname",): _ok(),
        }
    )
    service = DoctorService(config, runner=runner)

    results = service.run()

    assert not results["overlapping-subnets"].ok
    assert "10.10.10.64/28" in results["overlapping-subnets"].stderr


def test_nft_version_reports_both_versions(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            **SYSCTL_OK,
            ("ip",): _ok("[]"),
            ("nft", "--version"): _ok("nftables v1.0.9"),
            ("uname", "-r"): _ok("6.1.0-kornode"),
        }
    )
    service = DoctorService(_config(tmp_path), runner=runner)

    results = service.run()

    assert results["nft-version"].ok
    assert "nftables v1.0.9" in results["nft-version"].stdout
    assert "6.1.0-kornode" in results["nft-version"].stdout


def test_nft_version_fails_when_nft_missing(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            **SYSCTL_OK,
            ("ip",): _ok("[]"),
            ("nft", "--version"): _fail("command not found"),
            ("uname", "-r"): _ok("6.1.0-kornode"),
        }
    )
    service = DoctorService(_config(tmp_path), runner=runner)

    results = service.run()

    assert not results["nft-version"].ok


def _connected_profile_config(tmp_path: Path, server: str = "203.0.113.10") -> AppConfig:
    config = _config(
        tmp_path,
        routing={"fwmark": "0x0c01", "table_id": 1201},
        upstream={
            "enabled": True,
            "active_profile": "primary",
            "profiles": [
                {
                    "name": "primary",
                    "server": server,
                    "auth_type": "password",
                    "username": "user",
                }
            ],
        },
    )
    return config


def test_policy_tables_reports_missing_routes_for_connected_profile(tmp_path: Path) -> None:
    config = _connected_profile_config(tmp_path)
    upstream = UpstreamService(config)
    process = _spawn_fake_openconnect(tmp_path)
    try:
        path = upstream._pid_file(config.upstream.profiles[0])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(process.pid))

        runner = FakeRunner(
            {
                **SYSCTL_OK,
                ("ip", "route", "show", "table", "1201"): _ok(""),
                ("ip",): _ok("[]"),
                ("nft",): _ok(),
                ("uname",): _ok(),
            }
        )
        service = DoctorService(config, runner=runner)

        results = service.run()

        assert not results["policy-tables"].ok
        assert "1201" in results["policy-tables"].stderr
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_policy_tables_passes_when_routes_present(tmp_path: Path) -> None:
    config = _connected_profile_config(tmp_path)
    upstream = UpstreamService(config)
    process = _spawn_fake_openconnect(tmp_path)
    try:
        path = upstream._pid_file(config.upstream.profiles[0])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(process.pid))

        runner = FakeRunner(
            {
                **SYSCTL_OK,
                ("ip", "route", "show", "table", "1201"): _ok(
                    "default dev oc-primary\nunreachable default metric 4096\n"
                ),
                ("ip",): _ok("[]"),
                ("nft",): _ok(),
                ("uname",): _ok(),
            }
        )
        service = DoctorService(config, runner=runner)

        results = service.run()

        assert results["policy-tables"].ok
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_carrier_exclusions_detects_missing_rule_for_connected_profile(tmp_path: Path) -> None:
    config = _connected_profile_config(tmp_path, server="203.0.113.10")
    upstream = UpstreamService(config)
    process = _spawn_fake_openconnect(tmp_path)
    try:
        path = upstream._pid_file(config.upstream.profiles[0])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(process.pid))

        runner = FakeRunner(
            {
                **SYSCTL_OK,
                ("ip", "-j", "rule", "show"): _ok("[]"),
                ("ip", "route"): _ok(""),
                ("nft",): _ok(),
                ("uname",): _ok(),
            }
        )
        service = DoctorService(config, runner=runner)

        results = service.run()

        assert not results["carrier-exclusions"].ok
        assert "203.0.113.10" in results["carrier-exclusions"].stderr
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_carrier_exclusions_passes_when_rule_present(tmp_path: Path) -> None:
    config = _connected_profile_config(tmp_path, server="203.0.113.10")
    upstream = UpstreamService(config)
    process = _spawn_fake_openconnect(tmp_path)
    try:
        path = upstream._pid_file(config.upstream.profiles[0])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(process.pid))

        rules = json.dumps([{"priority": 95, "dst": "203.0.113.10/32", "table": "main"}])
        runner = FakeRunner(
            {
                **SYSCTL_OK,
                ("ip", "-j", "rule", "show"): _ok(rules),
                ("ip", "route"): _ok(""),
                ("nft",): _ok(),
                ("uname",): _ok(),
            }
        )
        service = DoctorService(config, runner=runner)

        results = service.run()

        assert results["carrier-exclusions"].ok
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_carrier_exclusions_passes_when_no_profile_connected(tmp_path: Path) -> None:
    config = _connected_profile_config(tmp_path)
    runner = FakeRunner(
        {
            **SYSCTL_OK,
            ("ip",): _ok("[]"),
            ("nft",): _ok(),
            ("uname",): _ok(),
        }
    )
    service = DoctorService(config, runner=runner)

    results = service.run()

    assert results["carrier-exclusions"].ok
    assert "no connected" in results["carrier-exclusions"].stdout


def test_run_returns_every_check(tmp_path: Path) -> None:
    runner = FakeRunner({**SYSCTL_OK, ("ip",): _ok("[]"), ("nft",): _ok(), ("uname",): _ok()})
    service = DoctorService(_config(tmp_path), runner=runner)

    results = service.run()

    assert set(results) == {
        "sysctl",
        "overlapping-subnets",
        "policy-tables",
        "nft-version",
        "carrier-exclusions",
    }


def test_doctor_api_route_returns_every_check(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "web": {"admin_password": "secret"},
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
        }
    )
    client = TestClient(create_app(config=config))

    response = client.get("/api/diagnostics/doctor", auth=("admin", "secret"))

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "sysctl",
        "overlapping-subnets",
        "policy-tables",
        "nft-version",
        "carrier-exclusions",
    }
    for check in body.values():
        assert set(check) == {"argv", "returncode", "stdout", "stderr", "ok"}


def test_doctor_api_route_requires_admin(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "web": {"admin_password": "secret"},
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
        }
    )
    client = TestClient(create_app(config=config))

    response = client.get("/api/diagnostics/doctor")

    assert response.status_code == 401


class FakeDoctorService:
    def __init__(self, results: dict[str, CommandResult]) -> None:
        self._results = results

    def __call__(self, config: AppConfig) -> FakeDoctorService:
        return self

    def run(self) -> dict[str, CommandResult]:
        return self._results


def test_cli_doctor_prints_every_check_even_when_one_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    results = {
        "sysctl": CommandResult((), 1, "", "not applied: net.ipv4.ip_forward"),
        "overlapping-subnets": CommandResult((), 0, "no route overlaps VPN pool", ""),
    }
    monkeypatch.setattr(cli, "get_config", lambda: AppConfig.model_validate({}))
    monkeypatch.setattr(cli, "DoctorService", FakeDoctorService(results))

    with pytest.raises(cli.typer.Exit) as exc:
        cli.doctor()

    assert exc.value.exit_code == 1
    out = capsys.readouterr().out
    assert "sysctl" in out
    assert "overlapping-subnets" in out
    assert "no route overlaps VPN pool" in out


def test_cli_doctor_exits_zero_when_every_check_passes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    results = {"sysctl": CommandResult((), 0, "all required sysctls are applied", "")}
    monkeypatch.setattr(cli, "get_config", lambda: AppConfig.model_validate({}))
    monkeypatch.setattr(cli, "DoctorService", FakeDoctorService(results))

    cli.doctor()

    assert "all required sysctls are applied" in capsys.readouterr().out
