from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from kornode import cli
from kornode.api import routes_diagnostics
from kornode.api.auth import require_admin
from kornode.config.models import AppConfig
from kornode.services.command import CommandResult
from kornode.services.doctor import DoctorService


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


class FakeNet:
    def __init__(
        self,
        ops: list[dict[str, str]] | None = None,
        exits: list[str] | None = None,
    ) -> None:
        self._plan = {"ops": ops or [], "exits": exits or []}
        self.calls = 0

    def plan(self) -> dict[str, object]:
        self.calls += 1
        return self._plan


def test_sysctl_check_passes_when_all_values_match(tmp_path: Path) -> None:
    service = DoctorService(_config(tmp_path), runner=FakeRunner({}), net=FakeNet())

    results = service.run()

    assert results["sysctl"].ok


def test_sysctl_check_fails_when_a_value_is_wrong(tmp_path: Path) -> None:
    service = DoctorService(
        _config(tmp_path),
        runner=FakeRunner({}),
        net=FakeNet([{"op": "SetSysctl", "text": "set net.ipv4.ip_forward=1"}]),
    )

    results = service.run()

    assert not results["sysctl"].ok
    assert "net.ipv4.ip_forward" in results["sysctl"].stderr
    assert "kernel differs from the policy" in results["sysctl"].stderr


def test_kernel_plan_fails_when_any_reconciler_op_is_pending(tmp_path: Path) -> None:
    service = DoctorService(
        _config(tmp_path),
        runner=FakeRunner({}),
        net=FakeNet([{"op": "UpdateElements", "text": "replace nft set split"}]),
    )

    results = service.run()

    assert not results["kernel-plan"].ok
    assert "replace nft set split" in results["kernel-plan"].stderr


def test_kernel_plan_reuses_one_net_plan_for_derived_checks(tmp_path: Path) -> None:
    net = FakeNet()
    service = DoctorService(_config(tmp_path), runner=FakeRunner({}), net=net)

    service.run()

    assert net.calls == 1


def test_overlapping_subnets_ignores_own_pool_route(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            ("ip", "route", "show", "table", "all"): _ok("10.100.1.0/24 dev lo\n"),
        }
    )
    service = DoctorService(_config(tmp_path), runner=runner, net=FakeNet())

    results = service.run()

    assert results["overlapping-subnets"].ok


def test_overlapping_subnets_detects_conflicting_route(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            ("ip", "route", "show", "table", "all"): _ok("10.100.1.128/25 dev docker0\n"),
        }
    )
    service = DoctorService(_config(tmp_path), runner=runner, net=FakeNet())

    results = service.run()

    assert not results["overlapping-subnets"].ok
    assert "10.100.1.128/25" in results["overlapping-subnets"].stderr


def test_nft_version_reports_both_versions(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            ("ip",): _ok("[]"),
            ("nft", "--version"): _ok("nftables v1.0.9"),
            ("uname", "-r"): _ok("6.1.0-kornode"),
        }
    )
    service = DoctorService(_config(tmp_path), runner=runner, net=FakeNet())

    results = service.run()

    assert results["nft-version"].ok
    assert "nftables v1.0.9" in results["nft-version"].stdout
    assert "6.1.0-kornode" in results["nft-version"].stdout


def test_nft_version_fails_when_nft_missing(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            ("ip",): _ok("[]"),
            ("nft", "--version"): _fail("command not found"),
            ("uname", "-r"): _ok("6.1.0-kornode"),
        }
    )
    service = DoctorService(_config(tmp_path), runner=runner, net=FakeNet())

    results = service.run()

    assert not results["nft-version"].ok


def _connected_profile_config(tmp_path: Path, server: str = "203.0.113.10") -> AppConfig:
    config = _config(
        tmp_path,
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
    service = DoctorService(
        _connected_profile_config(tmp_path),
        runner=FakeRunner({}),
        net=FakeNet(
            [{"op": "ReplaceRoute", "text": "replace default in table 1201 via oc-primary"}]
        ),
    )

    results = service.run()

    assert not results["policy-tables"].ok
    assert "1201" in results["policy-tables"].stderr


def test_policy_tables_passes_when_routes_present(tmp_path: Path) -> None:
    service = DoctorService(
        _connected_profile_config(tmp_path),
        runner=FakeRunner({}),
        net=FakeNet(),
    )

    results = service.run()

    assert results["policy-tables"].ok


def test_carrier_exclusions_detects_missing_rule_for_connected_profile(tmp_path: Path) -> None:
    service = DoctorService(
        _connected_profile_config(tmp_path, server="203.0.113.10"),
        runner=FakeRunner({}),
        net=FakeNet([{"op": "AddRule", "text": "add carrier exclusion for 203.0.113.10/32"}]),
    )

    results = service.run()

    assert not results["carrier-exclusions"].ok
    assert "203.0.113.10" in results["carrier-exclusions"].stderr


def test_carrier_exclusions_passes_when_rule_present(tmp_path: Path) -> None:
    service = DoctorService(
        _connected_profile_config(tmp_path, server="203.0.113.10"),
        runner=FakeRunner({}),
        net=FakeNet(),
    )

    results = service.run()

    assert results["carrier-exclusions"].ok


def test_carrier_exclusions_passes_when_no_profile_connected(tmp_path: Path) -> None:
    service = DoctorService(
        _connected_profile_config(tmp_path),
        runner=FakeRunner({}),
        net=FakeNet(),
    )

    results = service.run()

    assert results["carrier-exclusions"].ok
    assert "policy rules" in results["carrier-exclusions"].stdout


def test_run_returns_every_check(tmp_path: Path) -> None:
    runner = FakeRunner({("ip",): _ok("[]"), ("nft",): _ok(), ("uname",): _ok()})
    service = DoctorService(_config(tmp_path), runner=runner, net=FakeNet())

    results = service.run()

    assert set(results) == {
        "admin-password",
        "control-only",
        "kernel-plan",
        "sysctl",
        "overlapping-subnets",
        "policy-tables",
        "nft-version",
        "carrier-exclusions",
        "access-certificates",
        "agent-versions",
        "sources",
    }


def test_doctor_api_route_returns_every_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    results = {
        "kernel-plan": CommandResult((), 0, "the kernel matches the compiled policy", ""),
        "sysctl": CommandResult((), 0, "all required sysctls are applied", ""),
        "overlapping-subnets": CommandResult((), 0, "no route overlaps VPN pool", ""),
        "policy-tables": CommandResult((), 0, "0 exit(s), routes as planned", ""),
        "nft-version": CommandResult((), 0, "nft: test; kernel: test", ""),
        "carrier-exclusions": CommandResult((), 0, "policy rules as planned", ""),
    }
    monkeypatch.setattr(routes_diagnostics, "DoctorService", FakeDoctorService(results))

    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=config)))
    body = routes_diagnostics.doctor(request)  # type: ignore[arg-type]

    assert set(body) == {
        "kernel-plan",
        "sysctl",
        "overlapping-subnets",
        "policy-tables",
        "nft-version",
        "carrier-exclusions",
    }
    for check in body.values():
        assert set(check) == {"argv", "returncode", "stdout", "stderr", "ok"}


def test_doctor_api_route_requires_admin() -> None:
    assert any(
        dependency.dependency is require_admin
        for dependency in routes_diagnostics.router.dependencies
    )


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


SOURCES = {"sources": [{"name": "wg", "interface": "wg0", "cidr": "10.8.1.0/24"}]}
NAT_JSON = (
    '{"nftables": [{"rule": {"family": "ip", "table": "wgnat", "chain": "post", "expr": ['
    '{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, '
    '"right": {"prefix": {"addr": "10.8.1.0", "len": 24}}}}, {"masquerade": null}]}}]}'
)


def test_sources_check_is_quiet_without_sources(tmp_path: Path) -> None:
    results = DoctorService(_config(tmp_path), runner=FakeRunner({}), net=FakeNet()).run()

    assert results["sources"].ok and "no sources" in results["sources"].stdout


def test_sources_check_passes_with_the_interface_and_no_foreign_nat(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            ("ip", "-j"): _ok('[{"ifname": "wg0"}]'),
            ("nft", "-j"): _ok(NAT_JSON.replace("masquerade", "counter")),
        }
    )
    service = DoctorService(_config(tmp_path, **SOURCES), runner=runner, net=FakeNet())

    assert service.run()["sources"].ok


def test_sources_check_flags_a_missing_interface(tmp_path: Path) -> None:
    runner = FakeRunner(
        {("ip", "-j"): _ok('[{"ifname": "lo"}]'), ("nft", "-j"): _ok('{"nftables": []}')}
    )
    service = DoctorService(_config(tmp_path, **SOURCES), runner=runner, net=FakeNet())

    result = service.run()["sources"]

    assert not result.ok and "wg0 is absent" in result.stderr


def test_sources_check_flags_foreign_nat_on_the_source_subnet(tmp_path: Path) -> None:
    runner = FakeRunner({("ip", "-j"): _ok('[{"ifname": "wg0"}]'), ("nft", "-j"): _ok(NAT_JSON)})
    service = DoctorService(_config(tmp_path, **SOURCES), runner=runner, net=FakeNet())

    result = service.run()["sources"]

    assert not result.ok and "foreign NAT" in result.stderr


def test_control_only_check_reports_the_mode_and_a_dead_end(tmp_path: Path) -> None:
    runner = FakeRunner({("ip",): _ok("[]"), ("nft",): _ok(), ("uname",): _ok()})

    def check(**extra: object) -> object:
        service = DoctorService(_config(tmp_path, **extra), runner=runner, net=FakeNet())
        return service._check_control_only()

    normal = check()
    assert normal.ok and "accepts VPN clients" in normal.stdout  # type: ignore[attr-defined]
    only = check(server={"clients": False}, control={"enabled": True})
    assert only.ok and "refuses every VPN login" in only.stdout  # type: ignore[attr-defined]
    dead = check(server={"clients": False}, control={"enabled": False})
    assert not dead.ok and "nothing can connect" in dead.stderr  # type: ignore[attr-defined]
