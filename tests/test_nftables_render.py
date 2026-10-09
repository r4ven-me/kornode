from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.renderers.nftables import NftablesConfigRenderer
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.nftables import NftablesService


class MissingNftRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        return CommandResult(tuple(argv), 1, "", "Error: No such file or directory", dry_run)


class SuccessfulNftRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, extra_secrets
        # Simulate a plain (non-Docker-managed) host: the DOCKER-USER
        # compat check has nothing to find, so _ensure_docker_forward_compat
        # is a no-op and doesn't add trailing results after the summary
        # message this fake exists to test.
        if tuple(argv[:5]) == ("nft", "list", "chain", "ip", "filter"):
            return CommandResult(tuple(argv), 1, "", "No such file or directory", dry_run)
        return CommandResult(tuple(argv), 0, "", "", dry_run)


class CrashingNftRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 30,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        dry_run: bool = False,
        extra_secrets: Sequence[str] | None = None,
    ) -> CommandResult:
        del timeout, input_text, env, check, extra_secrets
        if tuple(argv[:2]) == ("nft", "-f"):
            return CommandResult(tuple(argv), -11, "", "", dry_run)
        return CommandResult(tuple(argv), 0, "", "", dry_run)


def test_nftables_render_does_not_flush_global_ruleset(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "split": {"routes": ["192.168.25.0/24", "10.20.30.40"]},
            }
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "flush ruleset" not in rendered.lower()
    assert "table inet kornode_filter" in rendered
    assert "192.168.25.0/24" in rendered
    assert "10.20.30.40" in rendered


def test_split_sets_use_auto_merge_for_overlapping_intervals(tmp_path: Path) -> None:
    # Regression test: without auto-merge, nft rejects the entire ruleset
    # with "Error: conflicting intervals specified" as soon as the routes
    # list contains overlapping CIDRs (e.g. 5.28.192.0/18 alongside
    # 5.28.192.0/21) -- which real-world pasted lists routinely do -- or
    # when dnsmasq's nftset= tries to add an IP already covered by a
    # listed interval.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "split": {"routes": ["5.28.192.0/18", "5.28.192.0/21"]},
            }
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    v4_static, v4_dynamic = rendered.split("set split_v4_dynamic")
    v6_static, v6_dynamic = rendered.split("set split_v6_dynamic")
    assert "auto-merge" in v4_static
    assert "auto-merge" in v4_dynamic
    assert "auto-merge" in v6_static
    assert "auto-merge" in v6_dynamic


def test_render_static_refresh_only_touches_static_sets(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "split": {"routes": ["192.168.25.0/24"]},
                "host_traffic": True,
                "host_mode": "split",
                "host_split": {"routes": ["10.2.0.0/16"]},
            },
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance",
                        interface="oc-finance",
                        routes=["10.50.0.0/16"],
                        route_host_enabled=True,
                        host_routes=["10.90.0.0/16"],
                    ),
                ],
            },
        },
        environ={},
    )

    refresh = NftablesConfigRenderer().render_static_refresh(config)

    assert "flush set inet kornode_filter split_v4_static" in refresh
    assert "add element inet kornode_filter split_v4_static { 192.168.25.0/24 }" in refresh
    assert "flush set inet kornode_filter split_v4_finance_static" in refresh
    assert "add element inet kornode_filter split_v4_finance_static { 10.50.0.0/16 }" in refresh
    assert "flush set inet kornode_filter host_v4_finance_static" in refresh
    assert "add element inet kornode_filter host_v4_finance_static { 10.90.0.0/16 }" in refresh
    assert "flush set inet kornode_filter host_split_v4_static" in refresh
    assert "add element inet kornode_filter host_split_v4_static { 10.2.0.0/16 }" in refresh
    # Never touches any *_dynamic set -- that's dnsmasq's job, and a refresh
    # here must not wipe already-resolved domain IPs.
    assert "_dynamic\n" not in refresh
    assert "flush set inet kornode_filter split_v4_dynamic" not in refresh


def test_nftables_render_includes_routes_added_at_runtime(tmp_path: Path) -> None:
    # Regression test: split_v4_elements used to read routing.split.routes
    # directly, silently ignoring anything added via the API/CLI at runtime
    # (which is stored in routes_file, not the static config list) -- so a
    # route added through the web UI never actually reached the firewall.
    routes_file = tmp_path / "routes.txt"
    routes_file.write_text("10.99.0.0/16\n", encoding="utf-8")
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "split": {"routes_file": str(routes_file)},
            }
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "10.99.0.0/16" in rendered


def test_nftables_auto_interface_still_masquerades_clients(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={"routing": {"mode": "full", "main_interface": "auto"}},
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert f"ip saddr {config.server.ipv4_network} masquerade" in rendered


def _upstream_profile() -> dict[str, object]:
    return {
        "name": "primary",
        "server": "vpn.example.com",
        "auth_type": "password",
        "username": "user",
    }


def test_split_mode_with_upstream_masquerades_unmarked_traffic_normally(
    tmp_path: Path,
) -> None:
    # Regression test: split mode used to scope the ENTIRE client-subnet
    # masquerade rule to the upstream oifname, meaning any traffic that
    # wasn't in the split list (i.e. destined for the ordinary internet,
    # not upstream) never matched any masquerade rule at all once upstream
    # was enabled -- it left with a private VPN-subnet source address and
    # was effectively undeliverable.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "split", "split": {"routes": ["192.168.25.0/24"]}},
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert (
        f"ip saddr {config.server.ipv4_network} meta mark != {config.routing.fwmark} "
        "masquerade" in rendered
    )


def test_full_mode_with_upstream_adds_killswitch_drop(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert (
        f'meta mark {config.routing.fwmark} oifname != "oc-middle0" counter drop' in rendered
    )
    assert (
        f'ip saddr {config.server.ipv4_network} meta mark {config.routing.fwmark} '
        'oifname "oc-middle0" masquerade' in rendered
    )


def test_killswitch_absent_when_upstream_disabled(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={"routing": {"mode": "full"}},
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "drop" not in rendered


def test_client_traffic_off_suppresses_default_client_marking_and_nat(
    tmp_path: Path,
) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full", "client_traffic": False},
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    # Disabling client routing suppresses the broad client-subnet selector
    # and its NAT, but not symmetric replies for local services accepted
    # through the active upstream.
    assert (
        f"ip saddr {config.server.ipv4_network} counter "
        f"meta mark set {config.routing.fwmark}" not in rendered
    )
    assert (
        f'meta mark {config.routing.fwmark} oifname != "oc-middle0" counter drop'
        in rendered
    )
    assert (
        f'ip saddr {config.server.ipv4_network} meta mark {config.routing.fwmark} '
        'oifname "oc-middle0" masquerade' not in rendered
    )
    # Plain NAT still applies -- clients aren't left without connectivity.
    assert f"ip saddr {config.server.ipv4_network} masquerade" in rendered


def test_client_traffic_off_does_not_affect_host_split_mode(tmp_path: Path) -> None:
    # host_mode: split uses its own dedicated routing.host_split
    # routes/domains and host_split_v4/v6 set -- entirely independent of
    # client_traffic, which only ever gates the default target's own
    # client-facing marking.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "client_traffic": False,
                "host_traffic": True,
                "host_mode": "split",
                "host_split": {"routes": ["192.168.25.0/24"]},
            },
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "192.168.25.0/24" in rendered
    assert (
        f"ct direction original ip daddr != {config.server.ipv4_network} "
        f"ip daddr @host_split_v4_static counter meta mark set {config.routing.fwmark}"
        in rendered
    )
    assert (
        f"ct direction original ip daddr != {config.server.ipv4_network} "
        f"ip daddr @host_split_v4_dynamic counter meta mark set {config.routing.fwmark}"
        in rendered
    )
    # No client-facing prerouting mark for the default target.
    assert "\n    ip daddr @split_v4_static counter meta mark set" not in rendered
    assert "\n    ip daddr @split_v4_dynamic counter meta mark set" not in rendered


def test_host_split_mode_uses_its_own_list_not_the_clients(tmp_path: Path) -> None:
    # Regression test: host_mode: split used to reuse the client-facing
    # default target's own split_v4/v6 set (routing.split.routes/domains)
    # -- an admin routing different subnets for host vs. clients would
    # silently get the client's list applied to the host too. Now they're
    # fully separate lists/sets.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "host_traffic": True,
                "host_mode": "split",
                "split": {"routes": ["10.1.0.0/16"]},
                "host_split": {"routes": ["10.2.0.0/16"]},
            },
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "set split_v4_static" in rendered
    assert "10.1.0.0/16" in rendered
    assert "set host_split_v4_static" in rendered
    assert "10.2.0.0/16" in rendered
    # The client set must not also contain the host's own CIDR (proves the
    # two lists aren't merged into one set).
    set_split_section = rendered.split("set split_v4_static {")[1].split("}")[0]
    assert "10.2.0.0/16" not in set_split_section


def test_host_traffic_split_mode_adds_output_marking_and_killswitch(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {
                "mode": "split",
                "host_traffic": True,
                "host_mode": "split",
                "host_split": {"routes": ["192.168.25.0/24"]},
            },
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "type route hook output priority mangle" in rendered
    # Connections accepted from an upstream to a local service retain that
    # target in conntrack; reply packets restore its fwmark before routing.
    assert "type filter hook input priority mangle" in rendered
    assert (
        'iifname "oc-middle0" ct direction original ct state new counter '
        f"ct mark set {config.routing.fwmark}" in rendered
    )
    assert (
        f"ct direction reply ip daddr != {config.server.ipv4_network} "
        f"ct mark {config.routing.fwmark} counter meta mark set {config.routing.fwmark}"
        in rendered
    )
    assert (
        f"ct direction original ip daddr != {config.server.ipv4_network} "
        f"ip daddr @host_split_v4_static counter meta mark set {config.routing.fwmark}"
        in rendered
    )
    assert (
        f"ct direction original ip daddr != {config.server.ipv4_network} "
        f"ip daddr @host_split_v4_dynamic counter meta mark set {config.routing.fwmark}"
        in rendered
    )
    # The host kill-switch must be a postrouting chain: an output-hook
    # filter chain shares nf_hook_state with the route chain and still sees
    # the pre-reroute oifname, dropping ALL marked host traffic.
    assert "type filter hook postrouting priority filter" in rendered
    assert "type filter hook output" not in rendered
    assert 'oifname "lo" accept' in rendered
    # Host-originated packets keep their uplink source address through the
    # fwmark re-route; without this masquerade replies never come back.
    assert (
        f'meta mark {config.routing.fwmark} oifname "oc-middle0" counter masquerade'
        in rendered
    )


def test_active_upstream_routes_local_service_replies_without_host_routing(
    tmp_path: Path,
) -> None:
    # Symmetric replies are transport correctness, not host-originated route
    # selection: a service reached through the active tunnel must answer via
    # that tunnel even when routing.host_traffic is deliberately disabled.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"client_traffic": False, "host_traffic": False},
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert (
        'iifname "oc-middle0" ct direction original ct state new counter '
        f"ct mark set {config.routing.fwmark}" in rendered
    )
    assert (
        f"ct direction reply ip daddr != {config.server.ipv4_network} "
        f"ct mark {config.routing.fwmark} counter meta mark set {config.routing.fwmark}"
        in rendered
    )
    assert (
        f'meta mark {config.routing.fwmark} oifname != "oc-middle0" counter drop'
        in rendered
    )
    # Both packet paths explicitly protect the VPN server subnet: forwarded
    # replies are cleared in prerouting and local replies in output.
    protected_clear = (
        f"ip daddr {config.server.ipv4_network} counter meta mark set 0"
    )
    assert rendered.count(protected_clear) == 3
    assert "type filter hook prerouting priority -50" in rendered
    assert "ct direction reply ct status snat counter meta mark set 0" in rendered
    # No ordinary host-originated packet is selected for the tunnel.
    assert "ct direction original ip daddr" not in rendered


def test_host_traffic_output_chain_absent_by_default(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "split", "split": {"routes": ["192.168.25.0/24"]}},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "hook output" not in rendered
    assert "hook input" not in rendered


def test_host_traffic_works_independent_of_client_mode(tmp_path: Path) -> None:
    # Regression test: host_traffic used to be hard-wired to only work
    # alongside client mode=split. It's independent now -- host_mode picks
    # full/split for the host's own traffic on its own terms.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full", "host_traffic": True, "host_mode": "split"},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "hook output" in rendered


def test_host_mode_full_marks_all_host_traffic_unconditionally(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full", "host_traffic": True, "host_mode": "full"},
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert (
        f"ct direction original ip daddr != {config.server.ipv4_network} "
        f"counter meta mark set {config.routing.fwmark}" in rendered
    )
    assert f"ct direction original ip6 counter meta mark set {config.routing.fwmark}" in rendered
    # Full mode must not also emit the split-set-scoped rule.
    assert "@split_v4_static counter meta mark" not in rendered
    assert "@split_v4_dynamic counter meta mark" not in rendered


def test_nft_show_guides_apply_when_managed_tables_are_needed() -> None:
    result = NftablesService(
        AppConfig.model_validate({"routing": {"mode": "split"}}),
        runner=MissingNftRunner(),
    ).show()

    assert result.returncode == 0
    assert "not installed yet" in result.stdout
    assert "korctl nft apply" in result.stdout
    assert result.stderr == ""


def test_nft_apply_explains_successful_empty_nft_output(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "full"},
        }
    )

    results = NftablesService(config, runner=SuccessfulNftRunner()).apply()

    assert results[-1].returncode == 0
    assert "Applied kornode-owned nftables rules" in results[-1].stdout
    assert "masquerading" in results[-1].stdout


class ReadySchemaRunner(CommandRunner):
    """Fake `nft` that reports the live table already has exactly the given
    static/dynamic set names -- the schema-matches case that should make
    NftablesService take the surgical static-only refresh path instead of a
    full table recreate. `refresh_ok=False` simulates the refresh's own
    `nft -f` failing (e.g. the table was torn down between the readiness
    probe and the refresh itself), which should self-heal to a full
    recreate -- the full-recreate `nft -f` always succeeds here, since it's
    the fallback ground truth being tested against.
    """

    def __init__(self, set_names: frozenset[str], *, refresh_ok: bool = True) -> None:
        self.calls: list[list[str]] = []
        self._set_names = set_names
        self._refresh_ok = refresh_ok

    def run(self, argv: Sequence[str], **kwargs: object) -> CommandResult:
        del kwargs
        self.calls.append(list(argv))
        if tuple(argv[:4]) == ("nft", "-j", "list", "table"):
            payload = {"nftables": [{"set": {"name": name}} for name in sorted(self._set_names)]}
            return CommandResult(tuple(argv), 0, json.dumps(payload), "")
        if tuple(argv[:2]) == ("nft", "-f"):
            is_full_recreate = str(argv[2]).endswith("nftables.nft") and not str(
                argv[2]
            ).endswith("nftables-static-refresh.nft")
            ok = is_full_recreate or self._refresh_ok
            return CommandResult(tuple(argv), 0 if ok else 1, "", "" if ok else "flush failed")
        return CommandResult(tuple(argv), 0, "", "")


def _nft_f_calls(calls: list[list[str]]) -> list[list[str]]:
    return [call for call in calls if tuple(call[:2]) == ("nft", "-f")]


def _record_current_rules_fingerprint(config: AppConfig, runner: CommandRunner) -> None:
    # The rules are unchanged since the last full recreate: the surgical
    # refresh is only allowed in that state (see NftablesService._apply_ruleset).
    fingerprint = NftablesService(config, runner=runner)._rules_fingerprint(None)
    generated = config.system.generated_dir
    (generated / "nftables-rules.sha256").write_text(fingerprint + "\n", encoding="utf-8")


def test_nft_apply_uses_surgical_refresh_when_schema_already_matches(tmp_path: Path) -> None:
    # The common case: a routes/domains-only change (profile edit, pushed-
    # routes sync, panel Reload) with no change to which targets/host
    # routing exist -- the live table's schema already matches, so a
    # surgical *_static-only refresh is safe and preserves *_dynamic sets.
    config = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "routing": {"mode": "split"}}
    )
    expected = NftablesConfigRenderer().expected_set_names(config)
    runner = ReadySchemaRunner(expected)
    _record_current_rules_fingerprint(config, runner)

    NftablesService(config, runner=runner).apply()

    calls = _nft_f_calls(runner.calls)
    assert len(calls) == 1
    assert calls[0][2].endswith("nftables-static-refresh.nft")


def test_nft_apply_falls_back_to_full_recreate_when_schema_differs(tmp_path: Path) -> None:
    # A stale/mismatched schema (e.g. from before a profile was added, or
    # before this kornode version introduced the static/dynamic split at
    # all) must not take the surgical path -- only a full recreate can
    # correctly add the missing sets (and drop any now-orphaned ones).
    config = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "routing": {"mode": "split"}}
    )
    runner = ReadySchemaRunner(frozenset({"split_v4_static"}))

    NftablesService(config, runner=runner).apply()

    calls = _nft_f_calls(runner.calls)
    assert len(calls) == 1
    assert calls[0][2].endswith("nftables.nft")
    assert not calls[0][2].endswith("nftables-static-refresh.nft")


def test_nft_apply_self_heals_to_full_recreate_when_surgical_refresh_fails(
    tmp_path: Path,
) -> None:
    config = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "routing": {"mode": "split"}}
    )
    expected = NftablesConfigRenderer().expected_set_names(config)
    runner = ReadySchemaRunner(expected, refresh_ok=False)
    _record_current_rules_fingerprint(config, runner)

    results = NftablesService(config, runner=runner).apply()

    calls = _nft_f_calls(runner.calls)
    assert len(calls) == 2
    assert calls[0][2].endswith("nftables-static-refresh.nft")
    assert calls[1][2].endswith("nftables.nft")
    assert results[0].ok


class RecordingRunner(CommandRunner):
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(  # type: ignore[override]
        self,
        argv: Sequence[str],
        **kwargs: object,
    ) -> CommandResult:
        self.calls.append(list(argv))
        return CommandResult(tuple(argv), 0, "", "", bool(kwargs.get("dry_run", False)))


def test_nft_apply_reasserts_policy_routing_when_upstream_active(tmp_path: Path) -> None:
    # Regression test: the fwmark rule/route used to be installed only by
    # the upstream connect/switch lifecycle, so a rules refresh (panel
    # Reload, korctl nft apply) after the rule went missing left marked
    # traffic hitting the kill-switch -- local sockets got EPERM even with
    # the tunnel up.
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "split"},
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        }
    )
    runner = RecordingRunner()

    NftablesService(config, runner=runner).apply()

    assert [
        "ip", "rule", "add", "fwmark", config.routing.fwmark,
        "table", "1201", "priority", "100",
    ] in runner.calls
    assert [
        "ip", "route", "replace", "default", "dev", "oc-middle0", "table", "1201",
    ] in runner.calls


def test_nft_apply_never_uses_literal_auto_as_policy_route_device(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"client_policy": "off", "main_interface": "auto"},
            "upstream": {"enabled": True, "profiles": [_upstream_profile()]},
        }
    )
    runner = RecordingRunner()

    NftablesService(config, runner=runner).apply()

    route_calls = [call for call in runner.calls if call[:3] == ["ip", "route", "replace"]]
    assert [
        "ip",
        "route",
        "replace",
        "default",
        "dev",
        "oc-middle0",
        "table",
        "1201",
    ] in route_calls
    assert not any(call[4:6] == ["dev", "auto"] for call in route_calls)


def test_nft_apply_reasserts_named_target_policy_routing_too(tmp_path: Path) -> None:
    # Regression test: _reassert_policy_routing() used to only reassert the
    # DEFAULT target's ip rule/route on a manual reload (panel Reload,
    # korctl nft apply), leaving named per-profile targets stale until the
    # watchdog's next tick -- so a named target's traffic could hit its own
    # kill-switch after a reload even though its tunnel was already up.
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "full", "fwmark": "0x0c01", "table_id": 1201},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _upstream_profile(),
                    _profile_with_target(
                        "finance", interface="oc-finance", routes=["10.50.0.0/16"]
                    ),
                ],
            },
        }
    )
    runner = RecordingRunner()

    NftablesService(config, runner=runner).apply()

    # finance is the 2nd configured profile -> offset 2 -> fwmark 0x0c03,
    # table 1203 (see UpstreamConfig.profile_routing_offset()).
    assert [
        "ip", "rule", "add", "fwmark", "0x0c03", "table", "1203", "priority", "100",
    ] in runner.calls
    assert [
        "ip", "route", "replace", "default", "dev", "oc-finance", "table", "1203",
    ] in runner.calls


def test_nft_apply_reasserts_named_targets_even_without_a_selected_profile(
    tmp_path: Path,
) -> None:
    # Regression test: the old early-return ("no selected profile -> return
    # [] entirely") skipped named targets too, even though a named target's
    # routing is independent of which profile (if any) is active/selected.
    # The profile is disabled so selected_profile() falls back to None
    # (there's no other enabled profile to pick) while its named target
    # (unconditional kill-switch, see RoutingService.list_targets()) still
    # needs its own routing reasserted.
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "full", "fwmark": "0x0c01", "table_id": 1201},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance",
                        interface="oc-finance",
                        routes=["10.50.0.0/16"],
                        enabled=False,
                    ),
                ],
            },
        }
    )
    runner = RecordingRunner()

    assert config.upstream.selected_profile() is None
    NftablesService(config, runner=runner).apply()

    assert [
        "ip", "route", "replace", "default", "dev", "oc-finance", "table", "1202",
    ] in runner.calls


def test_nft_apply_cleans_up_target_that_disappeared(tmp_path: Path) -> None:
    # Regression test: a profile's routes/domains being cleared (or the
    # profile removed entirely) used to leave its old fwmark/table/ip-rule
    # installed forever -- RoutingService.list_targets() only ever describes
    # what SHOULD exist right now, with no memory of the previous apply.
    base = {
        "system": {"generated_dir": tmp_path},
        "routing": {"mode": "full", "fwmark": "0x0c01", "table_id": 1201},
    }
    with_target = AppConfig.model_validate(
        {
            **base,
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance", interface="oc-finance", routes=["10.50.0.0/16"]
                    ),
                ],
            },
        }
    )
    NftablesService(with_target, runner=RecordingRunner()).apply()

    # finance keeps existing but loses its own routes/domains -> its named
    # target (fwmark 0x0c02 / table 1202, offset 1 as the only profile) no
    # longer exists.
    without_target = AppConfig.model_validate(
        {
            **base,
            "upstream": {
                "enabled": True,
                "profiles": [_profile_with_target("finance", interface="oc-finance")],
            },
        }
    )
    runner = RecordingRunner()

    NftablesService(without_target, runner=runner).apply()

    assert [
        "ip", "rule", "del", "fwmark", "0x0c02", "table", "1202", "priority", "100",
    ] in runner.calls
    assert ["ip", "route", "flush", "table", "1202"] in runner.calls


def test_nft_apply_does_not_clean_up_targets_still_present(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "full", "fwmark": "0x0c01", "table_id": 1201},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance", interface="oc-finance", routes=["10.50.0.0/16"]
                    ),
                ],
            },
        }
    )
    NftablesService(config, runner=RecordingRunner()).apply()
    runner = RecordingRunner()

    NftablesService(config, runner=runner).apply()

    # "ip route flush table <N>" only ever comes from cleanup(); a normal
    # reassert only ever does "ip rule del" (as part of apply()'s own
    # idempotent delete-then-add) and "ip route replace", never a flush --
    # so its absence here proves no stale-target cleanup ran for a target
    # that's still present.
    assert not [call for call in runner.calls if call[:3] == ["ip", "route", "flush"]]


def test_nft_apply_leaves_routing_alone_without_upstream(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "split"},
        }
    )
    runner = RecordingRunner()

    NftablesService(config, runner=runner).apply()

    assert not [call for call in runner.calls if call[0] == "ip"]


def test_nft_apply_returns_crash_as_command_result(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "full"},
        }
    )

    results = NftablesService(config, runner=CrashingNftRunner()).apply()

    assert results[-1].returncode == -11
    assert "signal 11" in results[-1].stderr
    assert "inside the container" in results[-1].stderr


def _profile_with_target(name: str, **overrides: object) -> dict[str, object]:
    return {
        "name": name,
        "server": f"{name}.example.com",
        "auth_type": "password",
        "username": "user",
        **overrides,
    }


def test_profile_with_routes_gets_its_own_fwmark_table_and_killswitch(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full", "fwmark": "0x0c01"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target("primary"),
                    _profile_with_target(
                        "finance", interface="oc-finance", routes=["10.50.0.0/16"]
                    ),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    # A distinct set, fwmark and kill-switch drop for the named target.
    # finance is the 2nd configured profile (primary is 1st), so its
    # routing offset is 2 (derived from list position, not from a count of
    # profiles with routes) -> fwmark 0x0c01 + 2 = 0x0c03.
    assert "set split_v4_finance_static" in rendered
    assert "10.50.0.0/16" in rendered
    assert "ip daddr @split_v4_finance_static counter meta mark set 0x0c03" in rendered
    assert "ip daddr @split_v4_finance_dynamic counter meta mark set 0x0c03" in rendered
    assert 'meta mark 0x0c03 oifname != "oc-finance" counter drop' in rendered
    assert (
        f"ip saddr {config.server.ipv4_network} meta mark 0x0c03 "
        'oifname "oc-finance" masquerade' in rendered
    )
    # The default target (mode=full, no explicit routes) is untouched and
    # keeps its own fwmark.
    assert f"ip saddr {config.server.ipv4_network} counter meta mark set 0x0c01" in rendered


def test_two_targeted_profiles_get_distinct_fwmarks_and_tables(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full", "fwmark": "0x0c01", "table_id": 1201},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target("a", interface="oc-a", routes=["10.1.0.0/16"]),
                    _profile_with_target("b", interface="oc-b", routes=["10.2.0.0/16"]),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "ip daddr @split_v4_a_static counter meta mark set 0x0c02" in rendered
    assert "ip daddr @split_v4_b_static counter meta mark set 0x0c03" in rendered
    assert 'meta mark 0x0c02 oifname != "oc-a" counter drop' in rendered
    assert 'meta mark 0x0c03 oifname != "oc-b" counter drop' in rendered


def test_targeted_profile_routes_ignored_entirely_without_upstream_enabled(
    tmp_path: Path,
) -> None:
    # Regression test: targeting a specific profile is meaningless if
    # upstream isn't even turned on -- the target (and its set/fwmark/rules)
    # must not be rendered at all, keeping "upstream disabled -> everything
    # is inert" true without a maze of per-target fallback branches.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {
                "enabled": False,
                "profiles": [
                    _profile_with_target("finance", routes=["10.50.0.0/16"]),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "split_v4_finance" not in rendered
    assert "10.50.0.0/16" not in rendered
    # Clients still get plain NAT (Phase 1 behavior), unaffected.
    assert f"ip saddr {config.server.ipv4_network} masquerade" in rendered


def test_targeted_profile_killswitch_applies_even_when_that_profile_is_disabled(
    tmp_path: Path,
) -> None:
    # A disabled *targeted* profile still blocks its assigned traffic rather
    # than silently leaking it out the host's own connection -- upstream
    # itself is on, so this specific channel being down is exactly what the
    # kill-switch exists for.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance", interface="oc-finance", enabled=False, routes=["10.50.0.0/16"]
                    ),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert 'meta mark 0x0c02 oifname != "oc-finance" counter drop' in rendered


def test_targeted_profile_mark_overrides_default_full_mode_for_its_own_routes(
    tmp_path: Path,
) -> None:
    # Rendering order matters: the default's blanket full-mode mark must be
    # written first so a named target's more specific rule (for the same
    # traffic) is written after and wins via "meta mark set" overwrite.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full", "fwmark": "0x0c01"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target("primary"),
                    _profile_with_target(
                        "finance", interface="oc-finance", routes=["10.50.0.0/16"]
                    ),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    # finance is the 2nd configured profile -> offset 2 -> fwmark 0x0c03.
    default_rule_pos = rendered.index("counter meta mark set 0x0c01")
    finance_rule_pos = rendered.index("counter meta mark set 0x0c03")
    assert default_rule_pos < finance_rule_pos


def test_profile_host_routing_gets_its_own_set_marking_and_killswitch(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full", "fwmark": "0x0c01"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance",
                        interface="oc-finance",
                        route_clients_enabled=False,
                        route_host_enabled=True,
                        host_routes=["10.90.0.0/16"],
                    ),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    # finance is the 1st (only) profile -> offset 1 -> fwmark 0x0c02.
    assert "set host_v4_finance_static" in rendered
    assert (
        'iifname "oc-finance" ct direction original ct state new counter '
        "ct mark set 0x0c02" in rendered
    )
    assert (
        f"ct direction reply ip daddr != {config.server.ipv4_network} "
        "ct mark 0x0c02 counter meta mark set 0x0c02" in rendered
    )
    assert "10.90.0.0/16" in rendered
    assert (
        f"ct direction original ip daddr != {config.server.ipv4_network} "
        "ip daddr @host_v4_finance_static counter meta mark set 0x0c02" in rendered
    )
    assert (
        f"ct direction original ip daddr != {config.server.ipv4_network} "
        "ip daddr @host_v4_finance_dynamic counter meta mark set 0x0c02" in rendered
    )
    assert 'meta mark 0x0c02 oifname != "oc-finance" counter drop' in rendered
    assert 'meta mark 0x0c02 oifname "oc-finance" counter masquerade' in rendered
    # This profile has no client routing enabled: its client-scoped set is
    # still declared (every target gets one) but stays empty -- no elements
    # line, so it never actually matches any client traffic.
    assert (
        "set split_v4_finance_static {\n    type ipv4_addr\n    flags interval\n    auto-merge\n  }"
        in rendered
    )


def test_profile_host_routing_independent_of_global_host_traffic(tmp_path: Path) -> None:
    # Regression: per-profile host routing must work even with the global
    # routing.host_traffic switch off -- it's a separate, profile-scoped
    # decision, not a special case of the default target's host marking.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance",
                        route_host_enabled=True,
                        host_routes=["10.90.0.0/16"],
                    ),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "type route hook output priority mangle" in rendered
    assert "host_v4_finance" in rendered


def test_profile_host_routing_off_by_default_even_with_lists_populated(tmp_path: Path) -> None:
    # host_routes/host_domains alone don't activate anything -- the toggle
    # (route_host_enabled) must also be on, mirroring how routing.host_traffic
    # gates routing.host_mode at the global level.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance",
                        route_clients_enabled=False,
                        host_routes=["10.90.0.0/16"],
                    ),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    assert "host_v4_finance" not in rendered
    assert "10.90.0.0/16" not in rendered


def test_profile_client_routing_off_suppresses_client_set_even_with_routes_populated(
    tmp_path: Path,
) -> None:
    # route_clients_enabled off must ignore `routes`/`domains` (progressive
    # disclosure: the admin can keep a list drafted without it taking
    # effect), while host routing on the same profile keeps working.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "routing": {"mode": "full"},
            "upstream": {
                "enabled": True,
                "profiles": [
                    _profile_with_target(
                        "finance",
                        route_clients_enabled=False,
                        routes=["10.50.0.0/16"],
                        route_host_enabled=True,
                        host_routes=["10.90.0.0/16"],
                    ),
                ],
            },
        },
        environ={},
    )

    rendered = NftablesConfigRenderer().render(config)

    # The client set is declared but empty -- route_clients_enabled=False
    # means the CIDR never lands in its elements list.
    assert "10.50.0.0/16" not in rendered
    assert "host_v4_finance" in rendered
    assert "10.90.0.0/16" in rendered


def test_list_targets_returns_only_default_without_any_profiles(tmp_path: Path) -> None:
    from kornode.services.routing import RoutingService

    config = load_config(tmp_path / "missing.yaml", environ={})

    targets = RoutingService(config).list_targets(default_interface="auto")

    assert [target.name for target in targets] == ["default"]


class DockerUserChainRunner(CommandRunner):
    """Simulates a Docker-managed host with a DOCKER-USER chain, optionally
    pre-populated with the compat rules (with fake handles), for testing
    NftablesService's insert/idempotency/removal logic against realistic
    `nft [-a] list chain ...` output shapes."""

    def __init__(self, *, prepopulated: bool = False) -> None:
        self.calls: list[list[str]] = []
        self._prepopulated = prepopulated

    def run(self, argv: Sequence[str], **kwargs: object) -> CommandResult:
        del kwargs
        self.calls.append(list(argv))
        if tuple(argv[:3]) == ("nft", "list", "chain"):
            body = (
                (
                    "\t\tip saddr 10.10.10.0/24 accept # handle 21\n"
                    "\t\tip daddr 10.10.10.0/24 accept # handle 22\n"
                )
                if self._prepopulated
                else ""
            )
            return CommandResult(tuple(argv), 0, f"table ip filter {{\n{body}}}\n", "")
        if tuple(argv[:3]) == ("nft", "-a", "list"):
            body = (
                (
                    "\t\tip saddr 10.10.10.0/24 accept # handle 21\n"
                    "\t\tip daddr 10.10.10.0/24 accept # handle 22\n"
                )
                if self._prepopulated
                else ""
            )
            return CommandResult(tuple(argv), 0, f"table ip filter {{\n{body}}}\n", "")
        return CommandResult(tuple(argv), 0, "", "")


def test_nft_apply_inserts_docker_user_compat_rules_when_chain_present(
    tmp_path: Path,
) -> None:
    # Regression test: Docker's own `ip filter` FORWARD chain (recent
    # Docker/Moby releases) defaults to policy drop and only accepts
    # docker0-related traffic -- under network_mode: host, the VPN client's
    # forwarded traffic is unrelated to docker0 and falls through that drop
    # policy regardless of kornode's own (separate table) rules. Without
    # this compat shim, VPN clients connect successfully but get no network
    # access at all through the tunnel.
    config = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "server": {"ipv4_network": "10.10.10.0/24"}}
    )
    runner = DockerUserChainRunner(prepopulated=False)

    NftablesService(config, runner=runner).apply()

    assert [
        "nft", "insert", "rule", "ip", "filter", "DOCKER-USER",
        "ip", "saddr", "10.10.10.0/24", "accept",
    ] in runner.calls
    assert [
        "nft", "insert", "rule", "ip", "filter", "DOCKER-USER",
        "ip", "daddr", "10.10.10.0/24", "accept",
    ] in runner.calls


def test_nft_apply_docker_user_compat_is_idempotent(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "server": {"ipv4_network": "10.10.10.0/24"}}
    )
    runner = DockerUserChainRunner(prepopulated=True)

    NftablesService(config, runner=runner).apply()

    assert not [call for call in runner.calls if call[:2] == ["nft", "insert"]]


def test_nft_apply_docker_user_compat_noop_without_docker(tmp_path: Path) -> None:
    config = AppConfig.model_validate({"system": {"generated_dir": tmp_path}})
    runner = MissingNftRunner()

    # Must not raise even though every "nft list chain ..." check fails --
    # this is a compatibility shim for a Docker-managed host, not a
    # kornode requirement.
    NftablesService(config, runner=runner).apply()


def test_nft_cleanup_removes_docker_user_compat_rules_by_handle(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "server": {"ipv4_network": "10.10.10.0/24"}}
    )
    runner = DockerUserChainRunner(prepopulated=True)

    NftablesService(config, runner=runner).cleanup()

    assert [
        "nft", "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", "21",
    ] in runner.calls
    assert [
        "nft", "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", "22",
    ] in runner.calls


def test_nft_apply_full_recreates_when_rules_changed_under_matching_schema(
    tmp_path: Path,
) -> None:
    # Regression: moving server.ipv4_network left the set schema unchanged, so
    # the surgical refresh ran and the live NAT table kept the old subnet's
    # masquerade rules (client traffic left unmasqueraded). A stale NAT
    # fingerprint must force the full recreate that reloads the NAT table.
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "split"},
            "server": {"ipv4_network": "10.12.12.0/24"},
        }
    )
    expected = NftablesConfigRenderer().expected_set_names(config)
    runner = ReadySchemaRunner(expected)
    service = NftablesService(config, runner=runner)
    (tmp_path / "nftables-rules.sha256").write_text("stale-fingerprint\n", encoding="utf-8")

    service.apply()

    calls = _nft_f_calls(runner.calls)
    assert len(calls) == 1
    assert calls[0][2].endswith("nftables.nft")
    assert (tmp_path / "nftables-rules.sha256").read_text(encoding="utf-8").strip() == (
        service._rules_fingerprint(None)
    )


def test_nft_apply_keeps_surgical_refresh_when_rules_are_current(tmp_path: Path) -> None:
    config = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "split"},
            "server": {"ipv4_network": "10.12.12.0/24"},
        }
    )
    expected = NftablesConfigRenderer().expected_set_names(config)
    runner = ReadySchemaRunner(expected)
    service = NftablesService(config, runner=runner)
    (tmp_path / "nftables-rules.sha256").write_text(
        service._rules_fingerprint(None) + "\n", encoding="utf-8"
    )

    service.apply()

    calls = _nft_f_calls(runner.calls)
    assert len(calls) == 1
    assert calls[0][2].endswith("nftables-static-refresh.nft")


def test_nft_apply_full_recreates_when_only_marking_rules_changed(tmp_path: Path) -> None:
    # Regression: routing.client_traffic only changes the prerouting mark
    # rules, not any set name, so the surgical refresh kept the old marking
    # live. Recorded rules from before the change must force a full recreate.
    before = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "routing": {"mode": "full"}}
    )
    after = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "full", "client_traffic": False},
        }
    )
    expected = NftablesConfigRenderer().expected_set_names(after)
    runner = ReadySchemaRunner(expected)
    _record_current_rules_fingerprint(before, runner)

    NftablesService(after, runner=runner).apply()

    calls = _nft_f_calls(runner.calls)
    assert len(calls) == 1
    assert calls[0][2].endswith("nftables.nft")


def test_nft_apply_stays_surgical_when_only_route_lists_changed(tmp_path: Path) -> None:
    # Route/domain edits only change set elements, which the surgical refresh
    # is meant to handle -- they must not force a full recreate (that would
    # wipe the *_dynamic sets on every profile edit).
    before = AppConfig.model_validate(
        {"system": {"generated_dir": tmp_path}, "routing": {"mode": "split"}}
    )
    after = AppConfig.model_validate(
        {
            "system": {"generated_dir": tmp_path},
            "routing": {"mode": "split", "split": {"routes": ["198.51.100.0/24"]}},
        }
    )
    expected = NftablesConfigRenderer().expected_set_names(after)
    runner = ReadySchemaRunner(expected)
    _record_current_rules_fingerprint(before, runner)

    NftablesService(after, runner=runner).apply()

    calls = _nft_f_calls(runner.calls)
    assert len(calls) == 1
    assert calls[0][2].endswith("nftables-static-refresh.nft")
