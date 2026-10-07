from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from kornode.config.models import AppConfig
from kornode.renderers.nftables import NftablesConfigRenderer
from kornode.services.command import CommandResult, CommandRunner
from kornode.services.files import FileManager
from kornode.services.policy_routing import PolicyRoutingService
from kornode.services.routing import RoutingTarget

_HANDLE_RE = re.compile(r"#\s*handle\s+(\d+)\s*$")
# Route/domain lists live in one-line `elements = { ... }` set declarations;
# the static refresh is the only thing that updates those, so they are left
# out of the rules fingerprint.
_SET_ELEMENTS_RE = re.compile(r"^\s*elements = \{.*\}\s*$\n?", re.MULTILINE)


class NftablesService:
    def __init__(
        self,
        config: AppConfig,
        runner: CommandRunner | None = None,
        files: FileManager | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or CommandRunner()
        self.files = files or FileManager()
        self.renderer = NftablesConfigRenderer()

    @property
    def filter_table(self) -> str:
        return f"{self.config.routing.nft_prefix}_filter"

    @property
    def nat_table(self) -> str:
        return f"{self.config.routing.nft_prefix}_nat"

    def render(self, outbound_interface: str | None = None) -> str:
        return self.renderer.render(self.config, outbound_interface)

    @property
    def _targets_state_path(self) -> Path:
        return self.config.system.generated_dir / ".routing_targets.json"

    def apply(
        self,
        *,
        dry_run: bool = False,
        outbound_interface: str | None = None,
    ) -> list[CommandResult]:
        targets, resolved_interface, _ = self.renderer.resolve_targets(
            self.config, outbound_interface
        )
        if dry_run:
            content = self.render(outbound_interface)
            target = self.renderer.target_path(self.config)
            return [
                CommandResult(("nft", "-f", str(target)), 0, content, "", True),
                *self._reassert_policy_routing(targets, resolved_interface, dry_run=True),
                *self._ensure_docker_forward_compat(dry_run=True),
            ]
        applied = self._apply_ruleset(outbound_interface)
        results = [applied]
        # Only touch routing after a successful ruleset load; a failed nft
        # apply should change nothing else.
        policy_results: list[CommandResult] = []
        if applied.ok:
            policy_results = self._reassert_policy_routing(targets, resolved_interface)
            policy_results.extend(self._cleanup_stale_targets(targets))
            policy_results.extend(self._ensure_docker_forward_compat())
        if applied.ok and not applied.stdout.strip():
            results[-1] = CommandResult(
                applied.argv,
                applied.returncode,
                (
                    "Applied kornode-owned nftables rules.\n"
                    f"- refreshed inet table: {self.filter_table}\n"
                    f"- refreshed ip NAT table: {self.nat_table}\n"
                    "- VPN client routing, split-routing marks and masquerading now match "
                    "the generated config."
                ),
                applied.stderr,
                applied.dry_run,
            )
        elif not applied.ok:
            results[-1] = self._explain_apply_failure(applied)
        results.extend(policy_results)
        return results

    def _apply_ruleset(self, outbound_interface: str | None) -> CommandResult:
        """Load or refresh the nftables ruleset.

        Two paths, chosen by whether the live table's set schema already
        matches what the current config expects (see _static_sets_ready):

        - not ready (first apply ever, or the schema changed -- a profile
          was added/removed, host routing was toggled, or an older
          kornode's table lacks the current *_static/*_dynamic split):
          full `delete table` + `nft -f` recreate. Necessary and harmless
          here -- the *_dynamic sets start out empty either way, and this
          also naturally drops any leftover set from a target that no
          longer exists.
        - ready: refresh ONLY the *_static sets in place (flush + re-add),
          leaving every *_dynamic set -- every IP DomainResolverService
          (services/domain_resolver.py) has resolved for a configured domain,
          on its own schedule -- completely untouched.

        The second path is what makes routine reloads (profile route/domain
        edits, host DNS toggles, periodic sync of upstream-pushed routes,
        panel Reload, `korctl nft apply`) safe for long-lived connections.
        Always doing a full recreate wipes the dynamic sets on every one of
        those, even though most of them don't actually change which
        targets/host-routing exist -- only their route/domain contents. A
        domain resolved by the last resolver cycle would then silently fall
        out of its split set the next time any of those fired, stop being
        marked, and fall through to the default route -- breaking any
        connection using it with no client-visible cause, until the next
        resolver cycle repopulates it.

        Self-healing: if the live table gets torn down by something outside
        this process's control between the readiness check and the refresh
        actually running, the refresh's `flush set` targets a set that no
        longer exists and fails -- falling back to a full recreate here
        means the very next call repairs itself instead of needing a manual
        intervention.
        """
        # The surgical refresh only reloads the *_static set elements. Any
        # other change -- masquerade rules (server.ipv4_network), client or
        # host marking (routing.client_policy / mode), kill-switch rules --
        # lives in chains and table definitions it never touches, so while
        # the rules fingerprint differs from the last full recreate the
        # refresh would leave stale rules live. Fall back to the full recreate.
        if self._static_sets_ready(outbound_interface) and self._rules_are_current(
            outbound_interface
        ):
            refresh_result = self._apply_static_refresh(outbound_interface)
            if refresh_result.ok:
                return refresh_result
        return self._apply_full_recreate(outbound_interface)

    def _rules_fingerprint(self, outbound_interface: str | None) -> str:
        content = _SET_ELEMENTS_RE.sub("", self.render(outbound_interface))
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _rules_fingerprint_path(self) -> Path:
        return self.config.system.generated_dir / "nftables-rules.sha256"

    def _rules_are_current(self, outbound_interface: str | None) -> bool:
        try:
            applied = self._rules_fingerprint_path().read_text(encoding="utf-8").strip()
        except OSError:
            return False
        return applied == self._rules_fingerprint(outbound_interface)

    def _static_sets_ready(self, outbound_interface: str | None) -> bool:
        """Whether the live nftables table already has exactly the
        *_static/*_dynamic sets the current config expects -- see
        _apply_ruleset. Any probe failure (table missing, `nft -j` not
        supported, unexpected output) is treated as not-ready so the caller
        falls back to the always-correct full recreate.
        """
        expected = self.renderer.expected_set_names(self.config, outbound_interface)
        probe = self.runner.run(
            ["nft", "-j", "list", "table", "inet", self.filter_table],
            check=False,
            timeout=10,
        )
        if not probe.ok:
            return False
        try:
            data = json.loads(probe.stdout)
        except ValueError:
            return False
        current = {
            item["set"]["name"]
            for item in data.get("nftables", [])
            if isinstance(item, dict) and "set" in item
        }
        return current == expected

    def _apply_static_refresh(self, outbound_interface: str | None) -> CommandResult:
        content = self.renderer.render_static_refresh(self.config, outbound_interface)
        target = self.renderer.static_refresh_path(self.config)
        self.files.atomic_write_text(target, content)
        return self.runner.run(["nft", "-f", str(target)], timeout=30, check=False)

    def _apply_full_recreate(self, outbound_interface: str | None) -> CommandResult:
        content = self.render(outbound_interface)
        target = self.renderer.target_path(self.config)
        # A single `nft -f` invocation is one atomic transaction (see the
        # rendered file's own add/delete/redefine comment): either the whole
        # ruleset replaces cleanly, or nothing changes and the previous,
        # still-working tables stay in place. Do not run separate `nft
        # delete table` commands beforehand -- that would leave a window
        # with no kill-switch/NAT at all if the reload then failed.
        self.files.atomic_write_text(target, content)
        result = self.runner.run(["nft", "-f", str(target)], timeout=30, check=False)
        if result.ok:
            # Remember which rules are live; see _rules_are_current().
            self.files.atomic_write_text(
                self._rules_fingerprint_path(), self._rules_fingerprint(outbound_interface) + "\n"
            )
        return result

    def _reassert_policy_routing(
        self,
        targets: list[RoutingTarget],
        default_interface: str,
        *,
        dry_run: bool = False,
    ) -> list[CommandResult]:
        """Re-install the fwmark rule/route for every routing target (the
        default bucket, plus any named per-profile target -- see
        RoutingService.list_targets()) alongside every rules refresh.

        Policy routing is normally managed by the upstream connect/switch/
        disconnect lifecycle; a rules refresh outside that lifecycle (panel
        Reload, `korctl nft apply`) used to leave a missing rule missing, so
        marked traffic hit the kill-switch (local sockets get EPERM) even
        with the tunnel up. This used to only reassert the *default* target,
        leaving named per-profile targets stale until the watchdog's next
        tick (or never, if that profile wasn't "connected" yet) -- now every
        target is covered. Applied unconditionally per target, not gated on
        whether that profile is currently detected as connected: harmless
        when a target's tunnel is down (the route add fails, marked traffic
        keeps hitting that target's kill-switch instead of leaking out
        unencrypted), and a manual reload should reassert every target's
        intended routing rather than skip ones whose live state it doesn't
        know.

        `targets`/`default_interface` are the caller's already-resolved
        values (from NftablesConfigRenderer.resolve_targets()) so this uses
        exactly what was just rendered, not a separately recomputed view.
        """
        if not self.config.upstream.enabled:
            return []
        selected = self.config.upstream.selected_profile()
        results: list[CommandResult] = []
        for target in targets:
            if target.name == "default" and selected is None:
                # Nothing selected/active at all -- there's no device for the
                # default bucket's route to point at. Named targets (below)
                # are independent of this and still get reasserted.
                continue
            results.extend(
                PolicyRoutingService(
                    self.config,
                    runner=self.runner,
                    fwmark=target.fwmark,
                    table_id=target.table_id,
                ).apply(target.interface, dry_run=dry_run)
            )
        return results

    def _cleanup_stale_targets(self, current_targets: list[RoutingTarget]) -> list[CommandResult]:
        """Clean up any routing target that no longer exists (a profile's
        `routes`/`domains` were cleared, its `routing_offset` override
        changed, or the profile itself was deleted) but still has a
        leftover `ip rule`/table installed from a previous apply.

        RoutingService.list_targets() only ever describes what SHOULD exist
        right now; without tracking what existed at the *previous* apply, a
        target that disappears between two applies leaks its old
        fwmark/table/ip-rule forever -- silently misrouting or leaking any
        traffic that still happens to carry that stale mark, and wasting a
        routing table entry that could later collide with a new target.
        """
        state_path = self._targets_state_path
        previous: dict[str, dict[str, object]] = {}
        if state_path.exists():
            try:
                previous = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                previous = {}
        current_names = {target.name for target in current_targets}
        results: list[CommandResult] = []
        for name, info in previous.items():
            if name in current_names:
                continue
            results.extend(
                PolicyRoutingService(
                    self.config,
                    runner=self.runner,
                    fwmark=str(info["fwmark"]),
                    table_id=int(str(info["table_id"])),
                ).cleanup()
            )
        self.files.atomic_write_text(
            state_path,
            json.dumps(
                {t.name: {"fwmark": t.fwmark, "table_id": t.table_id} for t in current_targets},
                indent=2,
            )
            + "\n",
        )
        return results

    def _docker_forward_compat_exprs(self) -> tuple[str, str]:
        network = self.config.server.ipv4_network
        return (f"ip saddr {network} accept", f"ip daddr {network} accept")

    def _ensure_docker_forward_compat(self, *, dry_run: bool = False) -> list[CommandResult]:
        """Keep VPN client traffic forwardable on a Docker-managed host.

        Docker maintains its own `ip filter` table with a forward-hook
        chain whose policy is drop (recent Docker/Moby releases harden the
        default FORWARD policy) and which only accepts docker0-related
        traffic. Every base chain registered at a given netfilter hook is
        evaluated independently -- an "accept" verdict in kornode's own
        `inet <prefix>_filter` forward chain does not exempt a packet from
        a separate DROP-policy chain in another table, so under
        `network_mode: host` the VPN client's forwarded traffic (to the
        host's uplink, or to an upstream/middle-server tunnel) is unrelated
        to docker0 and falls through Docker's own policy regardless of what
        kornode's tables allow -- the kill-switch drop rule still works
        exactly the same way, independently, on top of this.

        `DOCKER-USER` is the chain Docker itself documents as the place for
        this kind of external interoperability rule (evaluated before
        Docker's own rules, and never rewritten by Docker except at chain
        creation). Scoped to the VPN client subnet -- the same address range
        already used for the masquerade rule -- rather than a specific
        tunnel device name, since ocserv assigns a distinct per-session
        device (`kor-client0`, `kor-client1`, ...) that isn't known up
        front, and the same forwarding gap applies to upstream tunnel
        interfaces too.

        A silent no-op if Docker (or this exact chain) isn't present --
        this is a compatibility shim for a Docker-managed host's own
        firewall, not a kornode requirement.
        """
        check = self.runner.run(
            ["nft", "list", "chain", "ip", "filter", "DOCKER-USER"],
            check=False,
            timeout=10,
            dry_run=dry_run,
        )
        if dry_run:
            return [check]
        if not check.ok:
            return []
        results: list[CommandResult] = []
        for expr in self._docker_forward_compat_exprs():
            if expr in check.stdout:
                continue
            results.append(
                self.runner.run(
                    ["nft", "insert", "rule", "ip", "filter", "DOCKER-USER", *expr.split()],
                    check=False,
                    timeout=10,
                )
            )
        return results

    def _remove_docker_forward_compat(self, *, dry_run: bool = False) -> list[CommandResult]:
        check = self.runner.run(
            ["nft", "-a", "list", "chain", "ip", "filter", "DOCKER-USER"],
            check=False,
            timeout=10,
            dry_run=dry_run,
        )
        if dry_run:
            return [check]
        if not check.ok:
            return []
        exprs = self._docker_forward_compat_exprs()
        results: list[CommandResult] = []
        for line in check.stdout.splitlines():
            stripped = line.strip()
            if not any(stripped.startswith(expr) for expr in exprs):
                continue
            match = _HANDLE_RE.search(stripped)
            if not match:
                continue
            results.append(
                self.runner.run(
                    [
                        "nft",
                        "delete",
                        "rule",
                        "ip",
                        "filter",
                        "DOCKER-USER",
                        "handle",
                        match.group(1),
                    ],
                    check=False,
                    timeout=10,
                )
            )
        return results

    def _explain_apply_failure(self, result: CommandResult) -> CommandResult:
        signal_note = ""
        if result.returncode < 0:
            signal_number = abs(result.returncode)
            signal_note = (
                f"\nnft exited from signal {signal_number}. If this works on the host but "
                "fails in the container, the container nft userspace package may be "
                "incompatible with the host kernel/netfilter stack. Run the same command "
                "inside the container to verify it."
            )
        stderr = (
            result.stderr.rstrip()
            or "nft did not print an error message before failing."
        )
        return CommandResult(
            result.argv,
            result.returncode,
            result.stdout,
            f"{stderr}{signal_note}",
            result.dry_run,
        )

    def show(self) -> CommandResult:
        result = self.runner.run(
            ["nft", "list", "table", "inet", self.filter_table],
            timeout=30,
            check=False,
        )
        if result.ok or "no such file" not in result.stderr.lower():
            return result
        return CommandResult(
            result.argv,
            0,
            "project-owned nftables table is not installed yet; run korctl nft apply to create it",
            "",
            result.dry_run,
        )

    def cleanup(self, *, dry_run: bool = False) -> list[CommandResult]:
        return [
            self.runner.run(
                ["nft", "delete", "table", "inet", self.filter_table],
                check=False,
                dry_run=dry_run,
            ),
            self.runner.run(
                ["nft", "delete", "table", "ip", self.nat_table],
                check=False,
                dry_run=dry_run,
            ),
            *self._remove_docker_forward_compat(dry_run=dry_run),
        ]
