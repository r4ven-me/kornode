# Roadmap

## Current working-tree status — 2026-10-23

D-85 implementation and Nodes consolidation are complete locally (not committed or
published). Legacy config/env/cache readers and schema tests are included; signed
v1 secrets retain their original AAD. NL-05 abrupt upstream loss now passes twice
with ICMP rejection, no leakage and automatic recovery (D-87).

Validation: backend Ruff/strict mypy clean; **1334 passed / 104 opt-in skipped**;
render/parity passed; frontend **48 passed**, build passed, Playwright **44 passed**.
Netlab: **83 unique passed** across bounded runs, not one uninterrupted green run.

Final acceptance is **not complete**: the new continuous access-client E2E-06
fails even on the distinct compatible post-D85 baseline `15b87a6` (`upgrade
access-client forwarding did not recover automatically`). The last full VM run
was stopped at the owner's request; owned cleanup completed. GitHub publication
and workflow acceptance remain pending. See `tests/e2e/ACCEPTANCE-2026-10-23.md`.
Historical phase snapshots below are retained, not current acceptance claims.


Six phases. Each phase ships as its own release (`v2.0.0-pN` pre-releases, then
`v2.0.0`). Task IDs (`P<phase>-<nn>`) are referenced in PRs and commits.
"Done when" items are acceptance criteria and must be covered by automated
tests (unit, netlab or e2e — noted in brackets).

Dependency graph:

```
P0 ──┐
     ├─► P2 ──► P3 ──► P4 ──► P5
P1 ──┘           ▲
                 └── e2e VMs required from P3
```

P0 and P1 run in parallel. P1's netlab must exist before P2 merges.

---

## P0 — Stabilise the current version (1–2 weeks)

Goal: remove root causes 4–8 from `PLAN.ru.md` without changing the model.
Works on the existing codebase; later phases replace this code.

| ID | Task |
| --- | --- |
| P0-01 | `services/sysctl.py`: ensure `net.ipv4.ip_forward=1`, `net.ipv4.conf.all.src_valid_mark=1`, `rp_filter=2` on `all`, `default`, tunnel devices (`vpns*`, upstream interfaces). Applied at startup and on interface creation (vpnc hook, ocserv connect-script). Failure is fatal at startup with a clear message. |
| P0-02 | MSS clamping: `tcp flags syn / syn,rst tcp option maxseg size set rt mtu` in `forward` (both directions, tunnel devices) and in a new `output` rule for host traffic leaving tunnel devices. |
| P0-03 | `ip rule priority 90 lookup main suppress_prefixlength 0` before every fwmark rule; managed by `PolicyRoutingService` (add in `apply`/`ensure`, delete in `cleanup`). |
| P0-04 | `unreachable default metric 4096` in every policy table, installed with the table and never removed while the target exists. |
| P0-05 | Carrier exclusion: on connect, resolve `profile.server`, install `ip rule priority 95 to <addr>/32 lookup main` per resolved address; refresh on reconnect; remove on disconnect. |
| P0-06 | `korctl doctor` (+ `GET /api/diagnostics/doctor` + panel card): sysctl values, overlapping subnets (VPN pool vs host routes, docker networks, upstream-pushed routes), policy tables present and non-empty, nft userspace vs kernel version, carrier exclusions present. |
| P0-07 | Release notes describing the fixes and `doctor`. |

Done when:
- host agent in `full` reaches a docker-bridge service on the same node [netlab];
- tunnel bounce produces zero marked packets on the uplink [netlab, tcpdump];
- a 50 MB HTTPS download through a nested tunnel completes with 1500/1400 MTUs [netlab];
- `host_policy: full` no longer loops the carrier connection [netlab].

## P1 — Netlab: data-plane integration tests (1–2 weeks, parallel to P0)

| ID | Task |
| --- | --- |
| P1-01 | `tests/netlab/` framework: pytest fixtures creating namespaces, veths, bridges; teardown guaranteed; `@pytest.mark.netlab`; skipped without root. |
| P1-02 | Topology `inet`, `hub`, `node2`, `node3`, `cli3`, `ext` from `docs/spec/09-testing.md`, with HTTP echo and DNS in `inet`, Prometheus stub on hub, agent stub `:9100`. |
| P1-03 | Real ocserv + openconnect inside namespaces (built from the project's runtime image packages) for the transport-level scenarios. |
| P1-04 | Failure artefacts: on failure dump `ip rule`, `ip route show table all`, `nft list ruleset`, `ss -tanp`, kornode logs per namespace into the pytest report. |
| P1-05 | CI job `netlab` (ubuntu-latest, sudo). |
| P1-06 | Regression scenarios reproducing today's incidents; they must fail on `v1.1.5` and pass after P0. |

Done when: the suite runs in CI in under 10 minutes and P1-06 is red on
`v1.1.5`, green on P0.

## P2 — Addressing and the `kornode.net` core (3–4 weeks)

| ID | Task |
| --- | --- |
| P2-01 | Package `backend/kornode/net/` (`kornode.net`): no imports from `kornode.api`, `kornode.config.models` or FastAPI. Enforced by an import-linter test. |
| P2-02 | `net/state.py`: desired-state model (`Sysctl`, `Rule`, `Route`, `RouteTable`, `NftRuleset`) as frozen dataclasses; `diff(actual, desired) -> Plan`. See `docs/spec/04-netcore-reconciler.md`. |
| P2-03 | `net/kernel.py`: read actual state and apply a `Plan` via pyroute2 (rules, routes, sysctl via /proc) and one `nft -f` transaction. |
| P2-04 | `net/egress.py`: compiler `EgressPolicy -> DesiredState` per `docs/spec/02-egress-and-sources.md`, including dead-rule detection. |
| P2-05 | `net/reconciler.py`: loop with triggers (input change, netlink events, 10 s timer), debounce 200 ms, single-flight, metrics. |
| P2-06 | `net/explain.py`: `explain(src, dst, proto, port) -> Decision` using the compiled policy + `ip route get ... mark`. |
| P2-07 | Addressing: `node.id`, `fabric.*` config, derived pools/service address, overlap validator (`docs/spec/01-addressing.md`). |
| P2-08 | Hub integration: replace every direct kernel call site (`UpstreamService.connect/switch/recover`, `apply_server_routing_if_changed`, `NftablesService.apply`, watchdog `ensure`, `PolicyRoutingService`) with "update inputs + wake reconciler". Legacy routing keys are compiled into an equivalent egress policy (`docs/spec/10-migration.md`). |
| P2-09 | Supervisor program `reconciler` on the hub. |
| P2-10 | CLI/API/Web: `korctl net plan|apply|explain|doctor`, `/api/net/*`, panel "Network" page with the plan diff and an explain form. |
| P2-11 | Parity manifest `parity.yaml`, `tests/test_parity.py`, `make parity`, `data-capability` attributes in the panel (`docs/spec/08-interfaces-parity.md`). Backfill existing capabilities. |

Status 2026-10-13: P2-01…P2-11 done (hub cut-over included; decisions D-29…D-31).

Done when:
- `nft` and rule/route mutations exist in exactly one module [unit, grep test];
- a manually deleted policy route is restored in ≤ 2 s [netlab];
- every P0/P1 scenario stays green with legacy configs auto-compiled [netlab];
- `make parity` passes and fails when a CLI command lacks an API/UI side [unit].

## P3 — Control plane and agent (4–5 weeks)

| ID | Task |
| --- | --- |
| P3-01 | Registry: SQLite at `data_dir/registry.db`, schema + migrations (`docs/spec/05-control-plane.md`), repository layer, WAL mode, nightly `VACUUM INTO` snapshot. |
| P3-02 | Hub-side classes: three ocserv groups `clients`, `agents`, `enroll`; group configs rendered from the registry. |
| P3-03 | Enrollment: token issue/revoke, one-time `enroll` ocserv users restricted to the control API, CSR signing with the existing CA (`certtool`), cert renewal, revocation via CRL. **Done (service layer, D-45…D-47; API/CLI/panel surfaces in P3-08).** |
| P3-04 | Bundle compiler on the hub: per-agent JSON per `schemas/bundle.v1.schema.json`, Ed25519 signature, secret sealing, monotonic versions, stored history. **Done (D-48).** |
| P3-05 | Control API service (`kornode.control`): separate supervisor program bound to the hub fabric address, mTLS, long-poll, reports, command queue. Runs with `web.enabled: false`. **Done (D-49…D-52).** |
| P3-06 | Agent package `kornode_agent` + image `kornode-agent`: enroll, run loop, cache (3 versions), verify, apply-with-confirm, rollback, boot from cache, report, commands. Depends only on `kornode.net` + small deps. **Done (D-53, D-54; CLI beyond enroll/run/version is P3-07).** |
| P3-07 | Agent CLI `kornode-agent` (`docs/spec/06-agent.md`). **Done (D-55, D-59; `07301e8`; privileged netlab green).** |
| P3-08 | Hub management surfaces with parity: `korctl agent ...`, `/api/agents/*`, panel "Agents" section (list, detail, enroll dialog, bundle history/diff, commands, revoke), control status/signing-key rotation. **Done (D-56, D-59; `619d4d0`; `P3-08-REVIEW.md`; privileged netlab green).** |
| P3-09 | `korctl hub backup|restore` (+ API + panel), encrypted archive, restore test. **Done (D-57, D-59; `51c813b`; `P3-09-REVIEW.md`; netlab wipe → restore → reconnect without re-enroll and E2E-05 green). Restore is staged, never a live replacement.** |
| P3-10 | E2E harness on 4 VMs via self-hosted runner, workflow `e2e.yml` (`workflow_dispatch` only, protected branch; no `pull_request` trigger — D-59). **Done (D-58, D-62; `bfd4401` + `f51fa28`; `P3-10-REVIEW.md`, [runbook](../runbooks/vm-e2e.md)): real four-VM run 2026-10-19 from the hub over SSH — 9 passed / 13 skipped. Outstanding: run through GitHub Actions on the self-hosted runner (needs push), E2E-06 (needs previous image digests), flaky E2E-04 under investigation. Container-isolated P3 scope only; full client/P4 and production host-network coverage remain with P4.** |

Status 2026-10-19: P3-01…P3-10 done and committed locally on `redesign/p3-08-agent-management`; **nothing pushed**, CI (`netlab`, `e2e`) not yet run on GitHub runners. Evidence: two review rounds (2026-10-17, D-59; 2026-10-18, LOW/INFO findings left open in `P3-0X-REVIEW.md`); `make check` 1088 passed / 65 skipped, `make parity` 4 passed; privileged netlab on a VM 43 passed (full suite incl. P3-07/08/09 and D-32); four-VM E2E (D-62) 9 passed / 13 skipped — NL-10/11/12, E2E-01…05, partial NL-13; skipped: E2E-06 (no previous image digests) and 12 P4 cases in `tests/e2e/test_routed_fabric.py`. P2 tails closed (D-60). Agent image 396 MB, spec 06 target revised to ≤ 400 MB (D-61). Intermediate commits are not individually verified green — only HEAD is.

Done when:
- `kornode-agent enroll <token>` brings a fresh VM to `online` in ≤ 30 s [e2e];
- a registry change reaches the agent in ≤ 10 s [e2e];
- a bundle that cuts the fabric is rolled back in ≤ 70 s and reported [netlab + e2e];
- tampered bundle rejected, applied version unchanged [unit + netlab];
- hub stopped for 10 min: agent clients keep internet access; agent restart boots from cache [e2e] — covered by partial NL-13 (cache boot, external tunnel/ICMP traffic); client forwarding is verified with P4;
- revoked agent loses fabric and gets 403 from the control API [e2e];
- every new capability is in `parity.yaml` [unit].

## P4 — Routed fabric (3–4 weeks)

| ID | Task |
| --- | --- |
| P4-01 | Per-user configs for agents from the registry: `explicit-ipv4`, `iroute` for exported prefixes, `route` for all other fabric prefixes; `occtl reload` on change. **Done (D-63; spike S-03 failed, so the hub reconciler installs the prefix routes in main with `proto 77`); NL-01/NL-04 pass on the four VMs (D-65).** |
| P4-02 | **Done (D-63; verified, no-NAT test added; `dpd`/`keepalive` are hub-side only).** Agent exit `fabric` built from bundle routes (not from pushed routes); no masquerade toward fabric prefixes; transport settings (`transport`, `dpd`, `keepalive`, camouflage). |
| P4-03 | DNS: per-node zone `node<id>.<fabric.domain>` on each dnsmasq, hub authoritative for `<fabric.domain>`, agents forward the zone to the hub service address. Records managed in the registry (`docs/spec/07-fabric.md`). **Done (D-66): netlab `test_p4_dns` (real dnsmasq of hub and agent, agent zone with the hub resolver down), E2E NL-02 on the four VMs.** |
| P4-04 | Agent role `access`: local ocserv, users assigned on the hub, delivered as hashes, local auth works without the hub. **Done (D-67): netlab `test_p4_access` (real ocserv, delivered hashes), E2E NL-03 on the four VMs (client login, hub reached without NAT, exit through the node with NAT, new login with the hub stopped).** |
| P4-05 | Sources (`docs/spec/02-egress-and-sources.md`): wg-easy/Amnezia interfaces, export into the fabric, doctor checks for foreign NAT rules on the source subnet. **Done for agent-attached sources (D-68): export/hub routes/validation unit tests, doctor `foreign_nat_on_source` (nft + legacy iptables) as error, one `missing_source` warning, `docs/sources.md`, E2E NL-06 (client behind a source reaches the hub and is reached by the hub and agent-a, no NAT). Hub-attached sources move to P4-06 (the hub has no egress model yet); NL-05 (source client through `upstream:office`) stays blocked.** |
| S-07 | **Done (D-71): spike passed, fabric vhost + `fabric.enabled` removed.** Spike before P4-06 part 2 (D-70): client certificate and OIDC login together with the fabric on one 443/tcp via ocserv SNI virtual hosts (`docs/redesign/DECISIONS.md`, S-07). If it passes: `fabric.enabled` is removed, `auth.certificate`/`auth.oidc` are allowed with agents, specs 01/05/07 updated. |
| P4-06 | **Part 1 done (D-69): agent-originated traffic through `exit:<n>` (hub transit by source prefix, per-node table, exit-node masquerade, default-deny for agent traffic on the hub); netlab goldens, E2E-07. Part 2 done (D-72, `95b0b62`): hub egress model (`egress`/`sources`/`sets`), hub sources, hub `exit:<n>` for clients/sources (`to: any`; golden `hub_egress_exit`, netlab 69 passed). Part 3 (D-79): set/inline-destination exits for hub and agent rules (the agent reports the addresses it resolved, the hub matches source+destination in policy order; golden `hub_transit_set`). E2E `test_e2e_07_domain_exit_…` passes on four VMs. Still open: netlab NL-17, NL-05, NL-07…NL-09.** Exit via another node: `via: exit:<node>` for agent-originated traffic and for hub-originated traffic (hub clients, hub sources, hub host); per-exit-node table tracking the node's current `vpnsX`; role `exit` required on the target node. |
| P4-07 | Panel/CLI/API for fabric: topology view, per-node prefixes, DNS records, sources (parity). **Done (D-74):** `FabricService`, `korctl fabric`, `/api/fabric`, Fabric tab. |

Done when:
- hub Prometheus scrapes `agent-b:9100` by its real address [e2e];
- an `agent-a` client reaches a service in `agent-b`'s LAN through the hub, no NAT [netlab + e2e];
- an Amnezia client on `agent-b` exits via `upstream:office` (`ext`) and, with `ext` down, gets ICMP unreachable, never the uplink [netlab + e2e];
- a wg-easy source on the hub exits via an agent by list and in full mode; with the agent offline, listed traffic is rejected, not leaked [netlab NL-17/18 (`tests/netlab/test_p4_exit_set.py`, done 2026-10-22) + e2e E2E-07 (done)];
- after a 60 s link outage the fabric recovers without operator action [e2e];
- 5 % packet loss: 50 MB transfer across the fabric completes [netlab].

## P5 — Egress model GA and removal of legacy knobs (2–3 weeks)

| ID | Task |
| --- | --- |
| P5-01 | **Done (D-72, D-76).** Egress editor in the panel (ordered list, drag to reorder, dead-rule warnings, inline explain of the saved policy; JSON kept as an advanced tab) + `korctl egress ...` + API (parity). |
| ~~P5-02~~ | **Removed (D-70):** no `korctl config migrate` — there are no v1 installations; legacy keys are deleted, not translated. |
| P5-03 | **Done (D-73, `1fdf819`).** Remove legacy keys and code outright (D-70; together with P4-06 part 2): `routing.client_policy/host_policy/split/host_split`, per-profile route/host-route lists, `routing.fwmark/table_id`, `kornode.config.legacy`/`legacy_policy`, last-mark-wins, per-target static/dynamic set families, static/dynamic refresh templates (the `UpstreamService`/watchdog policy re-application already went in P2, D-29). Tests encoding v1 behaviour are deleted in the same PR. |
| ~~P5-04~~ | **Removed (D-70):** no `korctl migrate-to-agent` — nodes are deployed as agents and enrolled. |
| P5-05 | **Done: `examples/`, `config.example.yaml`, README, `docs/architecture.md`, `docs/networking.md` are v2 (`tests/test_examples.py`, `tests/test_docs_v2.py`).** Documentation rewrite: README, `docs/architecture.md`, `docs/networking.md`, `examples/` rewritten in the v2 format. |

Done when: every file in `examples/` is valid v2 config and passes the
full netlab + e2e suites; no legacy routing key remains in `models.py`;
hub ⇄ agent version compatibility (E2E-06) still holds.
