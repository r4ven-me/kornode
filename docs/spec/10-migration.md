# 10 — v1 removal (no migration)

There are no v1 installations to carry over (D-70, 2026-10-21), so v2 does
**not** translate, migrate or tolerate v1 configuration. A config that still
contains a removed key fails validation with an error naming the key and its
v2 replacement below; nothing is rewritten automatically. There is no
`korctl config migrate`, no `korctl migrate-to-agent` / `korctl agent import`
and no deprecation period.

Compatibility that **does** stay: hub ⇄ agent version skew within v2 — the
bundle `format` version, `control.min_agent_version` and the E2E-06 upgrade
test (spec 09). That is about upgrading v2, not about v1.

## Removed config keys and their v2 replacement

The table is a reference for writing v2 configs (README, `examples/`), not a
translation performed by code.

| Removed v1 key | Write instead (v2) |
| --- | --- |
| v1 local-bypass meaning of `upstream.enabled: false` | `clients → any via local`; the retained v2 flag disables upstream availability and fails closed for known references, never changes policy to local |
| `routing.client_policy: full` | `clients → any via upstream:<profile>` |
| `routing.client_policy: split` + `routing.split.{routes,domains,*_urls}` | set `split` + `clients → {set: split} via upstream:<profile>`; `clients → any via local` |
| `routing.host_policy: full` | `host → any via upstream:<profile>` (carrier exclusion is automatic) |
| `routing.host_policy: split` + `routing.host_split` | set + `host → {set: …} via upstream:<profile>` |
| `profiles[].routes/domains/*_urls` (`route_clients_enabled`) | set + `clients → {set: …} via upstream:<name>` placed before the default rules |
| `profiles[].route_host_enabled/host_routes/host_domains` | set + `host → {set: …} via upstream:<name>` |
| `profiles[].accept_server_routes` | stays (third-party upstreams); pushed routes/domains extend the profile's pushed set |
| `profiles[].sync_url` between own nodes | the fabric; kept only for third-party kornode upstreams |
| `routing.fwmark`, `routing.table_id`, `routing_offset` | nothing: marks/tables are allocated by the compiler (03) |
| `routing.main_interface` | exit `local` interface hint |
| v1 implicit redirection by `upstream.active_profile` + switch/failover | alias `upstream:active` resolved to a concrete profile identity by the compiler; the retained selection setting and runtime switch/failover change only this alias and converge the reconciler; named rules stay pinned |

`server.ipv4_network`, `internal_dns.listen` (derived from `node.id`, 01) and
`routing.host_dns` (points to the node service address) are not removed.

## Code removed (P5-03, together with P4-06 part 2)

- `kornode.config.legacy` and `legacy_policy`: `egress`/`sources`/`sets` are
  the only policy input on the hub;
- "last mark wins" ordering and `meta mark set 0` resets for the VPN subnet
  (replaced by implicit rules + first-match chain);
- per-target `*_static`/`*_dynamic` set families and
  `nftables-static-refresh.nft.j2` / `nftables-dynamic-refresh.nft.j2`;
- `RoutingTarget` / `list_targets()`;
- (removed earlier, in P2, per D-29: `NftablesService`, `PolicyRoutingService`,
  `SysctlService` and every kernel call in `UpstreamService`, `upstream watch`,
  `apply_server_routing_if_changed`).

Unit, netlab and e2e tests that encode v1 behaviour are deleted in the PR that
removes it, and the PR lists them.

## v2 dataplane hardening upgrade (A02)

The stable identity mark/conntrack-label scheme (02/03) deliberately does not
adopt established flows with old positional marks or missing identity labels.
Those flows break and must reconnect after the first apply. No global conntrack
flush is performed. Reordering policy or restarting a process no longer changes
a concrete exit's identity; removing an exit blocks its old flows, including a
historical collision with another exit's numeric mark. Current collisions or
more than 99 exits fail compilation without touching networking. Conntrack
label support is required; validate on a disposable netlab before deployment.

A failed routing update can leave the temporary fail-closed nft barrier in place
until the reconciler succeeds. Diagnose the recorded error, repair the input or
runtime prerequisite, and retry; do not remove the guard to restore bypass.

`connect --dry-run` constructs planned argv/path references only: no cert/key,
OpenConnect config, vpnc script, carrier state or upstream lock is materialized.
Real connect performs the private atomic writes before dialing.

## Nodes

New nodes are deployed with `compose.agent.yaml` and enrolled with
`kornode-agent enroll <token>` (spec 05/06). There is no export/import path
from a v1 node.

## Fabric toggle

There is none. `fabric.enabled` existed only because D-43 could not combine client
certificate or OIDC login with agents on one listener. Spike S-07 showed ocserv virtual
hosts do (D-71): the hub always runs the fabric, a hub without agents is a plain client
server, and the key is rejected as unknown. Addresses are always derived (client pool
`10.100.<id>.0/24`, spec 01).
