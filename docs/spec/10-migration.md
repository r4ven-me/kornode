# 10 — v1 removal (no migration)

There are no v1 installations to carry over (D-70, 2026-10-21), so v2 does
**not** translate, migrate or tolerate v1 configuration. A config that still
contains a removed key fails validation with an error naming the key and its
v2 replacement below; nothing is rewritten automatically. There is no
`korctl config migrate`, no `korctl migrate-to-agent` / `korctl agent import`
and no deprecation period.

Compatibility that **does** stay: hub ⇄ agent version skew within v2 — the
bundle `format` version, `control.min_agent_version` and the E2E-06 upgrade
test (spec 09). That is about upgrading v2, not about v1. In particular, the
wire label `kornode.bundle/v1` is the earlier **v2-platform** bundle format;
it is not the removed v1 routing/configuration model.

## v2 rename compatibility (D-84/D-85)

For one minor release, readers accept these old spellings; writers emit the
new spelling. Loading alone does not rewrite YAML or cached signed bytes.

| Existing state | Read behavior / new output |
| --- | --- |
| Hub YAML `fabric:` | Warn, normalize to `interlink:` before merging defaults; explicit domains, pools and reserved prefixes remain unchanged. A settings save writes the new section name. |
| `KORNODE_FABRIC__*` in process env or `.env` | Warn and normalize to `KORNODE_INTERLINK__*` semantics. Explicit and discovered `.env` files both work. |
| Rule `fabric` in `from`, `to`, `via` | Normalize to `interlink`, including stored registry policy. Both class aliases in one `from` list are a duplicate, not two classes. |
| Rule `via: exit:<n>`, role `exit` | D-84 behavior stays: normalize to `node:<n>` / `gateway`; registry migration 0004 and old `exit_sets` reports remain supported. |
| Agent `agent.yaml` section `fabric:` | Read as `interlink:`; save uses the new name. Existing hub SNI/pin values are not guessed or rewritten. |
| Signed `kornode.bundle/v1` | Verify the exact original bytes first, then normalize `fabric`, `fabric_address`, tunnel names and prefix kind in memory. Unseal against original pointer AAD before translating runtime secret lookup paths. Keep cache bytes/signatures unchanged. |
| Hub `certs/fabric.key` | If `interlink.key` is absent, atomically copy with mode 0600 and issue the renamed certificate using the same private key, preserving the public-key pin. Legacy key/certificate files remain available for recovery. An existing new key takes precedence and is never overwritten. |
| Stored encrypted transport camouflage | Keep the original storage AAD label `fabric-transport`; UI/wire renaming does not invalidate registry ciphertext. |

Conflicts are fail-closed: old and new section names in the same YAML mapping
are an error, even with equal or disjoint fields. Both env name families in the
combined process/`.env` environment are also an error (including an old name in
`.env` plus a new name in process env). Across independent YAML and env sources,
normal precedence applies after normalization: CLI overrides YAML, YAML overrides
env, process env overrides `.env` for the same variable, env overrides defaults.
Remove the old env family before switching names. Legacy bundle aliases are
likewise mutually exclusive at each object level; they cannot silently replace
new fields.

### Operational limits

- **SNI flag day:** the hub vhost becomes `interlink.<configured-domain>`.
  Existing enrolled agents/tokens and cached hub entries still naming
  `fabric.<domain>` are not transparently upgraded. Re-enroll agents against the
  updated hub and regenerate outstanding enrollment tokens. A preserved pin does
  not make the old vhost name valid. Upgrade agent images to 2.1.0 first; new
  bundles are v2 and impose at least that version regardless of a lower configured
  minimum. Higher configured minimum versions remain effective.
- The default DNS zone is now `kornode.lan`. An explicit `kornode.internal`
  remains explicit: change it deliberately if desired, updating dependent DNS
  names and clients. No mass DNS or bootstrap SNI rewrite is performed.
- Cached bundles are authenticated and normalized, not re-signed or rewritten.
  Replay protection stays enabled for newly received bundles. Cached revalidation
  skips only the high-water comparison and retains trust, identity, minimum
  version, unsealing and policy checks. The runtime currently accepts signed v1
  input on receipt as well as from cache; only the writer is v2-only.
- Existing `interlink.key` wins over a leftover `fabric.key`; if these are different
  identities, operators must reconcile pins explicitly. Legacy files are retained
  rather than deleted automatically. Certificate issuance still requires the
  runtime CA and `certtool`; unit tests simulate issuance and do not prove a live
  hub/agent cutover.
- This compatibility does not restore removed v1 routing keys, old Python module
  imports, or old `fabric` CLI/API paths. Use `korctl interlink` and `/api/interlink`.
  Historical documents under `docs/redesign/` intentionally keep their vocabulary.

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
| `profiles[].sync_url` between own nodes | the interlink; kept only for third-party kornode upstreams |
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

## Interlink toggle

There is none. `interlink.enabled` existed only because D-43 could not combine client
certificate or OIDC login with agents on one listener. Spike S-07 showed ocserv virtual
hosts do (D-71): the hub always runs the interlink, a hub without agents is a plain client
server, and the key is rejected as unknown. Addresses are always derived (client pool
`10.100.<id>.0/24`, spec 01).
