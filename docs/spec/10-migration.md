# 10 — Migration from v1

## Config keys → egress (compiled automatically from P2, written back by `korctl config migrate` in P5)

| v1 | v2 |
| --- | --- |
| `upstream.enabled: false` | `clients → any via local` |
| `routing.client_policy: full` | `clients → any via upstream:<active_profile>` |
| `routing.client_policy: split` + `routing.split.{routes,domains,*_urls}` | set `split` + `clients → {set: split} via upstream:<active>`; `clients → any via local` |
| `routing.host_policy: full` | `host → any via upstream:<active>` (carrier exclusion is now automatic) |
| `routing.host_policy: split` + `routing.host_split` | set `host_split` + `host → {set: host_split} via upstream:<active>` |
| `profiles[].routes/domains/*_urls` (`route_clients_enabled`) | set `profile_<name>` + `clients → {set: profile_<name>} via upstream:<name>`, inserted **before** the default rules (v1 "named target wins") |
| `profiles[].route_host_enabled/host_routes/host_domains` | set `profile_<name>_host` + `host → {set: …} via upstream:<name>` before host defaults |
| `profiles[].accept_server_routes` | stays; pushed routes/domains extend set `profile_<name>_pushed` used by an implicit host rule, as in v1 |
| `profiles[].sync_url` between own nodes | replaced by the fabric; kept for third-party kornode upstreams |
| `routing.fwmark`, `routing.table_id`, `routing_offset` | removed; marks/tables allocated by the compiler (03) |
| `routing.main_interface` | becomes exit `local` interface hint |
| `server.ipv4_network`, `internal_dns.listen` | derived when `fabric.enabled` (01) |
| `routing.host_dns` | unchanged, points to the node service address |
| `upstream.active_profile` + switch/failover | v2 keeps "active profile" as an alias `upstream:active` resolved by the compiler; `switch` changes the alias target → reconciler re-applies; failover logic moves into the tunnel manager |

Translation is implemented once in `kornode.config.legacy` and covered by a
golden test per file in `examples/`: the compiled v2 state must route every
NL scenario the same way v1 did (where v1 was correct).

## Code removed in P5

- "last mark wins" ordering and `meta mark set 0` resets for the VPN subnet
  (replaced by implicit rules + first-match chain);
- per-target `*_static`/`*_dynamic` set families and
  `nftables-static-refresh.nft.j2` / `nftables-dynamic-refresh.nft.j2`;
- (removed earlier, in P2, per D-29: `NftablesService`, `PolicyRoutingService`,
  `SysctlService` and every kernel call in `UpstreamService`, `upstream watch`,
  `apply_server_routing_if_changed`);
- `RoutingTarget` / `list_targets()`.

## Nodes → agents

`korctl migrate-to-agent --out node3.json` on an existing v1 node exports
upstream profiles (secrets included, encrypted with a passphrase prompted on
the terminal), local users/groups, route/domain lists and host DNS settings.
On the hub: `korctl agent import node3.json` creates the agent, maps its
lists into its egress policy and prints an enroll token. The node is then
redeployed with `compose.agent.yaml` and enrolled. Old and new nodes can run
side by side during the transition: v1 nodes keep connecting as ordinary
clients to the hub.
