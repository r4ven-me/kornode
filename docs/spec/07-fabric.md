# 07 — Fabric

## Hub side (ocserv)

Three groups, rendered by the hub from the registry into
`config_per_group_dir`:

| Group | Auth | Address | Routes pushed | Notes |
| --- | --- | --- | --- | --- |
| `clients` | password / OTP / OIDC / cert (existing settings) | hub client pool `10.100.1.0/24` | per egress for `clients` (existing split/full semantics via `route`/`no-route`) | DNS = hub service address |
| `agents` | certificate, OU=`agents` (S-01, D-43) | `explicit-ipv4 10.99.0.<id>` per user (S-02) | `route` = every fabric prefix except the agent's own, plus `10.99.0.0/24` | `restrict-user-to-routes = false`, no DNS push (agents run their own resolver), `dpd`/`keepalive` from node transport settings |
| `enroll` | password, one-time users | `fabric.enroll_pool` (default `10.99.255.240/28`, outside `fabric.cidr`, D-42) | `10.99.0.1/32` only | `max-same-clients = 1`; restricted to `10.99.0.1:<control.port>` by a static nft rule set from `kornode.net`, not by ocserv `restrict-user-to-*` (D-44) |

Authentication on the shared listener (D-43): `auth = "plain[...]"` (clients,
enroll) with `enable-auth = "certificate"` (agents), `cert-user-oid = 2.5.4.3`,
`cert-group-oid = 2.5.4.11`. Because `enable-auth` lets any certificate of the
hub CA in without a password, the hub connect-script refuses sessions with an
empty group (OU-less certificates) and `agents` sessions whose user is not
`agent-<id>`. Password users without an explicit group are written with
`clients`. `auth.certificate.enabled` (client certificate + password) cannot be
combined with `fabric.enabled`. The hub side of an agent session is the first
host of the group network, i.e. the hub fabric address `10.99.0.1` (S-02).

Per-user config for each agent (`config_per_user_dir/agent-<id>`):

```
explicit-ipv4 = 10.99.0.3
```

Until P4-01, generated per-user files carry only `explicit-ipv4`; `iroute` and
per-agent route rendering are added with the routing reconciler work. Changes
rewrite group/user files atomically. ocserv reads `config-per-group` and
`config-per-user` when a session opens, so no ocserv reload is needed for these
files; existing sessions pick up changes on reconnect.

Hub egress for `from: fabric` (transit) is part of the hub's YAML policy;
default compiled rules: `fabric → fabric via fabric` (agent ↔ agent),
`fabric → any via local` only for agents that list `exit:1` in their policy
(the hub accepts exit traffic only from nodes whose bundle declares it).

## Agent side

- Exit `fabric` = `oc-hub0`; the bundle carries the full list of fabric
  prefixes; the compiler puts them in set `fabric_v4`.
- No masquerade toward fabric prefixes; the agent's own sources and pool keep
  their real addresses across the fabric.
- `transport`: `tcp` (default) passes `--no-dtls`; `auto` lets openconnect use
  DTLS when available.
- Defaults for fabric sessions: `dpd 20`, `keepalive 25` (agent profile),
  `mobile-dpd` unused. Configurable per node in the registry.

## DNS

- Zone `<fabric.domain>` (default `kornode.internal`). Hub dnsmasq is
  authoritative (`auth-zone`/local records) for the whole zone, records from
  `dns_records` plus generated ones:
  `node<id>.<domain>` → service address, `hub.<domain>` → `10.100.1.1`.
- Each agent's dnsmasq (when DNS enabled in its bundle) forwards
  `<domain>` to `10.100.1.1` (via fabric) and serves its own clients/sources;
  other queries go to the node's configured upstream resolvers or, if an
  egress rule routes DNS servers via an upstream, through it (existing
  behaviour).
- Records can be managed per node (`korctl dns record add monitoring A
  10.100.1.20`) with parity in API/panel.

## Exit via another node

`via: exit:<n>` on agent A marks traffic into the fabric exit (no NAT). The
hub routes it to node n only if the destination is not a fabric prefix — this
requires policy routing on the hub for traffic from A's prefixes:
the hub compiles `from: {node: A}` → `via: exit:n` into a mark whose table has
`default dev vpnsX` of node n's session (looked up by username → device from
`occtl`/connect-script events). Node n applies its own `from: fabric` rules
(normally `to any via local` or an upstream) and masquerades. If node n is
offline, the hub table falls to `unreachable` (kill switch).

### Exit through an agent from the hub itself

The same mechanism applies to traffic that originates on the hub: hub
clients, hub-attached sources (e.g. wg-easy on the hub) or hub host traffic
with `via: exit:<n>`. The hub keeps one table per exit node,
`default dev <vpnsX of node n's current session>` + `unreachable default`;
the reconciler updates the device on ocserv connect/disconnect events
(connect-script → reconciler socket, plus netlink link events as a safety
net). No NAT on the hub for this traffic; node n masquerades it (03).

Node n must accept it: its bundle contains `from: [fabric] to: any via local`
(or narrower) and the hub refuses to compile `exit:<n>` for a node whose role
list lacks `exit`. Example — wg-easy on the hub, internet through node 2,
split by list:

```yaml
sources:
  - { name: wgusers, interface: wg0, cidr: 10.8.1.0/24, export: false }
sets:
  via_host1: { routes: [203.0.113.0/24], domains: [example.org] }
egress:
  - { from: [wgusers], to: fabric,              via: fabric }
  - { from: [wgusers], to: { set: via_host1 },   via: "exit:2" }
  - { from: [wgusers], to: any,                  via: local }      # or "exit:2" for full tunnel
```
