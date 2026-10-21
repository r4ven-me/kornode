# 07 — Fabric

## Hub side (ocserv)

Three groups, rendered by the hub from the registry into
`config_per_group_dir`:

| Group | Auth | Address | Routes pushed | Notes |
| --- | --- | --- | --- | --- |
| `clients` | password / OTP / OIDC / cert (existing settings) | hub client pool `10.100.1.0/24` | per egress for `clients` (existing split/full semantics via `route`/`no-route`) | DNS = hub service address |
| `agents` | certificate, OU=`agents` (S-01, D-43) | `explicit-ipv4 10.99.0.<id>` per user (S-02) | `route` = every fabric prefix except the agent's own, plus `10.99.0.0/24` | `restrict-user-to-routes = false`, no DNS push (agents run their own resolver), `dpd`/`keepalive` from node transport settings |
| `enroll` | password, one-time users | `fabric.enroll_pool` (default `10.99.255.240/28`, outside `fabric.cidr`, D-42) | `10.99.0.1/32` only | `max-same-clients = 1`; restricted to `10.99.0.1:<control.port>` by a static nft rule set from `kornode.net`, not by ocserv `restrict-user-to-*` (D-44) |

Authentication on the shared 443 (D-71, spike S-07): ocserv has two virtual hosts,
selected by TLS SNI.

- **Client host** (default, any SNI that is not the fabric name): `auth = plain[...]`
  (`ocpasswd`), OIDC, `certificate`, OTP, exactly as the `auth.*` settings say, with the
  `clients` group. Agent certificates and enroll accounts do not exist there.
- **Fabric vhost** `[vhost:fabric.<fabric.domain>]` (`fabric.server_name`): its own server
  certificate `certs/fabric.crt` (hub CA, SAN = the name, key kept on renewal so the pin
  is stable), `ca-cert` = hub CA, `crl`, `auth = plain[passwd=ocpasswd-enroll]` (enroll
  accounts only) with `enable-auth = certificate`, `cert-user-oid = 2.5.4.3`,
  `cert-group-oid = 2.5.4.11`, `config-per-user`/`config-per-group`. `udp-port` is repeated in
  the section, otherwise the vhost sends no DTLS address. The section is the last one in
  `ocserv.conf`.

Because the fabric vhost accepts every certificate of the hub CA, the connect-script
guard (`$VHOST`) lets only `agents` sessions (user `agent-<id>` with a per-user file) and
`enroll` sessions (user `enroll-*`) in there; on the client host it refuses sessions in
the groups `agents`/`enroll`. Password users without an explicit group are written with
`clients`. The hub side of an agent session is the first host of the group network, i.e.
the hub fabric address `10.99.0.1` (S-02).

An agent dials the hub address from its token / bundle (`hubs[].host`) but presents
`hubs[].server_name` as SNI (`openconnect --resolve=<name>:<address> <name>:<port>`) and
pins the fabric certificate (`hubs[].pin`). Hub and agents move to this contract together
(D-71): a hub with the vhost does not accept an agent that dials the client host.

Per-user config for each agent (`config_per_user_dir/agent-<id>`):

```
explicit-ipv4 = 10.99.0.3
```

Since P4-01 (D-63) the per-user file also carries, from the registry:

```
iroute = 192.168.3.0/24     # this node's exported prefixes (pool included)
route = 192.168.2.0/24      # every other active node's exported prefixes
dpd = 20                    # node transport settings, when set
keepalive = 25
```

`export: false` prefixes appear in neither list. ocserv does not install `iroute`
routes in the kernel (spike S-03); the hub reconciler adds `<prefix> dev vpnsN` to
the main table with `proto 77` while the agent's session is up and removes it
afterwards. Changes rewrite group/user
files atomically. ocserv reads `config-per-group` and `config-per-user` when a
session opens, so new and removed files need no reload; when the content of an
existing file changes the hub runs `occtl reload`. Existing sessions pick up
changes on reconnect.

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

Zone `<fabric.domain>` (default `kornode.internal`), D-66.

- **Hub.** dnsmasq answers the whole zone from local data only:
  `local=/<domain>/` plus `host-record` (all A/AAAA of a name on one line) and
  `cname`; a name the hub does not know is NXDOMAIN, never forwarded. Generated
  names: `hub.<domain>` and `node1.<domain>` → hub service address
  (`10.100.1.1`), `node<N>.<domain>` → service address of every registered
  node. With `fabric.enabled` the hub dnsmasq always runs (`fabric_dns`
  reason). The hub restarts dnsmasq only when the rendered file changes, after
  record or agent mutations.
- **Records** live in `dns_records`, names relative to the domain. Hub-wide:
  `korctl dns record add monitoring A 10.100.1.20` → `monitoring.<domain>`
  (`hub`/`node<N>` are reserved as the last label). Per node:
  `korctl dns record add nas A 192.168.3.10 --node branch` →
  `nas.node3.<domain>`. A CNAME target must exist in the zone; an agent's CNAME
  must stay inside its node zone. API: `GET/POST/DELETE /api/dns/records`
  (`{name, type, value, node}`); panel: Agents → Fabric DNS (Fabric → DNS from
  P4-07).
- **Agent.** The bundle `dns` section carries the node's own zone as
  `local_records` (absolute names) and `forward_zones: [{zone: <domain>,
  servers: [<hub internal_dns.listen>]}]`. The agent's dnsmasq listens on the
  node service address `10.100.<id>.1` (bound to `lo` by `kornode.net`,
  `bind-dynamic`), answers `node<id>.<domain>` locally — also while the hub is
  down — and forwards the rest of the zone to the hub over the fabric
  (`server=/<zone>/<hub>@<fabric_address>`: the source is the fabric address,
  otherwise the unmarked route lookup picks the uplink address and the hub
  drops the query by strict RPF; no NAT). Other queries go to `upstream_servers` or, without
  them, to the host's resolvers.
- Bundle values are validated as plain lower-case host names and IP addresses
  before they reach a dnsmasq line.

## Exit via another node

Implemented for **agent-originated traffic** in P4-06 (D-69); the hub-originated case below
is the second part.

`via: exit:<n>` on agent A sends the matching traffic through A's fabric tunnel (no NAT).

- **Agent A.** `exit:n` is a second exit on the hub tunnel (`oc-hub0`): the same device,
  a table with `default dev oc-hub0` and the usual `unreachable default`; the first exit
  on the tunnel (`fabric`) owns the answer mark. It is accepted for `to: any` only (the hub
  does not repeat set/domain matching), `from: clients` and sources only (the node's own
  traffic carries the uplink address, which the hub's strict reverse path drops), and a source
  must be exported (answers find their way back by prefix).
- **Hub.** For every active node whose policy has such a rule the hub marks packets whose
  source is one of that node's prefixes (client pool, source subnets) with the mark of
  `exit:n`, whose table has `default dev <vpnsX of n's session>` and an `unreachable
  default`. Matching is by **source prefix** against a named set, not by session device, so
  the nft script does not change when sessions come and go (strict reverse path guarantees
  that only the owning agent can send from its prefixes); the table follows the device.
  No NAT on the hub. If n is offline, the table is only `unreachable`: the packet gets ICMP
  unreachable and the kill switch rejects any marked packet on the uplink.
- **Hub guard.** Agent traffic (`iifname @fabric_ifaces`) is policed: fabric and local
  destinations are routed as before, a declared exit is marked, **everything else is
  rejected** (spec: the hub accepts exit traffic only from nodes whose policy declares it;
  before P4-06 such traffic was forwarded unmarked and un-NATed).
- **Answers.** Answers from node n arrive on its session with the internet's addresses:
  established/related packets from the exit nodes' sessions skip the strict reverse-path
  check and are routed by the main table's prefix routes back to A.
- **Node n (role `exit`).** The bundle compiler adds `{from: [fabric], to: any, via: local}`
  unless the operator wrote a `from: fabric` rule; the node masquerades what the hub sends
  it. Answers come back from the internet addressed to fabric prefixes: a node whose policy
  has a `from: fabric` rule installs **prefix routes in main** (`<prefix> dev oc-hub0 proto
  77`, every other node's prefixes, only while the tunnel is up), so they return through the
  tunnel. Re-marking the answers does not work: `src_valid_mark=1` makes the reverse-path
  check look the internet source up in the marked (fabric) table, where there is no route,
  and the answer is dropped (found by E2E-07).
- **Validation (hub).** n must be another **active** agent with role `exit`
  (409 `exit_node` / `role_required`); an agent used as an exit keeps its role while in use
  (409 `exit_in_use`); the bundle compiler refuses an `exit:n` whose target is no exit node
  even if the registry was written another way.

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
