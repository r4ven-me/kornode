# 07 — Interlink

## Hub side (ocserv)

Three groups, rendered by the hub from the registry into
`config_per_group_dir`:

| Group | Auth | Address | Routes pushed | Notes |
| --- | --- | --- | --- | --- |
| `clients` | password / OTP / OIDC / cert (existing settings) | hub client pool `10.100.1.0/24` | per egress for `clients` (existing split/full semantics via `route`/`no-route`) | DNS = hub service address |
| `agents` | certificate, OU=`agents` (S-01, D-43) | `explicit-ipv4 10.99.0.<id>` per user (S-02) | `route` = every interlink prefix except the agent's own, plus `10.99.0.0/24` | `restrict-user-to-routes = false`, no DNS push (agents run their own resolver), `dpd`/`keepalive` from node transport settings |
| `enroll` | password, one-time users | `interlink.enroll_pool` (default `10.99.255.240/28`, outside `interlink.cidr`, D-42) | `10.99.0.1/32` only | `max-same-clients = 1`; restricted to `10.99.0.1:<control.port>` by a static nft rule set from `kornode.net`, not by ocserv `restrict-user-to-*` (D-44) |

Authentication on the shared 443 (D-71, spike S-07): ocserv has two virtual hosts,
selected by TLS SNI.

- **Client host** (default, any SNI that is not the interlink name): `auth = plain[...]`
  (`ocpasswd`), OIDC, `certificate`, OTP, exactly as the `auth.*` settings say, with the
  `clients` group. Agent certificates and enroll accounts do not exist there.
- **Interlink vhost** `[vhost:interlink.<interlink.domain>]` (`interlink.server_name`): its own server
  certificate `certs/interlink.crt` (hub CA, SAN = the name, key kept on renewal so the pin
  is stable), `ca-cert` = hub CA, `crl`, `auth = plain[passwd=ocpasswd-enroll]` (enroll
  accounts only) with `enable-auth = certificate`, `cert-user-oid = 2.5.4.3`,
  `cert-group-oid = 2.5.4.11`, `config-per-user`/`config-per-group`. No port options in the
  section: since ocserv 1.4.2 they are global-only (a hard error inside a vhost) and the vhost
  inherits `udp-port`, and so DTLS, from the default host (D-83; S-07 ran on 1.3.0, which
  needed `udp-port` repeated). The section is the last one in `ocserv.conf`.

Because the interlink vhost accepts every certificate of the hub CA, the connect-script
guard (`$VHOST`) lets only `agents` sessions (user `agent-<id>` with a per-user file) and
`enroll` sessions (user `enroll-*`) in there; on the client host it refuses sessions in
the groups `agents`/`enroll`. Password users without an explicit group are written with
`clients`. The hub side of an agent session is the first host of the group network, i.e.
the hub interlink address `10.99.0.1` (S-02).

An agent dials the hub address from its token / bundle (`hubs[].host`) but presents
`hubs[].server_name` as SNI (`openconnect --resolve=<name>:<address> <name>:<port>`) and
pins the interlink certificate (`hubs[].pin`). Hub and agents move to this contract together
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

Hub egress for `from: interlink` (transit) is part of the hub's YAML policy;
default compiled rules: `interlink → interlink via interlink` (agent ↔ agent),
`interlink → any via local` only for agents that list `node:1` in their policy
(the hub accepts transit traffic only from nodes whose bundle declares it).

### Control-only hub (D-100)

`server.clients: false` keeps the hub's ocserv for the agents' virtual host and enrollment but makes the default host
refuse every login: its only `auth` line is the plain module over the (normally empty) `ocpasswd`, group selection and
certificate-user options are not emitted, and the connect script's default-host branch exits 1 (a leftover account cannot
log in either). The vhost block is byte-identical to a normal hub. `egress` defaults to empty (the implicit
`clients -> any via local` has no subject) and an explicit rule with `from: [clients]` is a validation error. The client
pool stays reserved, so addresses do not move when the flag is switched.

## Peer links (D-101): direct agent<->agent links

Hub-and-spoke stays the default and the control plane. An operator may add **explicit pairs**
"A dials B" on the hub; B accepts on a second vhost of its own ocserv. Data plane only: the
control API stays on the hub tunnel, and peer tunnels run from the cached bundle, so A<->B keeps
flowing with the hub down.

Kernel model (`kornode.net`, facts `NodeFacts.peers: PeerFact`):

- **Routes.** For every prefix a peer exports (`node_prefixes[peer]`) the node installs a main-table
  route `dev <peer device>` with proto 77 and **metric 0**; rule 90 resolves it before any exit table.
  A dead link removes the route with its device. The hub route for the same prefix stays in the
  `interlink` exit table (and, on a gateway agent, in main with metric 200) as the **fallback**;
  `fallback_hub: false` removes it, so a dead direct link ends at the exit's permanent
  `unreachable default` (fail closed).
- **No NAT.** Peer devices join `interlink_ifaces` (both nft tables): the masquerade skips them,
  connections arriving over a peer are answered through the `interlink` exit, and the dialed side
  applies the strict reverse-path check to its peer session devices (`peer_session_iface`).
- **Peer guard.** After the implicit returns (local, carrier) anything arriving from `@peer_ifaces`
  is rejected: a peer reaches this node only, it can neither use it as an exit nor as a relay to
  other nodes' prefixes.
- **Carrier.** The peer's endpoint addresses are carrier exemptions like any tunnel endpoint.
- Peer health never blocks apply-confirm (a warning, like a pre-existing upstream outage).

Listener and dialer wiring (vhost, allow-list, CRL, addressing from `interlink.peer_pool`, bundle
`peering`) are specified with the bundle in spec 05/06; the ocserv behaviour is pinned by spike S-08.

## Agent side

- Exit `interlink` = `oc-hub0`; the bundle carries the full list of interlink
  prefixes; the compiler puts them in set `interlink_v4`.
- No masquerade toward interlink prefixes; the agent's own sources and pool keep
  their real addresses across the interlink.
- `transport`: `tcp` (default) passes `--no-dtls`; `auto` lets openconnect use
  DTLS when available.
- Defaults for interlink sessions: `dpd 20`, `keepalive 25` (agent profile),
  `mobile-dpd` unused. Configurable per node in the registry.

## DNS

Zone `<interlink.domain>` (default `kornode.lan`), D-66.

- **Hub.** dnsmasq answers the whole zone from local data only:
  `local=/<domain>/` plus `host-record` (all A/AAAA of a name on one line) and
  `cname`; a name the hub does not know is NXDOMAIN, never forwarded. Generated
  names: `hub.<domain>` and `node1.<domain>` → hub service address
  (`10.100.1.1`), `node<N>.<domain>` → service address of every registered
  node. While `server.enabled` the hub dnsmasq always runs (`interlink_dns`
  reason). The hub restarts dnsmasq only when the rendered file changes, after
  record or agent mutations.
- **Records** live in `dns_records`, names relative to the domain. Hub-wide:
  `korctl dns record add monitoring A 10.100.1.20` → `monitoring.<domain>`
  (`hub`/`node<N>` are reserved as the last label). Per node:
  `korctl dns record add nas A 192.168.3.10 --node branch` →
  `nas.node3.<domain>`. A CNAME target must exist in the zone; an agent's CNAME
  must stay inside its node zone. API: `GET/POST/DELETE /api/dns/records`
  (`{name, type, value, node}`); panel: Interlink → DNS.
- **Agent.** The bundle `dns` section carries the node's own zone as
  `local_records` (absolute names) and `forward_zones: [{zone: <domain>,
  servers: [<hub internal_dns.listen>]}]`. The agent's dnsmasq listens on the
  node service address `10.100.<id>.1` (bound to `lo` by `kornode.net`,
  `bind-dynamic`), answers `node<id>.<domain>` locally — also while the hub is
  down — and forwards the rest of the zone to the hub over the interlink
  (`server=/<zone>/<hub>@<interlink_address>`: the source is the interlink address,
  otherwise the unmarked route lookup picks the uplink address and the hub
  drops the query by strict RPF; no NAT). Other queries go to `upstream_servers` or, without
  them, to the host's resolvers.
- Bundle values are validated as plain lower-case host names and IP addresses
  before they reach a dnsmasq line.

## Exit via another node

Implemented for **agent-originated traffic** in P4-06 (D-69); the hub-originated case below
is the second part.

`via: node:<n>` on agent A sends the matching traffic through A's interlink tunnel (no NAT).

- **Agent A.** `node:n` is a second exit on the hub tunnel (`oc-hub0`): the same device,
  a table with `default dev oc-hub0` and the usual `unreachable default`; the first exit
  on the tunnel (`interlink`) owns the answer mark. It is accepted for `to: any` only (the hub
  does not repeat set/domain matching), `from: clients` and sources only (the node's own
  traffic carries the uplink address, which the hub's strict reverse path drops), and a source
  must be exported (answers find their way back by prefix).
- **Hub.** For every active node whose policy has such a rule the hub marks packets whose
  source is one of that node's prefixes (client pool, source subnets) with the mark of
  `node:n`, whose table has `default dev <vpnsX of n's session>` and an `unreachable
  default`. Matching is by **source prefix** against a named set, not by session device, so
  the nft script does not change when sessions come and go (strict reverse path guarantees
  that only the owning agent can send from its prefixes); the table follows the device.
  No NAT on the hub. If n is offline, the table is only `unreachable`: the packet gets ICMP
  unreachable and the kill switch rejects any marked packet on the uplink.
- **Hub guard.** Agent traffic (`iifname @interlink_ifaces`) is policed: interlink and local
  destinations are routed as before, a declared exit is marked, **everything else is
  rejected** (spec: the hub accepts exit traffic only from nodes whose policy declares it;
  before P4-06 such traffic was forwarded unmarked and un-NATed).
- **Answers.** Answers from node n arrive on its session with the internet's addresses:
  established/related packets from the gateway nodes' sessions skip the strict reverse-path
  check and are routed by the main table's prefix routes back to A.
- **Node n (role `gateway`).** The bundle compiler adds `{from: [interlink], to: any, via: local}`
  unless the operator wrote a `from: interlink` rule; the node masquerades what the hub sends
  it. Answers come back from the internet addressed to interlink prefixes: a node whose policy
  has a `from: interlink` rule installs **prefix routes in main** (`<prefix> dev oc-hub0 proto
  77`, every other node's prefixes, only while the tunnel is up), so they return through the
  tunnel. Re-marking the answers does not work: `src_valid_mark=1` makes the reverse-path
  check look the internet source up in the marked (interlink) table, where there is no route,
  and the answer is dropped (found by E2E-07).
- **Validation (hub).** n must be another **active** agent with role `gateway`
  (409 `gateway_node` / `role_required`); an agent used as a gateway keeps its role while in use
  (409 `gateway_in_use`); the bundle compiler refuses an `node:n` whose target is no gateway node
  even if the registry was written another way.

### Exit through an agent from the hub itself

The same mechanism applies to traffic that originates on the hub: hub
clients, hub-attached sources (e.g. wg-easy on the hub) or hub host traffic
with `via: node:<n>`. The hub keeps one table per gateway node,
`default dev <vpnsX of node n's current session>` + `unreachable default`;
the reconciler updates the device on ocserv connect/disconnect events
(connect-script → reconciler socket, plus netlink link events as a safety
net). No NAT on the hub for this traffic; node n masquerades it (03).

Node n must accept it: its bundle contains `from: [interlink] to: any via local`
(or narrower) and the hub refuses to compile `node:<n>` for a node whose role
list lacks `gateway`. Example — wg-easy on the hub, internet through node 2,
split by list:

```yaml
sources:
  - { name: wgusers, interface: wg0, cidr: 10.8.1.0/24, export: false }
sets:
  via_host1: { routes: [203.0.113.0/24], domains: [example.org] }
egress:
  - { from: [wgusers], to: interlink,              via: interlink }
  - { from: [wgusers], to: { set: via_host1 },   via: "node:2" }
  - { from: [wgusers], to: any,                  via: local }      # or "node:2" for full tunnel
```
