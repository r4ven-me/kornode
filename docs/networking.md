# Networking, routing and DNS

Contracts live in `docs/spec/` (`01-addressing`, `02-egress-and-sources`, `03-kernel-dataplane`,
`04-netcore-reconciler`, `07-interlink`). This page is the operator's overview.

## Principles

- Inter-node transport is ocserv/openconnect on 443/tcp. DTLS is used opportunistically; TCP alone works.
- Only `kornode.net` changes kernel state (sysctl, `ip rule`/`ip route`, nftables). Everything else edits
  inputs and wakes the reconciler.
- kornode owns only its objects: nft tables `inet kornode` and `ip kornode_nat`, rule priorities 90–199,
  route tables 12000–12999, main-table routes with `proto 77`. It never flushes global state or host firewall rules.
- Fail closed: traffic assigned to a tunnel never leaks through the uplink, including while a tunnel
  reconnects or the reconciler restarts (`unreachable default` in every exit table, stale-mark rejects).
- No NAT inside the interlink. Masquerade happens only toward the internet (`via: local`) and toward
  external upstreams (`via: upstream:<profile>`).
- Applying is idempotent, supports dry-run, and is one `nft -f` transaction.

## Required Linux capabilities

```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
devices:
  - /dev/net/tun:/dev/net/tun
```

Both images need `network_mode: host` so the node's interfaces, routes and nftables are the host's.
Rootless mode cannot control the network and is not supported.

## Addressing

The hub is node 1, agents are 2..254. With the default `interlink` settings:

| Item | Formula | Hub | Node 3 |
| --- | --- | --- | --- |
| Interlink address | `10.99.0.<id>` | `10.99.0.1` | `10.99.0.3` |
| Client pool | `10.100.<id>.0/24` | `10.100.1.0/24` | `10.100.3.0/24` |
| Service address (dnsmasq, panel, probes) | first host of the pool | `10.100.1.1` | `10.100.3.1` |
| Source default range | `10.8.<id>.0/24` | `10.8.1.0/24` | `10.8.3.0/24` |
| DNS zone | `node<id>.<interlink.domain>` | `node1.kornode.lan` | `node3.kornode.lan` |

An interlink prefix is any prefix a node owns and exports: its client pool, source subnets, exported LANs.
The overlap validator runs on every registry or config change and on bundle apply, and rejects overlapping
prefixes with `409 address_overlap` (CLI exit code 3). Ids of deleted agents are quarantined for 30 days.

## Egress policy

One ordered rule list per node decides where traffic goes; the first match wins. The same model is used on
the hub (YAML) and on agents (bundle):

```yaml
sources:
  - {name: amnezia, interface: awg0, cidr: 10.8.3.0/24, export: true}
sets:
  corp: {routes: [10.60.0.0/16], domains: [corp.example.com]}
egress:
  - {from: [clients, host, amnezia], to: interlink, via: interlink}
  - {from: [clients, amnezia], to: {set: corp}, via: "upstream:office"}
  - {from: [clients, amnezia], to: any, via: local}
```

- `from`: `clients` (this node's ocserv pool), `host` (locally originated traffic), `interlink` (transit from the
  interlink), or a named source.
- `to`: `any`, `interlink`, `{set: <name>}`, inline `{routes, domains}`, or `{node: <id>}`.
- `via`: `local` (main table, masquerade to the uplink), `interlink`, `node:<n>`, `upstream:<profile>`, `drop`.
- `kill_switch` defaults to `true` for every `via` except `local`: when the exit is down, traffic is rejected
  instead of falling through to the next rule.

Always prepended, not editable: local delivery to the node's own addresses, connected networks (docker bridges
and LANs always beat policies), and tunnel carrier addresses. Always appended: `clients`/sources to `any` is
dropped, `host` to `any` goes through normal routing.

Domain sets are filled by `DomainResolverService` into nft sets with element timeouts; clients routed by domain
should use the node's dnsmasq (service address) so they connect to the addresses that were put in the set.

Inspect and edit with `korctl egress` (`show`, `check`, `set`, `edit`), `korctl source`, `/api/egress`, `/api/sources`
or the panel's Network → Egress rules and Network → Sources. `korctl net explain SRC DST` answers "where does this packet go and why".

## Kernel layout

Each distinct exit gets a fwmark (`0x0c000000 | index << 8`, mask `0xffffff00`) and a routing table
`12000 + index`:

| Priority | Rule |
| --- | --- |
| 90 | `lookup main suppress_prefixlength 0` — connected routes and interlink sessions beat policies |
| 95 | `to <carrier>/32 lookup main` — a tunnel carrier never enters its own tunnel |
| 100+i | `fwmark <mark_i>/0xffffff00 lookup <12000+i>` |

The rule list compiles to a single `egress_classify` chain (`meta mark set … accept` in order). The mark is
copied to `ct mark` on the first packet, so a connection keeps its path for life. A connection whose exit was
removed by a policy change is rejected instead of leaking; new connections use the new policy.
`sysctl`: `ip_forward=1`, `src_valid_mark=1`, `rp_filter=2` on tunnel and source interfaces.

`korctl net plan` prints what the reconciler would change right now without touching the kernel; `korctl net apply`
runs one reconciler pass.

## Hub, agents and sources

- **Hub**: ocserv serves clients, agents and one-time enroll sessions on one 443/tcp, selected by SNI (clients
  host and `interlink.<interlink.domain>` vhost). Routes to agent prefixes come from ocserv `iroute` sessions, installed
  into `main` with `proto 77` by the hub reconciler. Agent ↔ agent traffic is forwarded by the hub.
- **Agent**: openconnect to the hub (the interlink exit) and to external upstreams; the reconciler converges the
  signed bundle. With a cached bundle it keeps forwarding when the hub is down and boots from cache.
- **Gateway nodes**: an agent with role `gateway` accepts `from: interlink` traffic and masquerades it; another node
  sends traffic there with `via: node:<n>`.
- **Sources** (wg-easy, Amnezia, any access server): run it in `network_mode: host`, disable its own NAT hooks;
  kornode owns routing and NAT for the source subnet. `korctl doctor` reports foreign NAT rules on a source
  subnet as an error. See `docs/sources.md`.

## DNS

The hub owns the interlink zone (`node<id>.<interlink.domain>` and registry records: `korctl dns record add|del|list`).
Each node runs dnsmasq on its service address, bound to `lo`; agents forward interlink names to the hub through
their interlink address. Clients of a node use that node's dnsmasq (blocklists, domain-set resolution).

## Diagnostics

`korctl doctor` (hub) and `kornode-agent doctor` check addressing, sources, tunnels and foreign NAT. For manual
inspection:

```text
ip addr
ip route show table all
ip rule
nft list table inet kornode
nft list table ip kornode_nat
ss -lntup
occtl show users
```

Output of the diagnostics commands masks secrets and never prints private keys.

If `nft` exits with signal 11 inside the container while the same rules load on the host, check nftables
userspace/kernel compatibility first (`nft --version`, `uname -r`); updating the image's `nftables` or using a
base image aligned with the host kernel usually fixes it.
