# 02 — Egress policy and sources

One ordered rule list per node decides where traffic goes. **First match
wins.** The same model is used on the hub (from YAML) and on agents (from the
bundle). JSON Schema: `schemas/egress.v1.schema.json`.

## Model

```yaml
sources:                      # named sources, besides the built-in classes
  - name: amnezia             # [a-z][a-z0-9-]{0,30}
    interface: awg0           # must exist on this node; may appear later
    cidr: 10.8.3.0/24         # must be inside this node's allowed ranges
    export: true              # announce cidr into the fabric
    description: wg-easy Amnezia

sets:                         # reusable destination sets
  corp:
    routes: [10.60.0.0/16]
    domains: [corp.example.com]
    route_urls: []            # refreshed by DomainResolver/ExternalList
    domain_urls: []

egress:
  - id: fabric                # optional stable id, else index-based
    from: [clients, host, amnezia]
    to: fabric
    via: fabric
  - from: [clients, amnezia]
    to: { set: corp }
    via: upstream:office
    kill_switch: true         # default true for upstream/exit/fabric
  - from: [clients, amnezia]
    to: any
    via: local
```

### Fields

- `from`: non-empty list of
  - `clients` — this node's ocserv client pool;
  - `host` — locally originated traffic of this node (`ct direction original`);
  - `fabric` — traffic arriving from the fabric interface(s) and not destined
    to this node (transit on the hub, exit-via-node on agents);
  - `<source name>`.
- `to`:
  - `any`;
  - `fabric` — union of all fabric prefixes except this node's own;
  - `{ set: <name> }`;
  - inline `{ routes: [...], domains: [...] }`;
  - `{ node: <id> }` — fabric prefixes of that node.
- `via`:
  - `local` — main routing table (uplink), masquerade to uplink;
  - `fabric` — the fabric exit (agent: tun to hub; hub: per-session routes);
  - `exit:<node>` — send through the fabric to node `<node>`, which applies
    its own `from: fabric` rules to it;
  - `upstream:<profile>` — the named external upstream, masquerade to it;
  - `drop` — explicit reject (ICMP admin-prohibited).
- `kill_switch` (bool): when the exit is unavailable, traffic is rejected
  instead of falling through to the next rule. Default `true` for every `via`
  except `local`. `false` means "fall through to later rules while the exit is
  down" (useful for opportunistic exits).

### Implicit rules (always prepended, not editable)

1. Destination is one of this node's own addresses → local delivery.
2. Destination in a connected network of this node (`suppress_prefixlength 0`
   lookup in main) → main table. This is how docker bridges and LANs always
   win over policies.
3. Destination is the carrier address of any active tunnel → main table.

### Implicit rules (always appended)

- `from: [clients, <sources>]  to: any  via: drop` — nothing escapes unrouted.
- `from: [host] to: any via: local` — host traffic defaults to normal routing.

## Validation

- Every name referenced in `from`, `to.set`, `via` exists.
- `exit:<node>` refers to an existing node ≠ self; the target node must have a
  rule accepting `from: fabric` traffic to `any` or the destination (checked
  on the hub at bundle compile; warning only on agents).
- **Dead rules**: a rule fully shadowed by earlier rules (every `from` source
  and the whole `to` set already matched earlier) → warning with the shadowing
  rule index. Domain-only sets are never considered fully shadowed.
- Source `cidr` must not overlap other prefixes (01) and must be inside
  `fabric.source_pool` for the node unless explicitly allowed with
  `allow_outside_pool: true`.

## Compilation (see 03 for the kernel layout)

- Each distinct exit gets a fwmark and a routing table:
  - fwmark = `0x0c000000 | (exit_index << 8)`, mask `0xffffff00`;
    the low byte is left free for other software.
  - table id = `12000 + exit_index`.
- Each `to` becomes an nft set pair (`<name>_v4`, `<name>_v6`, interval,
  auto-merge). Domain resolutions go to the same set with element timeouts
  (`timeout 2h` refreshed on every resolve) instead of separate static/dynamic
  sets — config elements are added without timeout, so a refresh never drops
  them.
- Each `from` becomes a match: `clients` → `ip saddr <pool>`; source →
  `iifname "<if>" ip saddr <cidr>` (both required); `host` → output hook,
  `ct direction original`; `fabric` → `iifname @fabric_ifaces`.
- The rule list compiles to a single chain `egress_classify` of
  `<from-match> <to-match> meta mark set <mark> accept` in order, so the
  first match wins by construction. `drop` compiles to `reject with icmpx
  admin-prohibited`.
- NAT: one masquerade rule per (`via` that needs NAT, outgoing interface),
  matched on `meta mark` and `oifname`. No NAT is emitted for `fabric` or
  `exit:<node>`.

## Domain-based sets

`DomainResolverService` stays, retargeted: it resolves every domain listed in
compiled sets and adds results to the set with timeout. Domains coming from an
`upstream:<profile>` with `accept_server_routes` resolve through that
upstream's DNS (unchanged behaviour). Interval: 5 min default; TTL-aware
(min(ttl, 1h)).

Consistency rule: when a source or client class is routed by domain sets,
its clients should use the node's dnsmasq (service address) as their DNS, so
that the addresses they connect to are the same ones the resolver put into
the set (CDN/geo answers differ between resolvers). `doctor` warns when a
source's DNS (if discoverable, e.g. wg-easy `WG_DEFAULT_DNS`) is not the
service address; documentation states it as a requirement.

## Sources (wg-easy, Amnezia, any external access server)

- Sources may be attached to the hub as well as to agents.
- The access server runs in `network_mode: host` so its interface is in the
  node's network namespace. kornode never manages the server itself.
- kornode owns NAT/forwarding for `cidr`. The operator must disable the
  server's own NAT hooks; `doctor` (03, P4-05) inspects nft/iptables for
  masquerade/SNAT rules matching the source cidr owned by other tables and
  reports them as **error**.
- Interface absent → rules referencing it are still installed (they match
  nothing); doctor reports a warning; status shows the source as `down`.
- With `export: true`, the hub adds `iroute <cidr>` for this agent and pushes
  `route <cidr>` to other agents (07).
- Recommended wg-easy settings (documented in `docs/sources.md` during P4):
  empty PostUp/PostDown hooks, client address range inside the node's source
  range, allowed IPs `0.0.0.0/0`, MTU 1280 when the node's exit is the fabric
  over TCP. Setting names differ between wg-easy versions (v14 and the Amnezia
  fork use `WG_POST_UP`/`WG_POST_DOWN`/`WG_DEFAULT_ADDRESS`/`WG_MTU`
  environment variables; v15 moved them into its UI) — verify against the
  version actually deployed on the test VM and document both.
