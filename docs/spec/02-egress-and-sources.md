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
    route_urls: []            # hub: downloaded hourly by DomainResolver, cached, last good copy kept (D-75)
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
  - `node:<n>` — send through the fabric to node `<node>`, which applies
    its own `from: fabric` rules to it;
  - `upstream:<profile>` — the named external upstream, masquerade to it;
  - `upstream:active` — the selected-profile alias, resolved to a concrete
    upstream identity before classification; `active` is a reserved profile slug;
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
- `node:<n>` refers to an existing node ≠ self; the target node must have a
  rule accepting `from: fabric` traffic to `any` or the destination (checked
  on the hub at bundle compile; warning only on agents).
- **Dead rules**: a rule fully shadowed by earlier rules (every `from` source
  and the whole `to` set already matched earlier) → warning with the shadowing
  rule index. Domain-only sets are never considered fully shadowed.
- Source `cidr` must not overlap other prefixes (01) and must be inside
  `fabric.source_pool` for the node unless explicitly allowed with
  `allow_outside_pool: true`.

## Compilation (see 03 for the kernel layout)

- Each concrete exit gets a stable identity mark, independent of rule order,
  selected alias, and process lifetime. Mask `0xffffff00`; low byte is not part
  of the identity. Marks are `0x0c000000 | (slot << 8)`:
  - `local`: slot `0x8000`; `fabric`: slot `0x8001` (reserved, never reused);
  - other exit names: slot `0x8002 + uint32_be(SHA256(name)[:4]) % 0x7ffe`;
  - simultaneous numeric-mark collisions are a compile error, never resolved
    by probing another slot (which would change an established flow's identity).
- Conntrack also stores an identity label: the first 128 bits of SHA256 of
  the concrete exit name. Restored marks are accepted only with their exact
  current identity label. This rejects collisions with *deleted* identities
  without a process-local allocator or recyclable persistent lease database.
- Routing tables remain bounded slots, `12000 + exit_index`, with first-appearance
  indices 1..99 and priorities `100 + exit_index`. More than 99 distinct exits
  is an error. A fail-closed nft barrier covers route/rule updates (04), so a
  table slot can be reassigned without sending old conntrack down another exit.
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
  `node:<n>`.

## Upstream selection, availability and administrative disablement

`upstream.active_profile` (overridden by the runtime `active-upstream` marker)
selects only `upstream:active`. Named `upstream:<slug>` rules never follow a
switch/failover. The compiler resolves the alias to the concrete profile's mark,
interface and table; it never reuses one alias mark for different profiles.
New flows follow the new selection. Existing flows retain their concrete
identity while that exit is still referenced; otherwise they are dropped, not
migrated. A deleted/disabled runtime selection does not silently select another
profile. No selection compiles the alias as a blocked exit, even with
`kill_switch: false`.

`upstream.enabled: false` and `profiles[].enabled: false` are administrative
unavailability, not a request for local egress. Known profile references remain
valid and compile with permanent `unreachable` routes and nft rejection on
**every** outgoing interface, even if the physical link is still up and even
if the rule requested `kill_switch: false`. Explicit policy changes to `local`
are how an administrator permits local egress. Unknown references still fail
validation. Carrier exclusions remain available for declared profiles.

Dialing/connection lifecycle and egress authorization are separate: manual
`connect` can prepare a tunnel but does not enable disabled egress or change the
selected profile. The watchdog's enablement flags control which connections it
maintains. Disconnecting openconnect removes its tunnel; policy remains and
normally fails closed. An `external_interface` is never torn down by kornode:
its `disconnect` only reconciles existing policy and explicitly reports that
policy/interface are untouched. Disable the profile or edit egress to change
its authorization; disconnect must not claim routing was deactivated.

## Domain-based sets

Every node resolves the domain sets of its own policy and records the addresses
per set (`NodeFacts.resolved`, D-25; no nft element timeouts). On the hub
`DomainResolverService` does it (internal DNS upstreams, `domain_urls` /
`route_urls` downloaded hourly and cached, D-75); on an agent `kornode_agent.resolver`
does it from the bundle's policy (D-78): it queries the hub resolver the node's
dnsmasq forwards the fabric zone to (else `/etc/resolv.conf`) and downloads the
lists itself. Interval: TTL-aware, 30 s to 1 h. An unresolved set is empty
(traffic assigned to it matches nothing).

`node:<n>` with a set or inline destination (D-79): a hub rule needs nothing extra, the
hub's own resolver feeds its classification. For an agent rule the agent classifies by the
addresses it resolved itself, marks the flow and sends it into the fabric tunnel; the hub
cannot see the mark, so it steers the transit traffic by source prefix **and** destination.
To make both sides agree the agent reports the addresses behind each such destination
(`gateway_sets` in its report, keyed like `NodeFacts.resolved`) and the hub matches those plus
the static routes of the set. The hub emits its transit rules in the order of the agent's
policy (first match wins, like on the agent). Until the hub has seen a new address the
flow matches no transit rule and falls to the fabric guard (dropped): it fails closed,
it never leaves through the hub's uplink. `to: fabric` and `to: {node: n}` with `node:<n>` stay
refused. A set that resolves into a fabric prefix is routed inside the fabric (the hub
passes fabric destinations before the transit rules), not exited.

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
