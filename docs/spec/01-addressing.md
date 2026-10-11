# 01 — Addressing

## Configuration (hub YAML)

```yaml
node:
  id: 1                         # the hub is always node 1

fabric:
  enabled: true
  cidr: 10.99.0.0/24            # fabric addresses: 10.99.0.<id>
  client_pool: 10.100.{id}.0/24 # per-node ocserv client pool template
  source_pool: 10.8.{id}.0/24   # per-node default range for named sources
  domain: kornode.internal      # DNS zone of the fabric
  reserved: []                  # extra CIDRs nothing may overlap (e.g. corp ranges)
```

Templates accept only `{id}` and must yield a valid network for every id in
1..254. Validation rejects templates that collide with each other for any pair
of ids.

## Derived addresses

| Item | Formula | node 1 (hub) | node 3 |
| --- | --- | --- | --- |
| Fabric address | `cidr` host `<id>` | `10.99.0.1` | `10.99.0.3` |
| Client pool | `client_pool` | `10.100.1.0/24` | `10.100.3.0/24` |
| Service address | first host of client pool | `10.100.1.1` | `10.100.3.1` |
| Source default range | `source_pool` | `10.8.1.0/24` | `10.8.3.0/24` |
| DNS zone | `node<id>.<domain>` | `node1.kornode.internal` | `node3.kornode.internal` |

`server.ipv4_network` and `internal_dns.listen` become derived on the hub when
`fabric.enabled`; an explicit value is accepted only if it passes the overlap
validator (it then overrides the template for node 1).

On agents the same values come from the bundle; agents never compute them.

## Overlap validator

Runs on every registry/config mutation (hub) and on bundle apply (agent).
Input set:

- all fabric prefixes of all nodes (pools, sources, exported LANs);
- `fabric.cidr`, `fabric.reserved`;
- per node: its *local* networks reported by the agent (connected routes of
  physical interfaces, docker bridges) — reported in status, see 05;
- hub: its own connected routes.

Rules:

1. No two fabric prefixes of different nodes may overlap.
2. No fabric prefix may overlap `fabric.cidr` or `reserved`.
3. A fabric prefix of node N must not overlap a local network of node M (M≠N)
   — otherwise M could not reach N's prefix. Reported as **error** for
   prefixes being added, **warning** for already-existing state (so a newly
   reported local network cannot block unrelated edits).
4. An exported LAN must be a local network of its own node (warning if the
   agent has not reported it yet).

Errors are returned as `409 Conflict` with body:

```json
{"error": "address_overlap", "conflicts": [
  {"prefix": "10.100.3.0/24", "node": 3, "with": "10.100.0.0/16", "owner": "node 2 local (eth1)"}
]}
```

The same structure is printed by `korctl` (non-zero exit code 3) and shown
inline in the panel.

## Node id allocation

- The hub allocates the lowest free id ≥ 2 when an agent is created; the
  operator may request a specific id.
- Ids of deleted agents are quarantined for 30 days (prevents stale routes or
  DNS from pointing at a new node). `korctl agent create --id N --force-reuse`
  overrides.
