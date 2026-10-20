# 00 — Overview and glossary

## Components

| Component | Runs on | Purpose |
| --- | --- | --- |
| `kornode` (hub image) | hub (node 1) | ocserv for clients/agents/enroll, registry, bundle compiler, control API, panel, `korctl`, reconciler. |
| `kornode-agent` (agent image) | every other node | openconnect to the hub and to external upstreams, reconciler, control-plane client, optional local ocserv (`access` role), optional dnsmasq. |
| `kornode.net` | both images | Python package: desired-state model, egress compiler, kernel adapter, reconciler, explain. The only code that changes kernel networking state. |
| `kornode.control` | hub | Control API (agent-facing), separate process from the admin API. |
| `kornode_agent` | agent | Agent runtime and `kornode-agent` CLI. |

## Glossary

- **Node** — any machine in the network. The hub is node 1; agents are 2..254.
- **Fabric** — the routed overlay formed by agents' ocserv sessions to the hub.
- **Fabric prefix** — any prefix owned by a node and exported into the fabric:
  its client pool, source subnets, exported LANs.
- **Service address** — `10.100.<id>.1`, the node's own address for dnsmasq,
  panel (hub) and probes; bound to `lo`.
- **Fabric address** — `10.99.0.<id>`, the node's address on its fabric
  interface (hub: on `lo` + ocserv side; agent: on its openconnect tun).
- **Class** (hub) — `clients`, `agents`, `externals`: the three participant
  kinds with distinct auth, addressing and NAT policy.
- **Source** — traffic origin class used in egress rules: `clients`, `host`,
  `fabric`, or a named source (an attached access server like wg-easy).
- **Exit** — where an egress rule sends traffic: `local`, `fabric`,
  `exit:<node>`, `upstream:<profile>`, `drop`.
- **Bundle** — the signed desired-state document the hub compiles per agent.
- **Reconciler** — loop that converges kernel state to desired state.
- **Apply-with-confirm** — apply bundle, verify health within a window, else
  roll back.

## Planes

- **Data plane**: kernel routing, nftables, tunnels. Must keep working without
  the control plane.
- **Control plane**: registry, bundles, reports, commands. Pull-only from
  agents, carried inside the fabric.
- **Management plane**: hub `korctl`, admin REST API, panel. All three equal
  (parity), all call the same services.

## Non-goals (v2.0)

- Multiple hubs / hub HA (designed not to preclude it: bundles carry a list of
  hub endpoints, but only one is used).
- Agent-to-agent direct tunnels.
- Dynamic routing protocols (BGP/OSPF).
- OTP/OIDC for users of agents with the `access` role (password and
  certificate only in v2.0).
- IPv6 client pools (rules are written family-aware; pools are IPv4 only).
