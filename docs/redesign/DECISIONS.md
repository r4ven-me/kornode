# Decisions and spikes

Format: ID, decision, rationale, status. `spike` entries are assumptions to
verify early in the named phase with a throwaway test; if a spike fails, apply
the listed fallback and update this file and the affected spec.

## Taken

| ID | Decision | Rationale |
| --- | --- | --- |
| D-01 | Inter-node transport: ocserv/openconnect, 443/tcp, DTLS optional. | Owner requirement: traverses restrictive networks, single port. |
| D-02 | Topology: hub-and-spoke. No agent-to-agent tunnels. | Matches the transport (agents dial the hub), simplest correct routing. |
| D-03 | WireGuard only as a third-party access server attached as a `source`. | Owner requirement. |
| D-04 | Control plane is pull-only over the fabric; enrollment also goes through ocserv (one-time `enroll` user). | No inbound ports on agents, no second public port on the hub, works behind DPI exactly like the fabric. |
| D-05 | Registry in SQLite (WAL); hub's own settings stay in YAML. | Registry is mutable inventory, not configuration; YAML-first stays for settings. |
| D-06 | Bundles are signed with Ed25519 (detached signature over exact bytes), separate from TLS. | Cached bundle stays verifiable at boot without the hub. |
| D-07 | Apply-with-confirm: 60 s health window, automatic rollback. | A bad bundle must not strand an agent. |
| D-08 | Bundles never expire. Only the agent certificate does (90 days, renew at 2/3). | Hub outage must not become a network outage. |
| D-09 | Agent is Python, same repo, separate package and image; depends on `kornode.net`, `pydantic`, `httpx`, `pyroute2`, `cryptography`. No FastAPI, no frontend. | Reuse of the data-plane core; one language for the team. |
| D-10 | Egress rules: ordered, first match wins. | Removes "last mark wins" ambiguity. |
| D-11 | Kill switch at two layers: `unreachable` route in each exit table + nft `oifname` check. | No leak window during tunnel bounce. |
| D-12 | Netlink via pyroute2 instead of parsing `ip -j`. | Atomicity, events, no text parsing. |
| D-13 | Hub-only capabilities follow CLI ⇄ API ⇄ Web parity, enforced by `parity.yaml`. | Owner requirement. |
| D-14 | Agent has no web panel; local CLI only. Remote diagnostics through hub commands. | Minimal attack surface and code size. |
| D-15 | Per-node addressing derived from `node.id` (1–254). Hub is node 1. | Prevents overlap by construction. |
| D-16 | Secrets for agents are sealed per agent: ephemeral X25519 + HKDF-SHA256 + ChaCha20-Poly1305. | Bundle bodies may be logged/cached; secrets stay unreadable to other agents. |

## Spikes

| ID | Phase | Assumption | How to verify | Fallback |
| --- | --- | --- | --- | --- |
| S-01 | P3 | ocserv accepts both password users (`clients`) and certificate users (`agents`) on the same 443 listener, with group derived from the certificate OU (`cert-group-oid = 2.5.4.11`). | netlab: one ocserv, password client and cert client both connect, `occtl show users` shows correct groups. | `auth = "certificate"` + `enable-auth = "plain[...]"` alternative-auth config; if that fails, agents use password auth with a per-agent random secret delivered at enrollment and rotated with the cert. |
| S-02 | P3 | Per-group `ipv4-network` in `config-per-group` lets `agents` use `10.99.0.0/24` while `clients` use `10.100.1.0/24`. | netlab: two groups, check leased addresses. | Single hub pool `10.99.0.0/16`-style split: agents `explicit-ipv4` inside the hub pool, clients from a sub-range; update `01-addressing.md`. |
| S-03 | P4 | `iroute` installs a kernel route to the agent's prefixes via its `vpnsN` device for the session lifetime, and `explicit-ipv4` pins the agent address. | netlab: connect agent, `ip route` on hub shows prefixes via `vpnsN`; reconnect keeps the address. | Hub reconciler installs routes itself on ocserv `connect-script` events (device + username → prefixes from registry). |
| S-04 | P3 | `restrict-user-to-routes = true` + `route = 10.99.0.1/32` limits the `enroll` group to the control API. | netlab: enroll session cannot reach anything else. | nft rule on the hub: `iifname "vpns*" ip saddr <enroll lease> ip daddr != <hub service addr> drop` driven by connect-script. |
| S-05 | P1 | openconnect + ocserv run inside network namespaces on GitHub-hosted runners. | CI job. | Use the project image in privileged Docker with `--network none` + veths created from the host side. |
| S-06 | P0 | `rp_filter=2` on tunnel devices is enough with `src_valid_mark=1`; no need to touch the main uplink's `rp_filter`. | netlab with strict uplink. | Set `rp_filter=2` on `all` and document; doctor warns if the host overrides it. |
