# 12 — Compatibility and operations

## Supported platforms (v2.0)

| Item | Supported | Tested in |
| --- | --- | --- |
| Host OS | Debian 12/13, Ubuntu 22.04/24.04 | netlab (CI runner Ubuntu), e2e (Debian 13 + Ubuntu 24.04) |
| Kernel | ≥ 5.15 (nft `rt mtu`, `ct mark`, interval sets with timeout) | e2e |
| nftables userspace (in image) | ≥ 1.0.6; doctor warns if host kernel is older than image expects | e2e |
| ocserv | version currently built by the project (≥ 1.3) | netlab + e2e |
| openconnect | ≥ 9.x | netlab + e2e |
| Docker | Engine ≥ 24 with compose plugin, `network_mode: host` | e2e |

Rootless Docker and non-host networking are unsupported for hub and agents.

## Upgrades

- Hub first, then agents. The hub serves bundle format versions it knows
  agents support (`agent_version` from reports); a bundle feature requiring a
  newer agent is withheld (and the agent is flagged "upgrade required") rather
  than sent.
- `bundle.format` is semver-major in the schema id (`bundle.v1`); additive
  fields only within v1; agents ignore unknown fields marked `x-optional`.
- Data migrations: registry migrations are forward-only; a pre-upgrade
  snapshot (`VACUUM INTO`) is taken automatically.

## Observability

- Hub `/metrics` (Prometheus, admin-auth or bound to interlink address):
  agents online/offline, applied vs desired lag, rollbacks, reconciler drift
  events, tunnel up/down, bundle compile duration.
- Agents expose the same reconciler/tunnel metrics only via reports (no
  listening port); the hub re-exports them per agent label.
- Logs: JSON lines option (`system.log_format: json`) for both images.

## Operational runbooks (written in P3–P5 under `docs/runbooks/`)

- Add a node; replace a node (same id); revoke a compromised node.
- Hub disaster recovery from backup; signing key rotation.
- "Agent offline" triage: `agent status`, last report, `collect_diag`.
- "Client cannot reach X" triage: `net explain` on hub and `agent exec explain`.
