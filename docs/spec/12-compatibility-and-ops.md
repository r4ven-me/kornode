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

- **Agents first, then the hub.** An agent of a given release reads the bundle
  format of the previous hub release and its own (the 2.x agents accept signed
  `kornode.bundle/v1` on receipt and from cache, and v2), so agents can be upgraded
  while the old hub still serves them. The hub's writer emits only the current
  format and stamps `min_agent_version` (never below what the format needs, D-85).
- An agent below that minimum refuses the new bundles, **keeps forwarding with its
  cached bundle**, and is flagged `upgrade_required` in the agent API/panel and by
  `korctl doctor` (`agent-versions`), computed from the `agent_version` of its last
  report. The hub does not down-compile bundles for old agents.
- Release-specific steps (e.g. the D-85 SNI flag day: `kornode-agent set-hub-name`, D-93)
  are in `docs/runbooks/upgrade-2.0.md` and spec 10.
- `bundle.format` is semver-major in the schema id (`bundle.v2`); additive
  fields only within a major; agents ignore unknown fields marked `x-optional`.
- Data migrations: registry migrations are forward-only. Before upgrading an
  existing registry the migrator writes a `VACUUM INTO` snapshot
  `data_dir/backups/registry/pre-migration-v<N>-<UTC>.db` under a file lock; if
  the snapshot fails, nothing is migrated. Rolling back the image means restoring
  that snapshot (`docs/runbooks/hub-recovery.md`).

## Observability

- Today: agent reports (state, versions, tunnels, drift, errors) in the agent API
  and panel, `korctl doctor`, the reconciler status (`korctl net status` via the
  API/panel), and plain-text logs per supervisor program.
- Planned, not in 2.0: a hub `/metrics` endpoint (Prometheus) re-exporting agent
  metrics per agent label, and a JSON log format option.

## Operational runbooks (written in P3–P5 under `docs/runbooks/`)

- Add a node; replace a node (same id); revoke a compromised node.
- Hub disaster recovery from backup; signing key rotation.
- "Agent offline" triage: `agent status`, last report, `collect_diag`.
- "Client cannot reach X" triage: `net explain` on hub and `agent exec explain`.
