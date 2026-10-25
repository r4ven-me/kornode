# Upgrading to 2.0 (interlink rename, D-85)

2.0 renames the fabric to **interlink** (the hub vhost becomes `interlink.<domain>`),
ships the agent 2.2 and carries the 2.0 hardening. Old configuration spellings are read
for one minor release (spec 10). Plan a short maintenance window: agents lose the hub
between steps 3 and 4, but keep forwarding with their cached bundle (the data plane
does not depend on the hub).

## Before you start

1. Back up the hub: `korctl hub backup --out hub-backup.enc` (or Config → Backup).
   The registry is also snapshotted automatically before its migration
   (`data_dir/backups/registry/pre-migration-v<N>-*.db`).
2. Note your interlink domain: `korctl interlink show` (`interlink.domain`, or
   `fabric.domain` in an old YAML). An explicit `kornode.internal` stays as it is;
   only the default changed to `kornode.lan`.
3. With `compose.web.yaml` or `compose.proxy.yaml`, set `KORNODE_ADMIN_PASSWORD` in
   `.env` (at least 12 characters, not a placeholder): compose now refuses to start
   without it instead of falling back to `change-me`.

## Steps

1. **Agents first.** On every node, pull and restart the 2.0 agent image
   (`ghcr.io/r4ven-me/kornode-agent:v2.0.0`, agent 2.2):

   ```bash
   docker compose -f compose.agent.yaml pull && docker compose -f compose.agent.yaml up -d
   ```

   The 2.x agent reads the old hub's bundles, so nothing changes yet.
2. **Hub config (optional now, required in the next minor release).** Rename the YAML
   section `fabric:` to `interlink:` and `KORNODE_FABRIC__*` variables to
   `KORNODE_INTERLINK__*`. Do not keep both spellings: that is a validation error.
3. **Hub.** Pull and restart the 2.0 hub image (`ghcr.io/r4ven-me/kornode:v2.0.0`).
   ocserv starts once the reconciler has converged the kernel. From now on the hub
   accepts agents only on `interlink.<domain>`.
4. **Point each agent at the new vhost** (identity, key and pin are unchanged; no
   re-enrollment):

   ```bash
   docker compose -f compose.agent.yaml stop agent
   docker compose -f compose.agent.yaml run --rm agent kornode-agent set-hub-name interlink.<domain>
   docker compose -f compose.agent.yaml up -d
   ```

   The agent first tries the vhost named in its cached bundle, then the one from
   `agent.yaml`, connects, and receives a new bundle that names the new vhost.
5. **Verify.** Nodes → Node list shows every agent `active · online` and
   "Configuration in sync"; `korctl doctor` reports no `agent-versions` problem;
   `kornode-agent status` on a node shows the interlink tunnel up.

## Behaviour changes to expect

- Activating a certificate at a new path (Let's Encrypt, external) restarts ocserv
  instead of reloading it: active VPN sessions reconnect (D-88).
- Clients of a down upstream get ICMP unreachable immediately (D-89); a
  `kill_switch: false` rule is skipped while its upstream is down.
- `via: local` no longer masquerades traffic that main routes into the interlink:
  agents see hub clients' real addresses.
- An IPv4 source's IPv6 traffic is rejected unless a policy covers it.
- Admin TOTP sign-in codes are single-use; enabling the browser terminal and other
  sensitive Web/API changes ask for the current password.
- `/docs` and `/openapi.json` are no longer served by the hub API.

## Rolling back

Stop the hub, restore the pre-migration registry snapshot over `data_dir/registry.db`
(or restore the hub backup, `docs/runbooks/hub-recovery.md`), and start the previous
hub image. Agents 2.2 also work with the previous hub; run
`kornode-agent set-hub-name fabric.<domain>` on them if they had already switched.
