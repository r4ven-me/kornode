# 06 — Agent

## Image and process model

- Image `kornode-agent` (same repo, `Dockerfile.agent` or a target in the
  main Dockerfile), Debian slim base matching the hub, packages:
  `openconnect`, `nftables`, `iproute2`, `dnsmasq`, `ocserv` (used only with
  role `access`), Python 3.12 + `kornode.net` + `kornode_agent`.
- Deployment: `network_mode: host`, `NET_ADMIN`, `NET_RAW`, `/dev/net/tun`,
  volume `/var/lib/kornode-agent`. `compose.agent.yaml` in the repo.
- One supervisor (s6 or supervisord, same as hub) with programs:
  `agent` (Python main loop: control client + reconciler + tunnel manager),
  `ocserv` (role `access` only), `dnsmasq` (when the bundle enables DNS).
- Target: image ≤ 150 MB, RSS of `agent` ≤ 80 MB idle.

## Local files

```
/var/lib/kornode-agent/
  agent.yaml                 # bootstrap: hub endpoints, written by enroll; operator-editable log level only
  tls/key.pem tls/cert.pem tls/ca.pem
  seal/x25519.key
  bundles/<version>.json + <version>.sig   # last 3 confirmed + 1 pending
  bundles/current -> <version>.json
  hub_signing.pub            # trusted signing key(s)
  state.json                 # applied/pending version, confirm deadline, last rollback
  logs/
```

Writes are atomic (temp + fsync + rename). Private keys 0600.

## Lifecycle

```
start
 ├─ load state; verify current bundle signature
 ├─ if pending bundle with expired confirm deadline → rollback to last confirmed
 ├─ apply current bundle (no confirm needed: it was confirmed before)
 ├─ start tunnels from bundle; start reconciler
 └─ main loop:
      poll(since=applied, wait=60)  ──► new bundle → verify → stage as pending → apply → confirm window
      report every 30 s / on events
      execute commands
      renew certificate at 2/3 lifetime
```

### Apply-with-confirm

1. Verify signature (trusted keys), schema, `node_id` matches, version >
   applied. Reject → report `invalid_bundle`, keep current.
2. Unseal secrets (failure → reject).
3. Compile with `kornode.net`; run validator; if compile fails → reject.
4. Persist as pending with `confirm_deadline = now + 60 s`; apply.
5. Health checks (all must pass at least once before the deadline, each
   retried every 3 s):
   - fabric tunnel up and `10.99.0.1:8444` reachable (TCP connect) via the
     fabric mark;
   - every `upstream:*` exit referenced by an egress rule with an enabled
     profile: tunnel up (probe host if configured);
   - reconciler reports zero drift after apply.
6. Pass → confirm: becomes current, prune to 3 confirmed, report
   `confirmed`. Fail → re-apply previous current, report `rolled_back` with
   the failed checks. A version that was rolled back is not retried until a
   newer version arrives.

The deadline survives restarts (state.json), so a crash during the window
also ends in rollback.

### Autonomy

- Hub unreachable: keep current state; tunnels retry with backoff (1 s → 60 s,
  jitter); no bundle expiry.
- Boot without hub: apply cached current bundle immediately.
- Certificate expiry with hub unreachable: fabric and control stop working at
  `not_after`; external upstreams and local egress continue. Agent logs a
  daily warning from 14 days before expiry.

## Tunnels

- `fabric` — openconnect to the hub with the agent certificate, interface
  `oc-hub0`, kornode vpnc-script (interface-only, as today), `--pfs`, server
  certificate pinned, camouflage secret if configured, `--no-dtls` when
  `transport: tcp`.
- `upstream:<name>` — external profiles from the bundle, same mechanism as
  today's `UpstreamService` (ported into `kornode_agent.tunnels`), interfaces
  `oc-<name>`.
- Each tunnel reports state transitions to the reconciler (facts) and to the
  report.

## CLI `kornode-agent`

| Command | Purpose |
| --- | --- |
| `enroll <token>` | One-time enrollment (05). Refuses if already enrolled unless `--force`. |
| `run` | Main process (used by supervisor). |
| `status [--json]` | Applied/pending version, hub reachability, tunnels, sources, last errors. |
| `explain <src> <dst> [--proto tcp --port 443]` | Local explain (04). |
| `doctor [--json]` | Local doctor findings. |
| `bundle show [<version>]` | Pretty-print bundle (secrets redacted). |
| `bundle history` | Cached versions with results. |
| `bundle rollback <version>` | Local emergency rollback to a cached confirmed version (reported to hub). |
| `diag [--out file.tar.gz]` | Same archive as the `collect_diag` command. |
| `reconnect [<tunnel>]` | Restart a tunnel. |
| `version` | Versions of agent and components. |

Exit codes: 0 ok, 1 error, 2 usage, 3 validation conflict, 4 hub unreachable.
All commands support `--json`. No command prints secrets.

## Role `access`

- Bundle contains `access`: ocserv settings subset (port, auth methods:
  password/certificate), `users` (username, ocpasswd hash, groups, enabled),
  `groups` (config-per-group bodies), CA for client certs.
- The agent renders `ocserv.conf`, `ocpasswd`, group configs with the same
  renderers as the hub (`kornode.renderers.ocserv` is shared; keep it free of
  hub-only imports).
- Client pool and DNS are the node's derived values.
- User changes on the hub → new bundle → agent applies → `occtl reload`.
