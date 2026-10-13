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
  agent.yaml                 # bootstrap (enroll): hub host/port/pin, fabric tunnel params, control_url; operator edits log level only
  tls/key.pem tls/cert.pem tls/ca.pem
  seal/x25519.key
  bundles/<version>.json + <version>.sig   # exact received bytes + signature envelope
  trust.json                 # trusted signing keys (see Trust store)
  state.json                 # see State
  logs/
```

Writes are atomic: temp file in the same directory, fsync, rename, fsync of
the directory. Private keys 0600. There is no `current` symlink: `state.json`
is the only pointer, so one rename switches it.

### State

```json
{"current": 42, "confirmed": [42, 41, 40], "high_water": 43,
 "pending": {"version": 43, "started_at": "...", "previous": 42},
 "deferred": {"version": 43, "attempts": 1},
 "failed": {"39": "health: fabric (control ping) failed"},
 "last_apply": {"version": 43, "result": "rolled_back", "at": "...", "error": "..."}}
```

- `current` — the version whose desired state the reconciler applies; always
  a verified bundle, or `0` for the bootstrap state (below).
- `confirmed` — up to 3 cached confirmed versions, newest first; older files
  are pruned after a confirm. A pending body is kept until it is confirmed or
  its fate is recorded.
- `high_water` — the highest version that passed verification. Only
  `version > high_water` is ever accepted from the hub (replay protection);
  polls use `since=high_water`. Local rollback lowers `current`, never
  `high_water`.

### Trust store

`trust.json` = `{"active": [<key>], "retired": [{"key": <key>, "max_version": N}]}`
with keys as `{key_id, pubkey_b64}`. The enroll result seeds `active`.
New bundles verify only against `active`. A cached bundle verifies against
`active` or a `retired` key with `version ≤ max_version`. When a confirmed
bundle carries `next_signing_pubkey`, the key joins `active`; when the first
bundle signed by a new key is confirmed, the other active keys move to
`retired` with `max_version` = their last version.

### Bootstrap state

`current = 0`: a desired state built from `agent.yaml` alone — the fabric
tunnel to the hub and an empty egress policy (only the implicit rules of 02;
nothing is marked to a tunnel, so nothing can leak). Used after enrollment
until the first bundle is confirmed, and when no cached bundle verifies.

## Lifecycle

```
start
 ├─ load state.json and trust.json
 ├─ pending present → the agent died inside a confirm window:
 │     current := pending.previous, record failed[v] = "restart during confirm"
 ├─ verify current (signature with active or retired keys, validator steps
 │     2 and 4–6 of 05); on failure try the next confirmed version, then the
 │     bootstrap state; report what was skipped
 ├─ start reconciler with current; start tunnels from current
 └─ main loop:
      poll(since=high_water, wait=60) ─► new bundle → stage → apply-with-confirm
      deferred version and fabric healthy for 30 s → retry it (max 3 attempts)
      report every report_interval_seconds and on apply/rollback/tunnel change
      execute commands
      renew certificate at 2/3 lifetime
```

A restart inside the window always rolls back (conservative: the crash may
be the bundle's fault). The operator re-pushes from the hub, which compiles
a new version.

### Agent process

One Python process (`kornode-agent run`), asyncio, modules in
`backend/kornode_agent/`:

| Module | Role |
| --- | --- |
| `store.py` | files above: cache, `state.json`, `trust.json`, atomic writes |
| `inputs.py` | `AgentNetInputs`: active bundle + runtime facts → `NetInputs`; the provider for `kornode.net.Reconciler` |
| `tunnels.py` | fabric and upstream openconnect sessions; reuses the shared dialer extracted from the hub's `UpstreamService` (argv, carrier resolution, pin probe) into a module free of hub imports |
| `apply.py` | apply-with-confirm state machine (below) |
| `health.py` | health checks and the baseline |
| `control.py` | httpx client: poll, report, commands, renew (mTLS, pinned CA) |
| `cli.py` | `kornode-agent` CLI |

The reconciler runs in-process: `apply.py` swaps the active bundle seen by
the provider and calls `run_once()` directly, so applying and rolling back
are the same operation with different input. Netlink and the 10 s timer keep
the active bundle converged between applies, exactly as on the hub.

### Apply-with-confirm

1. **Verify** (05 Validator, steps 1–6) with `active` trust keys.
   Reject → keep current, report `invalid_bundle` with the step that failed.
   A rejected body is not cached.
2. **Stage**: write `<v>.json` and `<v>.sig`; `high_water := v`; take the
   **baseline** — which health checks pass right now under `current`;
   persist `pending = {v, previous: current}`.
3. **Apply**: the provider switches to `v`; tunnels are started/stopped
   to match; `run_once()`.
4. **Health window** (`settings.confirm_window_seconds`, default 60 s). Every
   3 s, until each required check has passed once:
   - `fabric` — always required: fabric tunnel up and an mTLS
     `GET /agent/v1/ping` to the bundle's `control_url` succeeds;
   - `upstream:<name>` — tunnel up (and `check_host` reachable through its
     mark, if set) for every upstream exit referenced by an egress rule,
     required if it is new in this bundle or passed in the baseline. An exit
     that was already down before the apply is not required (no rollback for
     a pre-existing outage); it is reported as a warning;
   - `reconciler` — a pass after the apply with `last_error == null`,
     followed by a pass with an empty plan (converged, no drift).
5. **Confirm**: `current := v`, prepend to `confirmed`, prune to 3, clear
   `pending`, promote `next_signing_pubkey` (Trust store), report
   `confirmed`.
6. **Rollback** (deadline passed): provider switches back to `previous`,
   `run_once()`, `pending` cleared, report `rolled_back` with the failed
   checks. Then a 30 s check of `fabric` under `previous` decides the blame:
   - fabric healthy → the bundle broke it: `failed[v]`, never retried;
     a newer version from the hub is needed;
   - fabric still down → the hub or the path is down, not the bundle:
     `deferred = {v, attempts}`; retried automatically once fabric has been
     healthy for 30 s, at most 3 attempts, then `failed`.

Fail closed throughout: every step is a complete desired state compiled by
`kornode.net`, so kill-switches of the exits in use are installed before any
tunnel of the new bundle is dialled and stay in place during rollback.

Local rollback (`bundle rollback <v>`, hub command `rollback`) applies a
cached confirmed version with the same confirm window; it is reported, and
the hub's next bundle is above `high_water` as usual.

### Autonomy

- Hub unreachable: keep current state; tunnels retry with backoff (1 s → 60 s,
  jitter); no bundle expiry.
- Boot without hub: apply the cached current bundle immediately (no confirm
  window: it was confirmed before).
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
