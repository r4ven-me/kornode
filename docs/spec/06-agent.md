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
  `ocserv` (role `access` only), `dnsmasq` (when the bundle enables DNS: the
  agent writes `run/dnsmasq.conf` and starts/restarts/stops the program through
  the supervisor's local socket; `autostart=false`, D-66).
- Target: image ≤ 400 MB (measured 396 MB on python:3.12-slim-trixie + openconnect/nftables/supervisor, D-61), RSS of `agent` ≤ 80 MB idle.

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
  run/agent.lock             # exclusive process/enroll lock; inode is never unlinked
  run/agent.sock             # owner-only local RPC (0600), not a TCP listener
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
| `bundle rollback <version> [--dry-run]` | Local emergency rollback to a cached confirmed version (reported to hub); preview verifies the cache without applying. |
| `diag [--out file.tar.gz]` | Same archive as the `collect_diag` command. |
| `reconnect [<tunnel>] [--dry-run]` | Restart one named exit (`fabric`, `upstream:<name>`), or all; preview makes no network changes. |
| `version` | Versions of agent and components. |

Exit codes: 0 ok, 1 error, 2 usage, 3 validation conflict, 4 hub unreachable.
All commands support `--json` before or after the command/subcommand. No command
prints secrets. JSON success output is the command's data object; errors are
`{ok: false, error, message, exit_code}`. Usage errors never echo rejected values
(which could be enrollment tokens). Human output is labeled text, nested data is
indented JSON. `run` remains a supervisor entrypoint (its internal restart code 75
is unchanged).

### Local CLI transport (P3-07, D-55)

- `--root` (before the command), or `KORNODE_AGENT_DIR`, selects the agent directory;
  default `/var/lib/kornode-agent`.
- `status` uses the running process and an mTLS hub ping. A failed hub ping returns
  the status **and exit 4**. With no local listener it reads `state.json` without
  contacting the hub, returns exit 0 and `running: false`, and leaves
  `hub_reachable`, `tunnels`, `sources`, `reconciler` as `null` (unknown, not healthy).
  An unreadable/corrupt local state is an error, not a fabricated healthy state.
- `bundle show` and `bundle history` work without the process or hub. Show verifies
  the exact cached body/signature, node id, schema and sealed values with the same
  cached-bundle validator used at boot, including retired-key bounds. It does not
  change state/trust or weaken replay protection. Bootstrap version 0 has no body;
  show returns conflict (3). History lists retained version metadata/results;
  `cached` means the files exist, not that their signature has been checked.
- `explain`, `doctor`, `diag`, `reconnect`, `bundle rollback` require the running
  process, but not a reachable hub. A missing process is exit 1, not exit 4; none
  starts a second reconciler. Rollback still requires the existing confirm window,
  including fabric health, so an unreachable hub may prevent confirmation.
- RPC: one JSON request line, one response line, fixed operations only (`status`,
  `explain`, `doctor`, `diag`, `reconnect`, `rollback`), strict argument validation.
  Requests ≤ 8 KiB, responses ≤ 8 MiB; incomplete frames expire after 5 s. The
  diagnostic archive is base64 inside RPC, never in CLI stdout. Client deadlines
  are 120 s for reads, 1500 s for mutations (a confirm window can be 600 s and
  another apply can already hold the lock). A timeout is **not** permission to
  retry a mutation blindly: inspect status first; an accepted operation can finish
  after the client disconnects. There is no automatic retry.
- Process lock is acquired before boot, held through shutdown/worker completion;
  concurrent `run` or `enroll --force` is refused. Socket permissions are set
  **before listen**. Only a stale socket owned by this uid is replaced; regular
  files and symlinks are refused. A clean shutdown removes its own socket only.
- Local and hub mutations share `Agent.perform`, `Applier.rollback_to`, the same
  apply lock and reporting event. Cancellation does not release that lock while a
  worker still changes state. Local rollback never lowers `high_water`.
- `explain` uses `kornode.net.explain` and read-only `Kernel.route_get`. `--proto`
  and `--port` are validated and included in the query; the current egress model
  is address-based and the kernel lookup is mark-based, so an explicit warning
  says these are **not L4 filters or a protocol-specific connectivity probe**.
- `doctor` is read-only: desired/actual diff, sysctls, routes/guards, policy rules,
  owned nft sets/schema, sources, connected-network overlaps, MTUs and certificate
  dates. Errors produce exit 1, warnings/info alone exit 0. Unavailable checks are
  findings, not success. nft version is informational, foreign NAT is conservatively
  flagged for review (matching owned traffic is not proven); clock skew is explicitly
  unchecked without a trusted hub-time observation. Findings join reports and diag.
- `diag` uses the same collector as `collect_diag`: read-only rules/routes/nft,
  report, state, doctor, bounded log tails (100 kB/file, 2 MiB total). Symlink logs
  are excluded. It masks known current/cached credentials, secret fields, sealed
  objects, private-key blocks/tails, auth headers and secret URL queries. Keys,
  bootstrap config and raw bundles are not archived. Archive ≤ 5 MiB, output mode
  0600, atomic no-clobber publication (existing files/symlinks are never overwritten).
  Without `--out`, writes `kornode-agent-diag-<time_ns>.tar.gz` in the current directory.

## Role `access`

- Bundle contains `access`: ocserv settings subset (port, auth methods:
  password/certificate), `users` (username, ocpasswd hash, groups, enabled),
  `groups` (config-per-group bodies), CA for client certs.
- The agent renders `ocserv.conf`, `ocpasswd`, group configs with the same
  renderers as the hub (`kornode.renderers.ocserv` is shared; keep it free of
  hub-only imports).
- Client pool and DNS are the node's derived values.
- User changes on the hub → new bundle → agent applies → `occtl reload`.
