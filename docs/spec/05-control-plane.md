# 05 — Control plane (hub)

## Hub configuration

```yaml
control:
  enabled: true                 # implies fabric.enabled
  port: 8444                    # bound to the hub fabric address 10.99.0.1 only
  long_poll_seconds: 60
  report_interval_seconds: 30
  offline_after_seconds: 90
  cert_lifetime_days: 90
  enroll_token_ttl_minutes: 60
  bundle_history: 20            # versions kept per agent in the registry
  signing_key: ${data_dir}/control/signing.ed25519   # created on first start, 0600
```

Supervisor program `control-api` runs `uvicorn kornode.control.app:create_app`
on `10.99.0.1:8444` with mTLS (`ssl_cert_reqs=CERT_REQUIRED`, CA = kornode CA,
CRL checked per request). Independent of `web.enabled`.

The hub's fabric address `10.99.0.1/32` is bound to `lo` by the reconciler.

## Registry (SQLite, `data_dir/registry.db`)

WAL mode, `foreign_keys=ON`, migrations in `backend/kornode/registry/migrations/NNNN_*.sql`,
applied at startup in a transaction; schema version in `PRAGMA user_version`.

```sql
CREATE TABLE nodes (
  id            INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 254),
  name          TEXT NOT NULL UNIQUE CHECK (name GLOB '[a-z]*'),
  description   TEXT NOT NULL DEFAULT '',
  roles         TEXT NOT NULL DEFAULT '[]',         -- JSON array: "access", "exit"
  state         TEXT NOT NULL CHECK (state IN ('pending','active','revoked')),
  cert_serial   TEXT, cert_not_after TEXT,
  seal_pubkey   BLOB,                               -- X25519 public key (32 bytes)
  policy        TEXT NOT NULL DEFAULT '{}',         -- JSON: egress, sources, sets (02)
  transport     TEXT NOT NULL DEFAULT '{}',         -- JSON: transport, dpd, keepalive, camouflage
  desired_version INTEGER NOT NULL DEFAULT 0,
  applied_version INTEGER NOT NULL DEFAULT 0,
  last_seen     TEXT,
  created_at    TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE node_prefixes (
  node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  prefix   TEXT NOT NULL,
  kind     TEXT NOT NULL CHECK (kind IN ('pool','source','lan')),
  export   INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (node_id, prefix)
);
CREATE TABLE externals (                            -- external upstream profiles, per node (hub = 1)
  node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  name     TEXT NOT NULL,
  spec     TEXT NOT NULL,                           -- JSON, UpstreamProfile without secrets
  secrets  BLOB,                                    -- encrypted with hub master key
  PRIMARY KEY (node_id, name)
);
CREATE TABLE access_users (                         -- users of agents with role 'access'
  node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  pw_hash  TEXT,                                    -- ocpasswd-compatible hash
  groups   TEXT NOT NULL DEFAULT '[]',
  enabled  INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (node_id, username)
);
CREATE TABLE dns_records (
  name TEXT NOT NULL, type TEXT NOT NULL CHECK (type IN ('A','AAAA','CNAME')),
  value TEXT NOT NULL, node_id INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
  PRIMARY KEY (name, type, value)
);
CREATE TABLE enroll_tokens (
  id TEXT PRIMARY KEY, node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  ocserv_user TEXT NOT NULL UNIQUE, secret_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL, used_at TEXT
);
CREATE TABLE bundles (
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  version INTEGER NOT NULL, sha256 TEXT NOT NULL, body BLOB NOT NULL, signature BLOB NOT NULL,
  created_at TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY (node_id, version)
);
CREATE TABLE reports (
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  received_at TEXT NOT NULL, body TEXT NOT NULL      -- last 500 per node kept
);
CREATE TABLE commands (
  id TEXT PRIMARY KEY, node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  type TEXT NOT NULL, args TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL CHECK (state IN ('queued','delivered','done','failed','expired')),
  created_at TEXT NOT NULL, delivered_at TEXT, finished_at TEXT, result TEXT,
  expires_at TEXT NOT NULL
);
CREATE TABLE audit (                                 -- reuse existing audit service if suitable
  at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, details TEXT
);
```

All writes go through `RegistryService` (one class, used by CLI, admin API and
control API). Any mutation affecting an agent's bundle increments
`desired_version` in the same transaction and enqueues bundle compilation.

## Enrollment

1. Operator: `korctl agent create <name> [--id N] [--role access]` → node row
   `pending` + token. Panel: "Add agent" dialog, same service.
2. Token (shown once), base64url of:
   ```json
   {"v":1,"hub":"vpn.example.com:443","pin":"pin-sha256:…","user":"enroll-3-k2f9",
    "secret":"<32 random bytes b64>","camouflage":"<optional>","exp":"2026-10-11T16:41:00Z"}
   ```
   Hub stores `hash(secret)` and creates an ocserv user `enroll-3-k2f9` with the
   same password in group `enroll` (restricted to `10.99.0.1/32` tcp/8444,
   S-04), expiring at `exp`.
3. Agent `kornode-agent enroll <token>`: generates TLS key (ECDSA P-256) and
   X25519 seal key locally; connects openconnect with the enroll user (pinning
   `pin`); calls `POST /agent/v1/enroll` (server-auth TLS only, since it has no
   client cert yet) with `{token_id, secret, csr_pem, seal_pubkey_b64, facts}`.
4. Hub verifies secret, signs CSR with CN=`agent-<id>`, OU=`agents`, lifetime
   `cert_lifetime_days`; marks token used; deletes the enroll ocserv user;
   sets node `active`; returns `{cert_pem, ca_pem, node_id, hub_signing_pubkey,
   first bundle + signature}`.
5. Agent disconnects the enroll session, connects with its certificate,
   applies the first bundle with confirm, starts the run loop.

Failure modes: expired/used token → 410; wrong secret → 403 + audit; node not
pending → 409. Enroll endpoint rate-limited per source address (5/min).

## Bundle

- Body: JSON per `schemas/bundle.v1.schema.json`, UTF-8, keys sorted,
  no insignificant whitespace (canonical form so `sha256` is stable).
- Signature: Ed25519 over the exact body bytes, delivered as header
  `X-Kornode-Signature: ed25519:<b64>` and stored next to the cache file.
- Sealed secrets: values in `secrets` objects are
  `{"alg":"x25519-hkdf-sha256-chacha20poly1305","epk":"<b64>","nonce":"<b64>","ct":"<b64>"}`,
  HKDF info `kornode-bundle-secret-v1|<node_id>|<field path>`.
- Versions are per node, strictly increasing; the hub never reuses a number.
- Compilation is triggered by any relevant registry change and debounced 1 s;
  a new version is created only if the body differs from the latest.

## Control API (agent-facing, mTLS, `/agent/v1`)

Agent identity = certificate CN `agent-<id>`; every request is authorized
against `nodes.state == 'active'` and CRL.

| Method & path | Request | Response |
| --- | --- | --- |
| `POST /agent/v1/enroll` | see Enrollment (no client cert) | 200 enrollment result |
| `GET /agent/v1/bundle?since=<v>&wait=<s>` | — | 200 body + signature header + `X-Kornode-Version`; 304 if no newer version within `wait` (≤ `long_poll_seconds`) |
| `POST /agent/v1/report` | report JSON (below) | 204; 409 if `applied_version` > `desired_version` (agent ahead — hub restored from backup), see Recovery |
| `GET /agent/v1/commands?wait=<s>` | — | 200 list of commands (marks delivered); 204 none |
| `POST /agent/v1/commands/<id>/result` | `{ok, output, artefact_b64?}` (≤ 5 MB) | 204 |
| `POST /agent/v1/renew` | `{csr_pem}` | 200 `{cert_pem}`; allowed when ≥ 2/3 of lifetime elapsed |

Agents may combine bundle and command polling: `GET /agent/v1/poll?since=<v>&wait=<s>`
returns `{bundle?: {...}, commands: [...]}`; it is the default client path,
the two separate endpoints exist for diagnostics.

Errors: JSON `{"error": "<code>", "message": "..."}`; codes: `unauthorized`,
`revoked`, `not_found`, `conflict`, `rate_limited`, `invalid`, `internal`.

## Report

```json
{
  "node_id": 3, "agent_version": "2.0.0", "time": "2026-10-11T12:00:00Z",
  "applied_version": 42, "pending_version": null,
  "last_apply": {"version": 42, "result": "confirmed", "at": "...", "error": null},
  "rollbacks": [{"from": 43, "to": 42, "at": "...", "reason": "health: hub unreachable"}],
  "tunnels": [{"name": "fabric", "iface": "oc-hub0", "up": true, "since": "...",
               "carrier": "203.0.113.10:443", "transport": "tcp", "mtu": 1399,
               "rx_bytes": 0, "tx_bytes": 0}],
  "sources": [{"name": "amnezia", "iface": "awg0", "present": true}],
  "local_networks": ["192.168.3.0/24", "172.17.0.0/16"],
  "reconciler": {"last_apply": "...", "drift_events": {"route_deleted": 1}, "last_error": null},
  "doctor": [{"severity": "warning", "code": "foreign_nat", "message": "..."}],
  "versions": {"openconnect": "9.12", "nft": "1.1.3", "kernel": "6.12.0"}
}
```

Reports are sent every `report_interval_seconds` and immediately on apply,
rollback, tunnel state change. A node is `offline` when `now - last_seen >
offline_after_seconds`.

## Commands

| Type | Args | Result |
| --- | --- | --- |
| `reconnect` | `{tunnel?: name}` | `{ok}` |
| `explain` | `{src, dst, proto?, port?}` | Decision (04) |
| `collect_diag` | `{}` | tar.gz (≤ 5 MB): rules, routes, nft, logs tail, doctor, report |
| `restart` | `{}` | `{ok}` (agent restarts its process after replying) |
| `rollback` | `{to_version}` | `{ok}` — applies a cached version; hub marks it as pinned until next change |

Commands expire after 10 minutes undelivered. No free-form shell exists.

## Recovery and edge cases

- Hub restored from an older backup: agent reports `applied_version` greater
  than the hub's latest; hub responds 409 and bumps `desired_version` to
  `applied_version + 1`, recompiling from current registry, so versions stay
  monotonic for the agent.
- Signing key rotation: `korctl control rotate-signing-key` creates a new key,
  next bundles carry `next_signing_pubkey` for 7 days signed by the old key,
  then switch. Agents accept a key change only via a bundle signed by the
  current key.
- Agent deleted on hub: node `revoked`, cert added to CRL, prefixes released
  (id quarantined, 01).
