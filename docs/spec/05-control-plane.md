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
  desired_version INTEGER NOT NULL DEFAULT 0,       -- latest stored bundle version
  applied_version INTEGER NOT NULL DEFAULT 0,       -- from the last report
  high_water_version INTEGER NOT NULL DEFAULT 0,    -- highest version the agent ever accepted (D-37)
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
  version INTEGER NOT NULL, sha256 TEXT NOT NULL, body BLOB NOT NULL, signature TEXT NOT NULL,
  content_hash TEXT NOT NULL, key_id TEXT NOT NULL,  -- dedup and signing key (Bundle)
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
CREATE INDEX reports_node_id_received_at_idx ON reports(node_id, received_at);
CREATE INDEX commands_node_id_state_idx ON commands(node_id, state);
CREATE INDEX enroll_tokens_expires_at_idx ON enroll_tokens(expires_at);
```

The registry DB file is created `0600` (the mode of `data_dir` is left alone). A
snapshot worker checks hourly and writes at most one snapshot per 24 h to
`data_dir/backups/registry/registry-YYYYMMDDTHHMMSSZ.db` using `VACUUM INTO`
and an atomic replace. Snapshot copies are `0600`, verified with
`PRAGMA integrity_check`, and the newest 7 are retained.

All writes go through `RegistryService` (one class, used by CLI, admin API and
control API). Any mutation affecting an agent's bundle recompiles it in the
same transaction (see Bundle → Compilation); `desired_version` moves only
when the compiled content changed.

## Enrollment

1. Operator: `korctl agent create <name> [--id N] [--role access]` → node row
   `pending` + token. Panel: "Add agent" dialog, same service.
2. Token (shown once), base64url of:
   ```json
   {"v":1,"hub":"vpn.example.com:443","pin":"pin-sha256:…","user":"enroll-3-k2f9",
    "secret":"<32 random bytes b64>","camouflage":"<optional>","exp":"2026-10-11T16:41:00Z"}
   ```
   Hub stores `hash(secret)` and creates an ocserv user `enroll-3-k2f9` with the
   same password in group `enroll` (restricted to `10.99.0.1/32` tcp/8444 by
   the hub nft rule set, D-44), expiring at `exp`.
3. Agent `kornode-agent enroll <token>`: generates TLS key (ECDSA P-256) and
   X25519 seal key locally; connects openconnect with the enroll user (pinning
   `pin`); calls `POST /agent/v1/enroll` (server-auth TLS only, since it has no
   client cert yet) with `{token_id, secret, csr_pem, seal_pubkey_b64, facts}`.
4. Hub verifies secret, signs CSR with CN=`agent-<id>`, OU=`agents`, lifetime
   `cert_lifetime_days`; marks token used; deletes the enroll ocserv user;
   sets node `active`; returns `{cert_pem, ca_pem, node_id, signing_keys:
   [{key_id, pubkey_b64}], bundle: {version, body_b64, signature}}`.
5. Agent writes `agent.yaml` (bootstrap), disconnects the enroll session,
   connects with its certificate, applies the first bundle with confirm
   (on rollback it stays in the bootstrap state, 06), starts the run loop.

Failure modes: expired/used token → 410; wrong secret → 403 + audit; node not
pending → 409. Enroll endpoint rate-limited per source address (5/min).

## Bundle

Shared code lives in `backend/kornode/bundle/` (models, canonical encoding,
sign/verify, seal/unseal). It imports only stdlib, `pydantic`,
`cryptography` and `kornode.net`, enforced by an AST import test like
`tests/test_net_imports.py`; the hub compiler and the agent both use it (D-34).

### Body

- JSON per `schemas/bundle.v1.schema.json`, encoded as
  `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()`.
  No floats anywhere in the body. Maximum size 1 MiB; the agent refuses a
  larger body before verifying it.
- The canonical form matters only to the hub (stable `sha256`, dedup). The
  agent never re-encodes: it verifies, caches and parses the exact bytes it
  received.
- `generated_at` is informational. Nothing on the agent depends on time
  (bundles never expire, D-08).

### Signature (D-35)

- Ed25519 over `b"kornode.bundle.v1\x00" + body` (domain separation: the
  signing key can never be tricked into signing something that is also a
  valid message for another purpose).
- Envelope string: `ed25519:<key_id>:<b64 signature>`, where `key_id` is the
  first 16 hex chars of `sha256(raw public key)`. It travels as header
  `X-Kornode-Signature` (`/bundle`), as the `signature` field (`/poll`, enroll
  result) and is stored next to the cached body as `<version>.sig`.
- The signing key is `control.signing_key` (PKCS#8 PEM, 0600), created on first
  start. The hub's processes that mutate the registry (admin API, `korctl`,
  control API) compile and sign; they run as the same user.

### Sealed secrets (D-16, D-36)

Every value of a field typed `sealed` in the schema is
`{"alg":"x25519-hkdf-sha256-chacha20poly1305","epk":"<b64>","nonce":"<b64>","ct":"<b64>"}`:

- fresh ephemeral X25519 key per value; `shared = X25519(eph, agent seal_pubkey)`;
- `key = HKDF-SHA256(ikm=shared, salt=epk || seal_pubkey, info=I, length=32)`;
- `I = "kornode-bundle-secret-v1|<node_id>|<path>"`, where `<path>` is the
  RFC 6901 JSON pointer of the sealed object in the body
  (`/tunnels/upstreams/0/password`);
- `ct = ChaCha20-Poly1305(key, nonce = 12 random bytes, plaintext, aad = I)`.

Binding the path in both `info` and `aad` stops a hub-side bug or an attacker
with write access to the cache from moving a ciphertext into another field.
Plaintext is UTF-8 text; binary material (keys) is PEM.

### Versions and dedup (D-37)

- Versions are per node, strictly increasing, gaps allowed; the hub never
  reuses a number. The next version is
  `max(latest bundle version, nodes.desired_version, nodes.high_water_version) + 1`,
  where `high_water_version` is the highest version the agent reports having
  accepted (see Recovery).
- Sealing is randomized, so two compilations of the same input differ byte
  for byte. Dedup uses `content_hash = sha256` of the canonical body with
  `version` and `generated_at` removed and every sealed object replaced by
  `{"hmac": HMAC-SHA256(master_key, I || 0x00 || plaintext)}`. A new version
  is stored only when `content_hash` differs from the latest one.
  `bundles` gains columns `content_hash TEXT NOT NULL` and
  `key_id TEXT NOT NULL`.

### Compilation (D-38)

`BundleService.compile(node_id, reason)` is a pure function of the registry
(read inside the caller's transaction) plus the hub's YAML settings (hub
host/port/pin, fabric). It runs synchronously in the same transaction as
every registry mutation that can affect a bundle (a fabric-wide change, such
as a new node's prefixes, recompiles every active agent; that is at most 253
small JSON documents), on hub YAML save, and once at control API startup.
No queue, no debounce: content-hash dedup makes recompiling unchanged nodes
free, and `desired_version` is never ahead of the stored bundle.

Before storing, the compiler runs the agent-side validator (below) on its
own output and refuses to store a bundle that would fail it; the mutation
is rolled back with an `invalid` error.

### Validator (shared, agent and hub)

A bundle is valid only if, in this order:

1. the body is ≤ 1 MiB and the signature verifies with a trusted key (before
   any JSON parsing);
2. it parses into the pydantic `Bundle` model (mirror of the JSON schema;
   a unit test checks every example against both);
3. `format`, `node_id` match; `version > high_water_version`;
   `min_agent_version ≤` the running agent version;
4. every sealed value unseals;
5. `kornode.net` compiles `policy` with the bundle's addresses and the
   validator reports no errors;
6. the fabric tunnel and the `fabric` exit are present (a bundle cannot
   remove the agent's path to the hub, 11).

## Control API (agent-facing, mTLS, `/agent/v1`)

Agent identity = certificate CN `agent-<id>`; every request is authorized
against `nodes.state == 'active'` and CRL.

| Method & path | Request | Response |
| --- | --- | --- |
| `POST /agent/v1/enroll` | see Enrollment (no client cert) | 200 enrollment result |
| `GET /agent/v1/ping` | — | 204; the agent's `fabric` health check (06) |
| `GET /agent/v1/bundle?since=<v>&wait=<s>` | — | 200 raw body bytes + `X-Kornode-Signature` + `X-Kornode-Version`; 304 if no newer version within `wait` (≤ `long_poll_seconds`) |
| `POST /agent/v1/report` | report JSON (below) | 204 |
| `GET /agent/v1/commands?wait=<s>` | — | 200 list of commands (marks delivered); 204 none |
| `POST /agent/v1/commands/<id>/result` | `{ok, output, artefact_b64?}` (≤ 5 MB) | 204 |
| `POST /agent/v1/renew` | `{csr_pem}` | 200 `{cert_pem}`; allowed when ≥ 2/3 of lifetime elapsed |

Agents may combine bundle and command polling: `GET /agent/v1/poll?since=<v>&wait=<s>`
returns `{"bundle": {"version": 43, "body_b64": "...", "signature": "ed25519:..."} | null,
"commands": [...]}`; it is the default client path, the two separate endpoints
exist for diagnostics. The body travels base64-encoded so the exact signed
bytes survive the JSON envelope.

Long-poll waiters live in the control API process and re-check
`nodes.desired_version` every 500 ms (the registry is written by other
processes; SQLite is the only shared channel). A request with `since` greater
than the hub's latest version triggers a recompile (see Recovery) and is
answered with the new version.

Errors: JSON `{"error": "<code>", "message": "..."}`; codes: `unauthorized`,
`revoked`, `not_found`, `conflict`, `rate_limited`, `invalid`, `internal`.

## Report

```json
{
  "node_id": 3, "agent_version": "2.0.0", "time": "2026-10-11T12:00:00Z",
  "applied_version": 42, "pending_version": null, "high_water_version": 43,
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

- Hub restored from an older backup: the agent reports (or polls with) a
  version greater than the hub's latest. The hub stores it as
  `nodes.high_water_version` and recompiles; the next version is above it
  (D-37), so versions stay monotonic for the agent without any error
  round-trip. A bundle compiled before the hub learned the high-water mark
  is rejected by the agent as a replay, which reports again; the loop
  converges in one poll.
- Signing key rotation: `korctl control rotate-signing-key` creates a new key,
  next bundles carry `next_signing_pubkey` for 7 days signed by the old key,
  then switch. Agents accept a key change only via a bundle signed by the
  current key, and add `next_signing_pubkey` to their trust store only when
  that bundle is confirmed. The old key is kept only to verify cached bundles
  it signed (06, trust store).
- Agent deleted on hub: node `revoked`, cert added to CRL, prefixes released
  (id quarantined, 01).
