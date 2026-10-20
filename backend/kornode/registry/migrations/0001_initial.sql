CREATE TABLE nodes (
  id            INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 254),
  name          TEXT NOT NULL UNIQUE CHECK (name GLOB '[a-z]*'),
  description   TEXT NOT NULL DEFAULT '',
  roles         TEXT NOT NULL DEFAULT '[]',
  state         TEXT NOT NULL CHECK (state IN ('pending','active','revoked')),
  cert_serial   TEXT, cert_not_after TEXT,
  seal_pubkey   BLOB,
  policy        TEXT NOT NULL DEFAULT '{}',
  transport     TEXT NOT NULL DEFAULT '{}',
  desired_version INTEGER NOT NULL DEFAULT 0,
  applied_version INTEGER NOT NULL DEFAULT 0,
  high_water_version INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE externals (
  node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  name     TEXT NOT NULL,
  spec     TEXT NOT NULL,
  secrets  BLOB,
  PRIMARY KEY (node_id, name)
);
CREATE TABLE access_users (
  node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  pw_hash  TEXT,
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
  content_hash TEXT NOT NULL, key_id TEXT NOT NULL,
  created_at TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY (node_id, version)
);
CREATE TABLE reports (
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  received_at TEXT NOT NULL, body TEXT NOT NULL
);
CREATE TABLE commands (
  id TEXT PRIMARY KEY, node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  type TEXT NOT NULL, args TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL CHECK (state IN ('queued','delivered','done','failed','expired')),
  created_at TEXT NOT NULL, delivered_at TEXT, finished_at TEXT, result TEXT,
  expires_at TEXT NOT NULL
);
CREATE TABLE audit (
  at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, details TEXT
);
CREATE INDEX reports_node_id_received_at_idx ON reports(node_id, received_at);
CREATE INDEX commands_node_id_state_idx ON commands(node_id, state);
CREATE INDEX enroll_tokens_expires_at_idx ON enroll_tokens(expires_at);
