CREATE TABLE node_id_quarantine (
  node_id INTEGER PRIMARY KEY CHECK (node_id BETWEEN 2 AND 254),
  until_at TEXT NOT NULL
);
CREATE TABLE control_rotation (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  active_path TEXT NOT NULL,
  next_path TEXT NOT NULL,
  started_at TEXT NOT NULL
);
