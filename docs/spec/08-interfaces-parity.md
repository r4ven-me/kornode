# 08 — Management interfaces and parity

Every hub capability is available in three equal forms:

1. `korctl` command (works with `web.enabled: false`);
2. admin REST API endpoint (`/api/...`, existing auth);
3. panel control (React), calling that endpoint.

All three call the same service method. No business logic in Typer commands,
FastAPI routes or React hooks beyond argument parsing/validation display.

Agents have only the local `kornode-agent` CLI (06); their remote management
is the hub's `agent` capabilities.

## Manifest

`parity.yaml` at the repo root:

```yaml
capabilities:
  - id: agent.create
    service: kornode.registry.RegistryService.create_agent
    cli: "agent create"
    api: "POST /api/agents"
    ui: agent.create            # matches data-capability="agent.create" in frontend/src
  - id: hub.backup
    service: kornode.services.backup.BackupService.create
    cli: "hub backup"
    api: "POST /api/hub/backup"
    ui: hub.backup
  - id: net.run
    cli: "net run"
    api: null
    ui: null
    exempt: "process entrypoint for supervisor, not a management action"
```

`tests/test_parity.py`:

- every `cli` path resolves to a command in the Typer app;
- every `api` resolves to a route in the FastAPI app (method + path);
- every `ui` id appears as `data-capability="<id>"` in `frontend/src/**/*.tsx`;
- every Typer command and every `/api` route (except auth/session plumbing
  listed in `parity_ignore`) appears in some capability — no unlisted
  surfaces;
- `exempt` requires a reason string.

`make parity` runs it; CI runs it in the backend job.

## Capability matrix (new in v2)

| ID | korctl | API | Panel |
| --- | --- | --- | --- |
| agent.list | `agent list [--json]` | `GET /api/agents` | Agents → table |
| agent.show | `agent show <name>` | `GET /api/agents/{name}` | Agents → detail |
| agent.create | `agent create <name> [--id N] [--role access] [--description]` | `POST /api/agents` | Add agent dialog |
| agent.token | `agent token <name>` (re-issue) | `POST /api/agents/{name}/token` | Detail → Enrollment |
| agent.update | `agent set <name> --role/--description/--transport ...` | `PATCH /api/agents/{name}` | Detail → Settings |
| agent.revoke | `agent revoke <name>` | `POST /api/agents/{name}/revoke` | Detail → Revoke |
| agent.delete | `agent delete <name>` | `DELETE /api/agents/{name}` | Detail → Delete |
| agent.prefixes | `agent prefix add/del/list <name> <cidr> [--kind lan] [--no-export]` | `GET/POST/DELETE /api/agents/{name}/prefixes` | Detail → Networks |
| agent.policy | `agent egress show/edit/set <name> [--file]` | `GET/PUT /api/agents/{name}/policy` | Detail → Egress editor |
| agent.sources | `agent source add/del/list <name> ...` | `GET/POST/DELETE /api/agents/{name}/sources` | Detail → Sources |
| agent.externals | `agent upstream add/del/list/set <name> ...` | `/api/agents/{name}/upstreams` | Detail → Upstreams |
| agent.users | `agent user add/del/list/passwd/enable/disable <name> ...` | `/api/agents/{name}/users` | Detail → Users (role access) |
| agent.bundle | `agent bundle list/show/diff <name> [v1] [v2]` | `GET /api/agents/{name}/bundles[/{v}]`, `GET .../diff?a=&b=` | Detail → Bundles |
| agent.reports | `agent status <name> [--watch]` | `GET /api/agents/{name}/reports?limit=` | Detail → Status |
| agent.command | `agent exec <name> reconnect/explain/collect-diag/restart/rollback ...` | `POST /api/agents/{name}/commands`, `GET .../commands/{id}` | Detail → Actions |
| fabric.show | `fabric show` | `GET /api/fabric` | Fabric → Topology |
| fabric.settings | `fabric set --cidr/--domain/...` | `PATCH /api/fabric` | Fabric → Settings |
| dns.records | `dns record add/del/list` | `/api/dns/records` | Fabric → DNS |
| egress.hub | `egress show/edit/set/check` | `GET/PUT /api/egress`, `POST /api/egress/check` | Network → Egress |
| sources.hub | `source add/del/list` | `/api/sources` | Network → Sources |
| sets | `set add/del/list/refresh` | `/api/sets` | Network → Sets |
| net.plan | `net plan` | `GET /api/net/plan` | Network → Plan |
| net.apply | `net apply [--dry-run]` | `POST /api/net/apply` | Network → Apply |
| net.explain | `net explain <src> <dst> [...]` | `POST /api/net/explain` | Network → Explain |
| net.doctor | `doctor [--json]` | `GET /api/diagnostics/doctor` | Diagnostics → Doctor |
| control.status | `control status` | `GET /api/control` | Agents → header |
| control.rotate_key | `control rotate-signing-key` | `POST /api/control/rotate-signing-key` | Settings → Control plane |
| hub.backup | `hub backup [--out]` | `POST /api/hub/backup` (streams file) | Settings → Backup |
| hub.restore | `hub restore <file>` | `POST /api/hub/restore` (upload) | Settings → Backup |
| clients.* | existing `user ...` (+ alias `client ...`) | existing `/api/users` | Clients (renamed from Users) |
| externals.hub | existing `upstream ...` (+ alias `external ...`) | existing `/api/upstream` | External servers (renamed) |

Output conventions: every `korctl` command supports `--json`; human output is
a table. Exit codes as in 06. API errors use the `{error, message, details}`
shape. The panel shows `details` (e.g. overlap conflicts) inline next to the
field that caused them.

## Panel structure (hub)

Top-level sections: Dashboard · Clients · Agents · External servers ·
Network (egress, sources, sets, plan, explain) · Fabric (topology, DNS) ·
Certificates · Logs · Diagnostics · Settings.
