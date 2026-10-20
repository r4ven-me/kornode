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
    service: kornode.services.agents.AgentService.create
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
| agent.sources | `agent source add/set <name> <source> --file <json>`; `del/list` | `GET /api/agents/{name}/sources`, `PUT/DELETE .../sources/{source}` | Detail → Networks and sources |
| agent.externals | `agent upstream add/set <name> <upstream> --file <json>`; `del/list` | `GET /api/agents/{name}/upstreams`, `PUT/DELETE .../upstreams/{upstream}` | Detail → Upstreams |
| agent.access | `agent access show/set/del <name> [--hostname H --port P --udp --reissue]` | `GET/PUT/DELETE /api/agents/{name}/access` | Detail → Access listener and users (role access) |
| agent.users | `agent user add/del/list/passwd/enable/disable <name> ...`; `set --file <json>` | `GET /api/agents/{name}/users`, `PUT/DELETE .../users/{username}` | Detail → Access listener and users (role access; delivered in the bundle) |
| agent.bundle | `agent bundle list/show/diff <name> [v1] [v2]` | `GET /api/agents/{name}/bundles[/{v}]`, `GET .../diff?a=&b=` | Detail → Bundles |
| agent.reports | `agent status <name> [--watch]` | `GET /api/agents/{name}/reports?limit=` | Detail → Status |
| agent.command | `agent exec <name> reconnect/explain/collect-diag/restart/rollback ...` | `POST /api/agents/{name}/commands`, `GET .../commands/{id}` | Detail → Actions |
| fabric.show | `fabric show` | `GET /api/fabric` | Fabric → Topology |
| fabric.settings | `fabric set --cidr/--domain/...` | `PATCH /api/fabric` | Fabric → Settings |
| dns.records | `dns record add/del <name> <type> <value> [--node <agent>]`, `dns record list` | `GET/POST/DELETE /api/dns/records` | Agents → Fabric DNS (Fabric → DNS from P4-07) |
| egress.hub | `egress show/edit/set/check` | `GET/PUT /api/egress`, `POST /api/egress/check` | Network → Egress |
| sources.hub | `source add/del/list` | `/api/sources` | Network → Sources |
| sets | `set add/del/list/refresh` | `/api/sets` | Network → Sets |
| net.plan | `net plan` | `GET /api/net/plan` | Network → Plan |
| net.apply | `net apply [--dry-run]` | `POST /api/net/apply` | Network → Apply |
| net.explain | `net explain <src> <dst> [...]` | `POST /api/net/explain` | Network → Explain |
| net.doctor | `doctor [--json]` | `GET /api/diagnostics/doctor` | Diagnostics → Doctor |
| control.status | `control status` | `GET /api/control` | Agents → header |
| control.rotate_key | `control rotate-signing-key [--yes] [--dry-run]` | `POST /api/control/rotate-signing-key` | Agents → header |
| hub.backup | `hub backup [--out] [--passphrase-file] [--json]` | `POST /api/hub/backup` (streams encrypted file) | Config → Backup / Restore |
| hub.restore | `hub restore <file> [--target] [--passphrase-file] [--dry-run] [--yes] [--json]` | `POST /api/hub/restore` (encrypted binary upload; default validate-only) | Config → Backup / Restore |
| clients.* | existing `user ...` (+ alias `client ...`) | existing `/api/users` | Clients (renamed from Users) |
| externals.hub | existing `upstream ...` (+ alias `external ...`) | existing `/api/upstream` | External servers (renamed) |

Output conventions: every `korctl` command supports `--json`; human output is
a table. Exit codes as in 06. API errors use the `{error, message, details}`
shape. The Agents panel shows sanitized validation field paths and conflict details
in its error area, without echoing credential input values.

## P3-09 implementation and usage

`hub.backup` and `hub.restore` have CLI/API/UI parity through the same
`BackupService`, two manifest rows without exemptions. Passphrases are provided by
hidden CLI prompts/private files or write-only API/UI input, never command-line
secret arguments or query strings. Downloads and errors are no-store; cookie
mutations require CSRF. Restore validates first, stages a new private tree only,
and returns a manual activation path; it never switches the running hub. The panel
requires validation + confirmation and disables staging under global dry-run.
See [the recovery runbook](../runbooks/hub-recovery.md) for binary header encoding,
archive limits, coverage, maintenance-window consistency and activation steps.

## P3-08 implementation and usage

The matrix also contains future P4/P5 capabilities, not a claim that all rows
are already operational. P3-08 implements all agent management rows plus control
status/rotation with `AgentService`/`ControlManagement`: **39 manifest capability
rows, 37 CLI leaf commands and 32 admin endpoints, no new exemptions**. Grouped
matrix rows above are split per action in the executable manifest.

Additional lifecycle surfaces:

| Capability | CLI | Admin API | Agents panel |
| --- | --- | --- | --- |
| Revoke pending token | `agent token <name> --revoke` | `DELETE /api/agents/{name}/token` | Settings → Revoke token |
| List commands | `agent commands <name>` | `GET /api/agents/{name}/commands` | Activity → Remote commands |
| Read command result | `agent command <name> <id>` | `GET /api/agents/{name}/commands/{id}` | Activity → Result |
| Download diagnostics | `agent command <name> <id> --out <new-file>` | `GET /api/agents/{name}/commands/{id}/artifact` | Activity → Download diagnostic archive |

Examples (CLI works with `web.enabled: false`):

```sh
korctl agent create branch --role access --json
korctl agent list --json
korctl agent set branch --description 'Branch office' --transport tcp --dpd 30
korctl agent source set branch amnezia --file source.json
korctl agent upstream set branch office --file upstream.json
korctl agent egress set branch --file policy.json
korctl agent user add branch alice --password-stdin --group staff
korctl agent status branch --watch --json
korctl agent bundle list branch --json
korctl agent bundle diff branch 1 2 --json
korctl agent exec branch reconnect --tunnel fabric --dry-run --json
korctl agent exec branch reconnect --tunnel fabric --yes --json
korctl agent delete branch --dry-run --json
korctl control status --json
korctl control rotate-signing-key --dry-run --json
```

`agent set --file` accepts a structured patch (including write-only camouflage).
Source/upstream JSON files contain the named resource's fields, not its name.
Keep credential files private; never put passwords/private keys in command-line
arguments. `agent user add/passwd` use a hidden prompt or `--password-stdin`;
`user set --file` supports groups/enabled and optional password, preserving omitted
fields. Egress uses the existing EgressPolicy model and `egress edit` opens the
editor only in human mode; use `set --file` for noninteractive JSON workflows.

Revoke/delete/signing rotation and remote reconnect/restart/rollback need human
confirmation or `--yes`; JSON mode refuses interactive confirmation. Create,
revoke/delete, enqueue and rotation have dry-run previews. Other edits have no
preview API and are blocked while panel global dry-run is enabled. Preview is
not a promise that a later operation will succeed against changed state.

Agent list/detail show reported online/desired/applied status, not an active
network probe. Reports/commands refresh every 5 s without overwriting form drafts.
Policies have ordered rule controls and JSON destination/set controls; the full
polished egress editor belongs to P5. Access users and the listener are delivered with
the bundle since P4-04 (password authentication only); unsupported runtime policies/auth modes are rejected (05).

## Panel structure (hub)

Top-level sections: Dashboard · Clients · Agents · External servers ·
Network (egress, sources, sets, plan, explain) · Fabric (topology, DNS) ·
Certificates · Logs · Diagnostics · Settings.
