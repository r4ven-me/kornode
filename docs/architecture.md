# Architecture

Kornode v2 is a hub plus agents: one hub (node 1) and any number of agents (nodes 2..254) joined into a routed
overlay (the fabric) by ocserv/openconnect sessions on 443/tcp. Every node runs the same networking core and one
reconciler. Contracts: `docs/spec/` (start with `00-overview.md`); decisions: `docs/redesign/DECISIONS.md`.

## Components

| Component | Runs on | Purpose |
| --- | --- | --- |
| `kornode` (hub image) | hub | ocserv for clients, agents and enroll, registry, bundle compiler, control API, admin API, panel, `korctl`, reconciler. |
| `kornode-agent` (agent image) | every other node | openconnect to the hub and to external upstreams, reconciler, control-plane client, optional local ocserv (`access` role), optional dnsmasq. |
| `kornode.net` | both images | Desired-state model, egress compiler, kernel adapter, reconciler, explain. The only code that changes kernel networking state. |
| `kornode.control` | hub | Agent-facing control API, a separate process from the admin API, bound to the hub fabric address. |
| `kornode_agent` | agent | Agent runtime and the `kornode-agent` CLI. |

## Planes

- **Data plane**: kernel routing, nftables, tunnels. Keeps working without the control plane: an agent with a
  cached bundle keeps forwarding when the hub is down and boots from cache.
- **Control plane**: registry, signed bundles, agent reports, commands. Agents pull; everything is carried inside
  the fabric.
- **Management plane**: `korctl`, the admin REST API and the panel. They are equal (parity) and call the same
  services; `parity.yaml` plus `tests/test_parity.py` enforce it. The control plane runs even with
  `web.enabled: false`.

## Layers (hub)

1. **Configuration**: defaults → `.env` → environment → YAML → CLI overrides (lowest to highest priority), validated with Pydantic
   (`config/models.py`). Removed v1 keys fail validation and name their replacement.
2. **Registry** (`registry/`): SQLite (`data_dir/registry.db`) with nodes, prefixes, per-node egress policy,
   externals, bundle history.
3. **Services** (`services/`): all business logic, shared by CLI, API and panel — `AgentService`,
   `HubEgressService`, `FabricService`, `FabricGroupsService`, `FabricDnsService`, `UserService`,
   `CertificateService`, `SessionService`, `UpstreamService`, `DomainResolverService`, `BackupService`, `NetService`,
   `DiagnosticsService`, `DoctorService`, and others.
4. **Bundle** (`bundle/`): compiles, signs (ed25519) and seals per-agent bundles; schema
   `docs/spec/schemas/bundle.v1.schema.json`.
5. **Net core** (`net/`): pure `compile()` from inputs to `DesiredState`, `diff`, `kernel`, `reconciler`, `explain`.
6. **Infrastructure**: safe command runner (explicit argv, no shell), atomic file manager, secret masker,
   supervisor adapter, `tunnels/` (openconnect argv, carrier and pin handling).
7. **Interfaces**: `korctl`, REST API (`api/`), panel (`frontend/`).

## Backend package layout

Regenerate with `find backend/kornode -name '*.py' | sort` if it drifts. `api/routes_*.py` is one file per
resource; `services/` holds all logic reusable by CLI and API, per `AGENTS.md` ("CLI and API must call the same
services").

```text
kornode/
├── cli.py, cli_agents.py, cli_egress.py, cli_fabric.py, cli_hub.py   # korctl
├── main.py, healthcheck.py
├── api/            # routes_agents, routes_egress, routes_fabric, routes_dns, routes_net, routes_hub,
│                   # routes_users, routes_sessions, routes_certificates, routes_config, ...
├── bundle/         # canonical JSON, models, signing, sealing, validator, redaction
├── config/         # defaults, env, loader, models, reserved
├── control/        # agent-facing API (app, auth, tls, service)
├── net/            # model, addressing, compile, nftgen, state, diff, kernel, reconciler, explain
├── registry/       # db, models, repository, snapshot, SQL migrations
├── renderers/      # ocserv, dnsmasq, supervisor
├── services/       # agents, hub_egress, fabric, fabric_groups, fabric_dns, netinputs, net, bundle, apply,
│                   # enrollment, backup, doctor, upstream, domain_resolver, users, certificates, ...
├── tunnels/        # openconnect argv, carrier addresses, pin
└── schemas/
kornode_agent/      # agent runtime: agent, control, apply, inputs, tunnels, access, dns, doctor, store, cli
```

`kornode.net` imports only stdlib, `pydantic`, `pyroute2` and its own modules (`tests/test_net_imports.py`).

## Frontend layout

`frontend/src/` is split by role; `main.tsx` only mounts `<App />`.

- `App.tsx` — the root component: tab navigation (Dashboard, Config, Users, Agents, Fabric, Groups, Sessions,
  Network, Diagnostics, Logs, Terminal) and the wiring of feature-hook state into the views.
- `app/core.ts` — `usePanelCore()`: auth, the loaded `AppState`, busy/notice handling, `loadAll()` and
  `runAction()` (the wrapper every mutation goes through for consistent busy state, notices, dry-run labelling
  and auth-error logout).
- `app/hooks/` — one hook per panel area (`useUsers`, `useGroups`, `useSessions`, `useDashboard`,
  `useInternalDns`, `useIdentity`, `useUpstream`, `useCertificates`, `useSettings`, `useConfigEditor`, `useLogs`,
  `useLogin`, `useTheme`). A hook with editable drafts copies fresh server values into them with
  `core.registerHydrator()`.
- `api.ts` — typed API client; `app/types.ts`, `app/state.ts` — shared types and initial state.
- `views/` — one component per tab or section; larger areas have a folder: `views/agents/` (agent policy,
  settings, resources, activity), `views/fabric/` (topology, fabric settings, fabric DNS), `views/network/`
  (hub egress and sources), `views/upstream/`, `views/users/`, `views/groups/`, `views/certificates/`,
  `views/config/`.
- `components/` — reusable UI blocks; `lib/` — pure helpers without React state.

Views receive state and callbacks as props and leave API calls to the hooks; the exceptions are views that own
their data flow (`views/network/HubEgress.tsx`, `views/fabric/FabricView.tsx`, `views/agents/AgentsView.tsx`,
`views/config/AdminTotpPanel.tsx`).

## Egress and the reconciler

What leaves where is declarative: one ordered `egress` list per node (first match wins) over `clients`, `host`,
`fabric` and named `sources`, with `via` one of `local`, `fabric`, `node:<n>`, `upstream:<profile>`, `drop`
(`docs/spec/02-egress-and-sources.md`). On the hub it comes from `config.yaml` (`egress`, `sources`, `sets`;
`HubEgressService`); for agents it is stored per node in the registry and delivered in the bundle.

`net.compile()` is a pure function: equal inputs give byte-identical nft text and rule lists. The hub builds its
inputs in `services/netinputs.py` (YAML + registry + runtime facts); the agent builds them from the bundle
(`kornode_agent/inputs.py`). The reconciler (`net/reconciler.py`) diffs actual against desired state and applies a
plan — sysctl, routes into exit tables, ip rules, one `nft -f` transaction — on a netlink event, an inputs
change or a 10 s timer, with debounce, single-flight and backoff. A failed op does not abort the pass, so the
fail-closed rules still land (`docs/spec/04-netcore-reconciler.md`). Only `kornode.net` writes kernel state.

## Runtime modes

### Hub

- ocserv serves three classes: `clients` (users, all `auth.*` methods), `agents` and one-time `enroll` sessions.
  Agents and enroll use the `fabric.<fabric.domain>` virtual host on the same 443/tcp, selected by TLS SNI, with
  their own certificate and a connect-script guard that admits only registry agents there.
- Per-user ocserv files (`FabricGroupsService`) carry `explicit-ipv4`, `iroute` for each agent's exported prefixes
  and `route` for other agents'. ocserv does not install `iroute` routes itself, so the hub reconciler installs
  `<prefix> dev vpnsN` into `main` with `proto 77`; a session counts as connected while that route exists.
- The hub egress model is the same as an agent's; without an explicit `egress` list, hub clients leave through
  the uplink, and an explicit list replaces that rule (unmatched traffic is dropped).
- Bundles are compiled per agent, signed and sealed; agents long-poll the control API at `10.99.0.1:8444`.

### Agent

- `kornode-agent enroll` redeems a one-time token and stores the identity; `kornode-agent run` is the supervisor
  main process. It holds the fabric tunnel and external upstream tunnels, applies bundles with
  apply-with-confirm (verify health within a window, else roll back) and reports status.
- A cached bundle is enough to boot and forward without the hub.
- Roles: `access` runs a local ocserv listener for users of that node (password and certificate, hashes delivered
  in the bundle); `gateway` accepts `from: fabric` traffic and masquerades it for other nodes' `via: node:<n>`.
- Sources (wg-easy, Amnezia) attach to a node as named sources; kornode owns their routing and NAT.

### External upstreams

`upstream.*` profiles (hub) and agent upstreams are openconnect client connections to other ocserv servers, used as
`via: upstream:<profile>`. Several profiles can be connected at once, each with its own tunnel device. Switching
the active profile (`korctl upstream switch`, panel) re-points the profile used by rules; the egress rules and the
kill switch (`unreachable default` in the exit table, stale-mark rejects) decide what happens while a tunnel is
down. A supervised watchdog (`korctl upstream watch`, `upstream.check_*`, `failover`) pings the active profile's
`check_host` through the tunnel interface and redials, cycling through profiles when `failover` is on. The
upstream openconnect runs with a minimal interface-only vpnc-script (`tunnels/vpnc-script-kornode`): routes and
DNS pushed by the server must not touch the namespace's routing table or `resolv.conf`; the reconciler owns them.

`routing.host_dns` (`off`, `resolv_conf`, `resolved`) optionally points the host's own resolver at the built-in
dnsmasq (`services/host_dns.py`). It needs `network_mode: host` and a mount of the host file or directory.

## Internal DNS

`internal_dns` turns the VPN server itself into the DNS server for connected clients:

- ocserv pushes the project-owned dnsmasq listen address (`internal_dns.listen`,
  which must be inside `server.ipv4_network`) to clients instead of `server.dns`, plus
  `tunnel-all-dns = true` so blocking cannot be bypassed;
- dnsmasq forwards queries to the resolvers configured in `server.dns`;
- blocked domains answer with `0.0.0.0` (Pi-hole style), rendered into
  `generated/dnsmasq-blocklist.conf` from three merged sources:
  1. `internal_dns.blocklist_domains` — inline list in the config (GUI textarea);
  2. `internal_dns.blocklist_files` — any number of local text files (hosts or
     plain-domain format);
  3. `internal_dns.blocklist_urls` — any number of HTTP(S) lists, each downloaded on
     demand (`korctl internal-dns refresh --url <url>` or the panel's per-URL
     "Download & apply" button), validated (scheme, size cap, per-line domain parsing)
     and cached individually under `data_dir/internal-dns/urls/` before use.

The same dnsmasq instance answers the fabric zone (`node<id>.<fabric.domain>` and registry records, owned by the
hub; agents forward fabric names to it) and, through `DomainResolverService`, backs the domain sets of the egress
policy. It runs whenever `server.enabled` or any of blocklist, local records or forward domains is on
(`AppConfig.dnsmasq_active_reasons()`), and the client DNS is the VPN server's own resolver unconditionally while
`server.enabled` (`client_dns_servers()`). Clients routed by domain sets must use it, so the addresses they
connect to match the ones the resolver put into the set.

### Listen address lifecycle (runtime-dependent)

ocserv never assigns the VPN gateway IP to any host interface: it creates one
point-to-point tun device (`vpnsN`) per client, and per-client `/32` routes appear only
while clients are connected — so the absence of a route for the client pool (default `10.100.1.0/24` on the hub) is
normal, and a bare dnsmasq would fail with "cannot assign requested address". The
supervisor therefore starts dnsmasq through `korctl internal-dns run`, which first runs
the idempotent `ip addr replace <listen>/32 dev lo` and then execs dnsmasq in the
foreground. With the address on `lo`, client DNS packets arriving via `vpnsN` are
delivered locally instead of following the default route out of the main interface
(requires `NET_ADMIN`, works with `network_mode: host`). `korctl internal-dns
ensure-listen [--dry-run]` runs the same step manually.

## Client routing sync

`GET /api/client/routing` is the only endpoint without admin authentication:
it serves connected VPN clients (the korclient sync loop). Because of that,
it needs its own explicit opt-in — `web.client_sync_enabled` (default
`false`) — on top of `web.enabled`: turning on the admin panel alone must
never also quietly expose an unauthenticated endpoint. The caller is
identified by its VPN session — the request must originate from an address
inside `server.ipv4_network` that occtl reports as an active session — and
receives only its own effective routing (server `routes`/`search_domains`,
the user's config-per-group files, the per-user config) plus a version hash.
korclient polls it through the tunnel and applies changes live without
reconnecting.

## Control surfaces

CLI is the primary control surface and must always work.

API and Web GUI are optional and disabled by default. When enabled, GUI uses backend API only.

## Config ⇄ GUI parity

The web panel's "Config" tab has a raw YAML editor (validate/save/render/diff against
`config.yaml` directly). That editor is a fallback and power-user escape hatch — it exists so
the panel is never blocked on a missing feature, not so individual settings only need to be
discoverable there. The actual goal is that **every config knob in `AppConfig`
(`backend/kornode/config/models.py`) has a matching structured control** somewhere in the
panel (a labeled input, checkbox or select bound to that specific field), grouped to mirror
`config.yaml`'s own section layout: VPN server behavior and accepted auth methods live under
the "Server (VPN)" / "Authentication methods" panels (Config tab), the admin web panel's own
settings live under "Web / API panel", `system`/`cli` under "General", `identity`/`certificates`
live in their own dedicated tabs, `egress`/`sources`/`sets` live in Network → Egress rules and Network → Sources,
and `fabric` settings live in the Fabric tab.

When a new field is added to `AppConfig`, add its GUI control in the same change:

- Backend: extend (or add) a small typed Pydantic request model next to the relevant router
  and patch the config through `apply_config_patch()` in `backend/kornode/api/routes_config.py`
  — every settings-save endpoint in the codebase already goes through this one helper
  (`deep_merge` into the YAML, re-validate, write, optionally re-render). Don't invent a second
  mechanism.
- Frontend: add a draft `useState` to the area's hook in `frontend/src/app/hooks/`,
  hydrated from the loaded config via `core.registerHydrator()` (see the `read*Draft`
  helpers in `frontend/src/lib/drafts.ts`, e.g. `readServerSettingsDraft`), a bound
  input/checkbox/select in the relevant view under `frontend/src/views/`, and a save handler
  in the same hook that calls the new endpoint through
  `runAction` (for consistent busy-state/notice/error handling).

Exceptions that intentionally stay YAML-only, because a form control would be actively
misleading or unsafe:

- deploy-time paths fixed via `.env`/volume mounts at container start
  (`system.data_dir`/`log_dir`/`generated_dir`/`secrets_dir`,
  `identity.config_per_group_dir`/`config_per_user_dir`,
  `web.tls_cert`/`tls_key`/`static_dir`) — editing these live would desync the running
  process from its actual mounted volumes;
- `advanced.raw_ocserv_options` — a free-form list/mapping escape hatch by design;
- `web.admin_password`/`admin_password_hash` — belongs behind a dedicated change-password
  flow, not a plain-text field in a general settings dump.
