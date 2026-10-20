# Changelog

## [Unreleased]

### Added (P4-04, D-67)

- Role `access` on agents: `korctl agent access show/set/del`, `GET/PUT/DELETE /api/agents/{name}/access`, panel listener editor. The hub issues the listener's server certificate from its CA **without OU** (it can never log in to the hub), keeps the key encrypted and seals it to the agent; the bundle carries `access` (port, DTLS, password auth, CA, certificate, sealed key, users as ocpasswd hashes) with strict validation of usernames, hashes and groups.
- The agent renders ocserv files under `/run/kornode-access` and runs ocserv as a supervisor program (`autostart=false`): user changes only rewrite `ocpasswd` and disconnect removed users, other changes restart it, removing the listener stops it and wipes the secrets; failures are the doctor finding `access_failed`. Local logins work while the hub is down (E2E NL-03).
- Security defaults for access nodes: clients are not in the implicit fabric rule, may reach the node itself only for DNS/ping (`vpns*` input guard), and the listener certificate is revoked in the hub CRL at issuance; hub doctor `access-certificates` warns before expiry.
- `kornode.net`: strict reverse-path rule for `vpns*` (`NodeFacts.access_ifaces`); doctor ignores per-session host routes in the client pool.
- Registry migration 0003 (`nodes.access`); agent image ships ocserv; netlab `test_p4_access`; E2E NL-03.

### Added (P4-03, D-66)

- Fabric DNS: the hub answers the whole `<fabric.domain>` zone (`hub`, `node<N>` and registry records) from local data; each agent runs dnsmasq on its service address, answers its own `node<id>.<domain>` zone (also with the hub down) and forwards the rest of the zone to the hub over the fabric.
- `korctl dns record add/del/list`, `GET/POST/DELETE /api/dns/records`, panel Agents → Fabric DNS (parity).
- Agent dnsmasq forwards the fabric zone with the node's fabric address as source (strict RPF on the hub); netlab `test_p4_dns` and E2E NL-02 (four VMs) cover it.
- Bundle `dns` section (own zone records, forward zone); strict validation of DNS names and addresses in bundles; agent image ships `dnsmasq-base` and a supervisor control socket.

### Fixed (review LOW findings, D-64)

- Hub backup of a new hub (no `master.key` yet); disk errors are `503 backup_io`; another agent's stale policy no longer blocks a mutation; agent report caches `doctor` for 120 s; hub validates diagnostic archives; netlab accepts both nft renderings.

### Added (P4-01, P4-02, D-63, D-65)

- E2E NL-01 (hub -> agent over the fabric, no NAT) and NL-04 (agent -> another agent's exported LAN through the hub, no NAT) run on the four VMs; failures print routing state of hub and agents (`net_dump`).
- Hub per-user ocserv files carry `iroute` for a node's exported prefixes, `route` for other nodes'
  exported prefixes and the node's `dpd`/`keepalive`; ocserv is reloaded when an existing file changes.
- Hub reconciler installs connected agents' exported prefixes in the main table (`proto 77`, owned by protocol only); S-03 showed ocserv `iroute` does not.
- Agent prefix API reports `runtime_supported: true`; test that the `fabric` exit is never masqueraded.

### Fixed (four-VM E2E acceptance, D-62)

- Hub image: `python` on `PATH` for supervisor programs is an `exec` wrapper of the venv interpreter
  (the symlink resolved to system python and `control-api` could not import `kornode`).
- Agent enroll waits up to 10 s for the pushed route to the hub before refusing (race with
  vpnc-script); an unrouted hub address is still never contacted.
- E2E harness fixes (connect_script, nft fault script, `pin` output, ext network, NL-13 re-dial
  window); real VM run: 9 passed, 13 skipped.

### Fixed (P2 tails, D-60)

- Reconciler: single kernel writer enforced by `flock` on `generated_dir/reconciler.lock` (daemon
  for life, in-process `net apply` per pass, waits for a starting daemon instead of writing);
  netlink events no longer bypass the backoff after a failed pass (`Reconciler.wake_netlink`).
- Tests: `tests/test_kernel_single_writer.py` is AST-based; new netlab scenario for D-32 (flow of a
  removed exit sends 0 packets to the uplink; with the stale-mark rule disabled it leaks 2). Full
  privileged netlab on the VM: 43 passed.
- Review 2026-10-18: `kornode-agent diag` returns the archive (the redactor swallowed it);
  `credentials_set` and other boolean flags, public keys and hex digests stay readable;
  `rotate-signing-key --dry-run` no longer counts the hub; e2e workflow no longer uploads agent
  diagnostic archives to the public repository.
- `Dockerfile.agent` built locally: 396 MB (target 150 MB not met; `supervisor` pulls a second
  Python 3.13, ~27 MB, base + apt ~250 MB).

### Fixed (review follow-ups for P3-07…P3-10, D-59)

- Agent: local socket shutdown cancels handlers before `wait_closed()`; `TunnelManager.specs()`
  no longer blocks behind a dial; unexpected local/doctor/ping failures are logged (type only);
  redactor covers `psk`, API/auth keys, sessions, credentials and bare `Bearer`/`Basic` tokens.
- Hub: address validation marks only the mutated node's prefixes as "adding"; the command queue
  limit counts `queued`+`delivered`; `ocpasswd` hashing happens outside the registry transaction;
  `control status` lists agents that have not confirmed the signing-key announcement.
- Backup: certbot-style symlinks at default `certs/` names are materialized; all directories of a
  staged restore are 0700.
- E2E: `pull_request` trigger removed (dispatch from a protected branch only), checkout keeps
  `artifacts/`, artifact retention 7 days, container `sysctls` for forwarding.
- Panel: secrets are kept after a failed save, the enrollment token can be revealed when the
  clipboard API is unavailable, Backup shows backend detail, policy "From" accepts commas.
- Tests: enrollment tests use the real clock (certtool dates certificates from it).

### Added (P3-10: disposable four-VM E2E tooling)

- Environment-only SSH inventory, strict host pins, explicit destructive opt-in,
  root-owned VM authorization markers, exclusive leases and guarded recovery.
- Build/save/load both images on the designated hub runner; Docker pinned to the
  local rootful socket/default builder. Per-case Compose projects isolate kernel
  faults in container namespaces; metadata/config are read-only, only state is RW.
- Executable enrollment, confirmed registry updates, bounded blackhole recovery,
  revoke/mTLS 403, rotating hub wipe/restore, previous-image upgrade, route repair,
  signed bad-bundle rollback, signature rejection and partial ten-minute cache /
  upstream outage scenarios. P4/client cases stay explicit skips.
- Detached container-only fault watchdog, teardown on setup failure, private recovery
  ledger, sanitized diagnostics and narrow artifact upload allowlist.
- Protected-environment self-hosted workflow (manual confirmation / same-repo `e2e`
  PR label), offline `make e2e-plan`, opt-in `make e2e`, strict harness typing in
  `make check`, and 49 local safety tests. No application config/parity additions.
- **Not accepted / no real VM execution yet**; both agents use Docker NAT, not the
  final public/host-network topology. See `docs/runbooks/vm-e2e.md` and
  `docs/redesign/P3-10-REVIEW.md`. Prior pending P3 tasks remain unaccepted.

### Added (P3-09: encrypted hub backup / staged restore)

- Shared `BackupService`, `korctl hub backup|restore`, admin `/api/hub/backup|restore`,
  Config → Backup / Restore; two new parity capabilities without exemptions.
- Versioned Argon2id (64 MiB, t=3, p=4) + ChaCha20-Poly1305 encrypted archives;
  `cryptography >=44`. Consistent SQLite backup, resolved config, CA/TLS identities,
  master key, secrets/users/groups and all referenced signing rotation files,
  including custom paths outside data_dir. Atomic private no-clobber archive output.
- Strict bounded manifests, portable path validation, hashes, DB integrity/schema
  and key-pair checks; source change detection, bounded cross-process backup lock.
  Restore validates first and writes a new private tree only, remapping config/DB
  paths and publishing config last. Managed connect hook regenerates restored paths.
- Masked ephemeral UI passphrases, CSRF/no-store streaming download and bounded
  encrypted upload; explicit restore confirmation. No live state replacement,
  automatic network changes or claimed live activation. Detailed recovery runbook
  documents maintenance-window consistency and offline activation/permissions.
- Unit/API/CLI/security/recovery tests, desktop/mobile light/dark browser checks,
  privileged wipe/restore/reconnect netlab scenario (execution still required).
  Implemented, **not finally accepted**; see `docs/redesign/P3-09-REVIEW.md`.

### Added (P3-08: hub agent management)

- Shared `AgentService`/`ControlManagement` for `korctl agent`/`control`, authenticated
  `/api/agents*`/`/api/control*`, and the responsive light/dark Agents panel; 39 parity
  capability rows without exemptions. CRUD, token issue/revoke, networks, sources,
  policies, upstreams, registry access users, reports, redacted bundle history/diff,
  typed remote commands/results and explicit diagnostic archive download.
- SQLite schema 2: 30-day deleted-ID quarantine with explicit force reuse; durable
  signing-key rotation. Seven-day public-key announcement in old-signed bundles,
  promotion on polls/compile, old private key files retained (required in P3-09 backup).
- Transactional validation/compilation and bounded management lock; revoke-before-delete,
  occtl reload and verified offline-session handling; group render/sync lock acquired
  before snapshot to prevent stale guard resurrection. Explicit committed-state errors.
- Write-only encrypted transport camouflage/upstream credentials, sanitized errors and
  no-store management responses; token shown only for explicit issue and forgotten on
  dialog close. Unsupported P4 runtime features are labeled/rejected, never implied active.
- Service/API/CLI/security/concurrency tests, Chromium checks at desktop/mobile in both
  themes, and a privileged netlab CLI scenario (execution still required). D-56;
  cumulative primary-review handoff: `docs/redesign/CLAUDE-HANDOFF.md`.

### Added (P3-07: agent CLI)

- `kornode-agent status`, `explain`, `doctor`, `bundle show|history|rollback`, `diag`,
  `reconnect`; `--json` on every command, sanitized errors and exit codes 0/1/2/3/4.
  Cache inspection/offline status work without the process or hub.
- Owner-only Unix RPC (`run/agent.sock`, 0600); process/enrollment flock before boot;
  one mutation path shared with hub commands, serialized with apply and cancellation-safe.
  Rollback/reconnect previews (`--dry-run`); rollback preserves high-water and health checks.
- Agent-local read-only doctor findings in reports/diagnostics; mark-based kernel check in
  explain with an explicit warning about protocol/port limitations.
- Shared redacted diagnostic collector (bounded logs, no symlink targets/keys/config/bundles),
  atomic private no-clobber archive output; verified/redacted bundle show. D-55.
- CLI, real Unix-socket, concurrency, cache/secrets and doctor tests; expanded P3 agent netlab
  scenario (privileged execution still required). Claude review handoff in
  `docs/redesign/P3-07-REVIEW.md`.

### Added (P3-06: agent)

- `kornode.tunnels` (stdlib only): shared openconnect argv builder (`--pfs`, `--no-dtls`),
  carrier resolution, certificate pin and the interface-only vpnc-script; `UpstreamService`
  uses it. `services.cert_pin` moved to `kornode.tunnels.pin`.
- `kornode_agent`: atomic store (`state.json`, `trust.json` with key rotation, bundle cache),
  `agent.yaml`, httpx control client (mTLS, pinned CA), enrollment. D-53.
- `kornode_agent`: apply-with-confirm state machine (stage, health window, rollback, blame:
  `failed` vs `deferred`, boot from cache, local rollback), `AgentNetInputs`, tunnel manager
  (carrier + reconciler pass before every dial, backoff with jitter, hub failover), health checks.
- `kornode-agent enroll|run|version`, `Dockerfile.agent`, `compose.agent.yaml`; run loop (long-poll,
  reports, commands, renewal, deferred retry). Netlab: real agent enrolls, confirms its bundle,
  reports and boots from cache with the control API down. D-54.
- Enroll token carries `control` (control API URL); `validate(revalidate=True)` for cached bundles.

### Added (P3-05: control API)

- `kornode.control`: agent-facing API on the hub fabric address (`python -m kornode.control`,
  supervisor program `control-api` when `control.enabled`, independent of `web.enabled`).
  mTLS on one port: the CA-verified client certificate is optional at the TLS layer and
  required per request everywhere except `POST /agent/v1/enroll` (CN `agent-<id>`,
  OU `agents`, CRL, `nodes.state`; a missing/stale CRL fails closed with 503).
  Endpoints `ping`, `bundle`, `poll` (long-poll, 500 ms registry re-check, recovery when
  `since` is ahead of the hub), `report`, `commands`, `commands/<id>/result`, `renew`
  (identity from the certificate), `enroll` (5/min per source). D-49, D-52.
- New `control.*` config (port, long-poll, report/offline intervals, certificate
  lifetime, token TTL, bundle history, `min_agent_version`, `signing_key`) replaces the
  constants of P3-03/P3-04; saving the hub configuration recompiles all bundles.
- `kornode.net` binds `service_address` (`10.99.0.1/32`) to `lo` (new add-only `Address`
  primitive). D-50.
- Registry: reports (last 500 per node), commands (queue, at-most-once delivery, expiry,
  owner-only results), monotonic `high_water_version`.
- Fix found by netlab: the enroll VPN session is cut after the answer was delivered, not
  inside `enroll` (the certificate was lost). D-51.

### Added (P3-04: bundle compiler)

- `kornode.bundle` (stdlib + pydantic + cryptography + `kornode.net`, AST-checked): bundle
  models, canonical JSON, Ed25519 signing with domain separation, per-value X25519 secret
  sealing bound to the JSON pointer, and the single validator used by hub and agent.
- `BundleService`: compiles a signed bundle per agent inside the registry transaction,
  monotonic versions above the agent's high-water mark, dedup by content hash, refuses to
  store a bundle its own validator rejects. `enroll` now returns the first bundle and the
  signing keys; `revoke_node` recompiles the remaining agents.
- Registry: `bundles` and `externals` accessors, history pruning (20 per node). D-48.

### Added (P3-03: agent enrollment)

- `EnrollmentService`: one-shot enrollment tokens (1 h, secret stored hashed) with a
  one-time `enroll-<node>-<id>` ocserv user, CSR signing by the hub CA (CN/OU set by the
  hub, ECDSA P-256 only, 90 days), renewal after 2/3 of the lifetime, node revocation via
  CRL + ocserv reload + `occtl disconnect`, and `korctl registry maintain` (expired
  tokens, stale CRL) in the registry supervisor loop. D-45, D-46.
- `ocserv.conf` gets `crl` with `fabric.enabled`; the connect-script guard refuses
  agents without a `config-per-user` file; strict reverse-path check for ocserv session
  devices closes source spoofing from enroll sessions (D-47).
- `cryptography` is now a runtime dependency.

### Added (P3-01: registry)

- Added the hub registry storage layer on SQLite/WAL with forward-only migrations,
  node/node-prefix repository methods, and `korctl registry snapshot` with
  integrity-checked 7-copy retention.
- P3-02 part A: added the dedicated `fabric.enroll_pool`, enforced D-43 fabric
  auth restrictions, and reserved fabric agent/enrollment usernames and groups.
- P3-02 part B: render fabric ocserv auth, connect-script guard, generated
  `clients`/`agents`/`enroll` group files, active agent `explicit-ipv4` files,
  and the static enroll nft guard.

Phase P0 of the [routing redesign](docs/redesign/PLAN.ru.md) (`docs/redesign/ROADMAP.md`):
stabilises the current routing model by fixing the root causes behind the most common
incidents, without changing the model itself.

### Testing

- `make parity` (+ CI step): `parity.yaml` maps every CLI command, API route and panel control
  to a capability; fails on unlisted surfaces and on capabilities missing a side without a
  stated exemption. Exemptions list the v1 parity gaps.
- Regression baseline: the P0 netlab scenarios fail on `raven` (pre-P0) for the root causes
  P0 fixes and pass on `main`; procedure and results in `docs/spec/09-testing.md`.
- Netlab NL-08 with the reconciler daemon running: tunnel drop and redial under traffic
  (connect converges through `reconciler.sock`) and a reconciler restart while the tunnel
  dies; both assert zero packets on the uplink.
- Added P1-03 netlab scenarios that run real kornode-rendered ocserv/openconnect
  inside namespaces to cover the P0 routing fixes.
- CI: new `netlab` job runs `sudo make netlab` on ubuntu-latest and uploads
  `artifacts/netlab/` when it fails.
- Added failure artifact capture for netlab tests, including per-namespace kernel network
  state dumps under `artifacts/netlab/`.
- Added the `tests/netlab/` network-namespace framework for real-kernel packet-level
  integration tests, plus `make netlab` to run tests marked with `@pytest.mark.netlab`.
- Added the default netlab topology fixture with routed hub/node/cli namespaces and HTTP/DNS
  stubs for baseline no-NAT connectivity scenarios.

### Changed (P2-08/P2-09: hub cut-over to the reconciler)

- `kornode.net.kernel` is now the only code that touches nftables, `ip rule`/`ip route` and
  sysctl (`tests/test_kernel_single_writer.py`). Removed: `NftablesService`,
  `PolicyRoutingService`, `SysctlService`, the nft renderer/templates, `korctl nft *`,
  `/api/routing/nft*`; `UpstreamService.ensure_policy_routing` is gone (the reconciler keeps
  routes itself). No migration of the old state (D-29).
- `UpstreamService` (`connect`/`disconnect`/`switch_profile`/`recover`/server-pushed routes)
  only updates reconciler inputs (active-profile marker, `upstream-carrier/<profile>.addrs`,
  pushed routes) and runs a converge pass. `connect` writes the carrier addresses, converges
  (kill-switch), then dials, then converges again; a failed pass is an error, no longer a
  silent success.
- The reconciler control socket gains a synchronous `apply` op; `NetService.apply` uses it,
  `NetService.converge` raises `NetApplyError` on a failed pass, `NetService.wake` is the
  fire-and-forget nudge used by the vpnc/ocserv hooks.
- The runtime-switched active profile (`active-upstream`) is now a reconciler input.
- Domain resolver writes `generated_dir/resolved/<set>.txt` per policy set and wakes the
  reconciler instead of loading nft sets.
- `initialize_runtime` runs one converge pass instead of sysctl + nft apply; failure is fatal.
- `reconciler` supervisor program (`korctl net run`, starts first).
- `korctl doctor` / `/api/diagnostics/doctor` report from `NetService.plan()` (kernel-plan,
  sysctl, policy tables, carrier exclusions); `routes reload`/`domains reload` converge via
  `net apply`; the routing-settings save response key `nft` is now `net`.

### Added

- `korctl net plan|apply|explain|run` and `GET /api/net/plan`, `POST /api/net/apply`,
  `POST /api/net/explain`, `GET /api/net/status`, all on one `NetService`.
- `kornode.config.legacy`: v1 routing keys (`client_policy`, `host_policy`, split lists,
  per-profile client/host routing) translate into an egress policy; named profiles win over the
  defaults by coming first. Golden translation for every file in `examples/`.
- `kornode.net.explain`: why a packet from `src` to `dst` goes where it goes (implicit rule or
  matched egress rule, mark, table, route, NAT), cross-checked against the kernel's own route lookup.
- P2-07 fabric addressing config: `node.id`, `fabric.*`, derived server pool/DNS
  listen values when enabled, overlap validation, and structured Fabric settings in the panel.
- `kornode.net.reconciler`: converges the kernel on input changes, netlink events and a 10 s
  timer (200 ms debounce, single flight, exponential backoff), with a status/wake Unix socket.
- `kornode.net.kernel`: reads kernel state (pyroute2, /proc, `nft -j`) and applies a plan --
  netlink for rules/routes, one `nft -f` transaction for kornode's tables and set contents.
- `kornode.net` egress model and compiler: an ordered first-match egress policy compiles
  deterministically into ip rules, per-exit tables (kill-switch route included), sysctls and one
  nft ruleset; dead (shadowed) rules are reported. Golden tests for the spec examples.
- `kornode.net.state`/`diff`: kernel networking state as data and `diff(actual, desired)` into an
  ordered, idempotent plan that only ever touches kornode-owned rules, routes and nft tables.
- New `kornode.net` package (routing redesign P2): the future single owner of kernel
  networking state; import-restricted to stdlib/pydantic/pyroute2. New dependency: `pyroute2`.
- `korctl doctor` (+ `GET /api/diagnostics/doctor` + a "Doctor" panel card on the Diagnostics
  page): checks required sysctls, overlapping subnets (VPN pool vs. host/Docker routes and
  upstream-pushed routes), policy-table health, `nft`/kernel versions, and that every connected
  upstream profile has its carrier-exclusion rule. Prints every check before exiting, unlike
  `diagnose`, so one failing check doesn't hide the rest.
- Required `net.ipv4.ip_forward`, `net.ipv4.conf.all.src_valid_mark` and `rp_filter` sysctls are
  now applied at startup (fatal if they can't be) and reasserted on every new tunnel interface
  (outbound upstream connect/reconnect, inbound ocserv client/agent session via a new
  kornode-installed connect-script). Previously nothing managed these at all, so asymmetric
  fwmark-routed paths could be silently dropped by a strict host `rp_filter`.

### Fixed

- Connections whose exit was removed by a policy change (profile switch, upstream disabled,
  rules reordered) kept a stale mark and left via the uplink without NAT; such marks are now
  rejected toward the uplink (D-32).
- A failed op in a reconciler pass (sysctl, a tunnel vanishing mid-pass) no longer prevents
  the rules and the nft kill-switch from being installed; any exception is an errored pass
  instead of killing the reconciler; the ocserv connect hook reports a failed pass (D-33).
- `routing.main_interface` is validated as `auto` or a kernel interface name; it is quoted
  into the nft kill-switch, and an arbitrary string could inject rules that bypass it.
  `kornode.net` also refuses to render any interface name that is not an ifname.
- In `full` mode, kill-switches dropped marked traffic to this node's own connected networks
  (LAN, docker bridge, client subnet) even though routing correctly sent it there; they now drop
  only marked traffic leaving via the uplink (or, if the uplink can't be determined, anything not
  leaving via the tunnel, as before).
- `host_policy: full` loaded no nftables rules at all: the template emitted `ip6 counter ...`
  (a bare `ip6` is a syntax error for nft, incl. the 1.1.3 shipped in the image), so the whole
  ruleset failed to apply -- no marking, no kill-switch, no MSS clamp -- while `upstream connect`
  still reported success. Now `meta nfproto ipv6`.
- Carrier connections are now also exempted from nft marking; previously, once the ruleset did
  load, the postrouting kill-switch dropped openconnect's own connection to the server.
- The global `suppress_prefixlength` rule was never recognised as already installed (iproute2's
  JSON key is `suppress_prefixlen`), so the second `apply()` failed with "File exists" and
  aborted `upstream connect`.
- Carrier connections no longer loop into their own tunnel: each upstream profile's resolved
  server address is excluded from policy routing (`ip rule priority 95 to <addr>/32 lookup
  main`) before any TCP to it, refreshed on every connect to track DNS changes, and removed on
  disconnect.
- Policy-routed traffic now fails closed, not open, if its tunnel device disappears: a
  persistent `unreachable default` route in each managed table rejects the traffic instead of
  letting it fall through to the main table during the few seconds before the watchdog notices.
- Traffic to this node's own LAN/docker networks is no longer shadowed by `host_policy: full`'s
  policy-routing tables: a global `ip rule ... lookup main suppress_prefixlength 0` rule now
  always lets connected/specific routes win over fwmark policy, installed ahead of every
  upstream profile's own rule.
- TCP MSS is now clamped to path MTU for forwarded VPN traffic and for host-originated traffic
  leaving an upstream tunnel interface, fixing HTTPS/large-response hangs through nested
  tunnels (TCP-over-TCP).
- Preserve symmetric policy routing for local services reached through an upstream tunnel by
  recording the ingress target in conntrack and restoring its fwmark on reply packets.
