# Changelog

## [Unreleased]

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
