# Changelog

## [Unreleased]

Phase P0 of the [routing redesign](docs/redesign/PLAN.ru.md) (`docs/redesign/ROADMAP.md`):
stabilises the current routing model by fixing the root causes behind the most common
incidents, without changing the model itself.

### Testing

- Added the `tests/netlab/` network-namespace framework for real-kernel packet-level
  integration tests, plus `make netlab` to run tests marked with `@pytest.mark.netlab`.
- Added the default netlab topology fixture with routed hub/node/cli namespaces and HTTP/DNS
  stubs for baseline no-NAT connectivity scenarios.

### Added

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
