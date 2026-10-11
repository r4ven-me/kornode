# Changelog

## [Unreleased]

### Added

- `korctl doctor` (+ `GET /api/diagnostics/doctor` + a "Doctor" panel card on the Diagnostics
  page): checks required sysctls, overlapping subnets (VPN pool vs. host/Docker routes and
  upstream-pushed routes), policy-table health, `nft`/kernel versions, and that every connected
  upstream profile has its carrier-exclusion rule. Prints every check before exiting, unlike
  `diagnose`, so one failing check doesn't hide the rest.
- Apply required IPv4 forwarding and rp_filter sysctls at startup and on new upstream/server tunnel interfaces; ocserv now installs a kornode connect-script by default.

### Fixed

- Exclude each upstream profile's resolved carrier address from policy routing (`ip rule priority
  95 to <addr>/32 lookup main`) so `host_policy: full` can no longer route openconnect's own
  connection to the VPN server back into the tunnel it is dialing; refreshed on every connect to
  track DNS changes and removed on disconnect.
- Keep marked policy-routed traffic fail-closed during upstream tunnel device loss by adding a
  persistent unreachable default route to each managed policy table.
- Preserve directly-connected local routes ahead of host full-tunnel policy routing by installing
  the global `main suppress_prefixlength 0` rule before kornode fwmark rules.
- Clamp TCP MSS to path MTU for forwarded VPN traffic and host-originated traffic leaving upstream tunnel interfaces to prevent nested-tunnel HTTPS hangs.
- Preserve symmetric policy routing for local services reached through an upstream tunnel by recording the ingress target in conntrack and restoring its fwmark on reply packets.
