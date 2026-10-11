# Changelog

## [Unreleased]

### Added

- Apply required IPv4 forwarding and rp_filter sysctls at startup and on new upstream/server tunnel interfaces; ocserv now installs a kornode connect-script by default.

### Fixed

- Preserve directly-connected local routes ahead of host full-tunnel policy routing by installing
  the global `main suppress_prefixlength 0` rule before kornode fwmark rules.
- Clamp TCP MSS to path MTU for forwarded VPN traffic and host-originated traffic leaving upstream tunnel interfaces to prevent nested-tunnel HTTPS hangs.
- Preserve symmetric policy routing for local services reached through an upstream tunnel by recording the ingress target in conntrack and restoring its fwmark on reply packets.
