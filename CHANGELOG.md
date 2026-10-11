# Changelog

## [Unreleased]

### Added

- Apply required IPv4 forwarding and rp_filter sysctls at startup and on new upstream/server tunnel interfaces; ocserv now installs a kornode connect-script by default.

### Fixed

- Preserve symmetric policy routing for local services reached through an upstream tunnel by recording the ingress target in conntrack and restoring its fwmark on reply packets.
