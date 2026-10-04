# Changelog

## [Unreleased]

### Fixed

- Preserve symmetric policy routing for local services reached through an upstream tunnel by recording the ingress target in conntrack and restoring its fwmark on reply packets.
