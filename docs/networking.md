# Networking, routing and DNS

## Principles

- Use nftables, not iptables.
- Do not flush host firewall rules.
- Create project-owned tables/chains/sets only.
- Use unique names with configurable prefix, default `kornode`.
- Support dry-run output.
- Make apply operations idempotent.
- Apply rendered project-owned tables/chains/sets automatically at Korvus Node startup.
- Cleanup only project-owned state.

## Required Linux capabilities

Container requires:

```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
devices:
  - /dev/net/tun:/dev/net/tun
```

Rootless mode is not expected to fully work for network control operations. Document this clearly.

## Full routing mode

VPN clients are NATed or routed through the selected outbound interface.

For middle-server mode, default outbound interface is upstream OpenConnect tunnel interface.

## Split routing mode

Traffic selection sources:

- static CIDR routes;
- static IPs;
- domains from YAML;
- domains from external file;
- dnsmasq-resolved IPs inserted into nftables sets.

Current behavior:

- dnsmasq is started only when split DNS is enabled;
- nftables rules are rendered from YAML/runtime route and domain files;
- `full` mode installs forwarding/NAT rules for VPN clients;
- `split` mode prepares project-owned chains/sets for selected traffic;
- apply and cleanup operations are scoped to Korvus Node-owned tables.

## Suggested names

```text
nft table inet kornode_filter
nft table ip kornode_nat
nft set inet kornode_filter split_v4
nft set inet kornode_filter split_v6
fwmark 0x0c01
routing table 1201
```

All names and numeric IDs are configurable.

Korvus Node startup writes generated config files and runs the shared nftables apply
service, so empty project-owned tables, base chains and sets exist before the operator
opens the GUI diagnostics page. Manual `korctl nft apply` stays available for re-apply,
dry-run checks and repair after runtime changes.

`korctl nft apply` renders and applies `/var/lib/kornode/generated/nftables.nft`.
If `nft` exits with signal 11 inside the container while the same rules work directly
on the host, debug nftables userspace/kernel compatibility first:

```bash
docker compose exec kornode nft -f /var/lib/kornode/generated/nftables.nft
docker compose exec kornode nft --version
uname -r
```

That failure mode is outside normal route rendering; updating the image's `nftables`
package or using a base image aligned with the host kernel is usually required.

## Diagnostics

Command/API diagnostics cover:

```text
ip addr
ip route
ip route show table all
ip rule
nft list ruleset
nft list table inet kornode_filter
nft list table ip kornode_nat
ss -lntup
occtl show users
occtl show status
```

Output must mask secrets and avoid dumping private key content.
