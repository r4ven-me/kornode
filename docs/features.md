# Feature requirements

## ocserv server

Implement config generation for common ocserv options:

- TCP port;
- UDP support;
- server certificate and key;
- CA certificate;
- auth methods;
- network and netmask;
- DNS servers;
- split DNS/search domains where appropriate;
- routes and no-routes;
- max clients;
- max same clients;
- keepalive;
- compression;
- Cisco AnyConnect compatibility;
- camouflage / secret URL;
- realm;
- isolation/chroot options where applicable;
- connect/disconnect hooks.

Do not attempt to expose every obscure ocserv option in GUI v1. Support an `advanced.raw_ocserv_options` map/list for unsupported options with validation and warnings.

## Users

Required:

- create user;
- delete user;
- disable user;
- enable user;
- change password;
- list users;
- inspect user state;
- export client artifacts.

## Certificates

Required:

- internal CA generation;
- server certificate generation;
- user certificate generation;
- `.p12` export;
- Apple-compatible `.p12` export mode;
- CRL generation;
- certificate revoke;
- CRL reset;
- reload ocserv after CRL update;
- support externally mounted cert/key/CA files.

## OTP/TOTP

Required:

- enable OTP for user;
- disable OTP;
- generate secret;
- show QR in CLI as terminal QR or base64/PNG for GUI;
- never log OTP seed;
- store `users.oath` safely.

## Identity / OIDC

ocserv does not provide a native browser-based OIDC redirect flow for VPN clients.
Korvus Node models OIDC providers and group policies, then connects ocserv to an
external identity bridge through PAM or RADIUS. Use the IdP's PAM/RADIUS integration
or an outpost/proxy that returns ocserv-compatible users and groups.

Required:

- configure OIDC providers such as Keycloak or authentik;
- store provider client secrets through normal secret references;
- render ocserv PAM/RADIUS auth directives;
- render `config-per-group` files;
- map IdP groups to ocserv group policies;
- manage routes, no-routes, DNS, split DNS and client limits per group;
- expose identity and group management in CLI/API/GUI;
- never return `client_secret` from API/GUI reads.

## Sessions

Required:

- list active sessions through occtl;
- parse connected username, VPN IP, real IP, connected time and traffic counters if available;
- disconnect user/session;
- show session details.

## Upstream OpenConnect client

Required:

- enable/disable upstream mode;
- multiple profiles;
- active profile;
- profile switch;
- reconnect loop;
- healthcheck host per profile;
- failover with thresholds;
- logs and status;
- trusted cert option;
- cert/password/p12 auth support;
- secret masking;
- per-profile HOST routing (`route_host_enabled`/`host_routes`/`host_domains`),
  independent of client-side targeting and of the global `routing.host_traffic`;
- accept server-pushed routes and split-DNS domains (`accept_server_routes`),
  merged into the per-profile host routing above;
- mid-session sync of those pushed lists on the live tunnel (`sync_url`/
  `sync_interval`, `korctl upstream sync`), without reconnecting;
- optional client-only deployment (`server.enabled: false`): upstream/host
  routing with no VPN server of its own.

## Routing

Required modes (only meaningful with upstream enabled -- otherwise clients always get
plain NAT through the host):

- full;
- split.

Split mode supports:

- static subnets;
- static IPs;
- domains from YAML;
- domains from file;
- dnsmasq integration;
- nftables sets for resolved domain IPs;
- fwmark-based policy routing;
- dedicated route table;
- reload without full container restart where possible.

Also supported:

- host-traffic routing (full/split), independent of the client-facing mode;
- per-upstream-profile targeted routes/domains, each with its own fwmark/table/kill-switch,
  regardless of which profile is active;
- host DNS handoff to the built-in dnsmasq (`routing.host_dns`: `resolv_conf`/`resolved`),
  so domain-based host routing applies to the host's own lookups too.

## GUI pages

Top-level navigation:

- Dashboard.
- Config, with sub-sections: System, Server, Certificates, Authentication,
  Identity, Upstream (also covers server-side routing/split routes/domains
  and per-profile targeted routing, formerly its own "Routing" tab),
  Internal DNS, Web / API, Advanced -- plus a raw YAML editor with
  validation and diff.
- Users (create/delete, enable/disable, password, certificate/PKCS#12,
  OTP enable/disable/QR are per-user actions here, not a separate page).
- Groups.
- Sessions.
- Diagnostics.
- Logs.
- Terminal (only shown when `web.terminal_enabled` is true).

## CLI/API/GUI parity

The Web GUI is optional and disabled by default, but when enabled it must be a
management interface, not a read-only dashboard. Domain logic lives in backend
services; CLI and API call those same services, and GUI calls the API.

Runtime-dependent operations must expose their command result and dry-run state in
both CLI and GUI where dry-run is available.

| Capability | CLI | GUI |
| --- | --- | --- |
| Validate effective config | `korctl config validate` | Config / Validate and Effective config |
| Edit persistent YAML config | edit `/etc/kornode/config.yaml` and validate/render | Config / Persistent YAML / Save |
| Render generated configs | `korctl config render` | Config / Rendered files / Refresh |
| Diff generated configs | `korctl config diff` | Config / Diff |
| Write generated configs | `korctl config render` | Dashboard or Config / Render configs |
| Start server process | `korctl server start` | Dashboard / Start |
| Stop server process | `korctl server stop` | Dashboard / Stop |
| Reload ocserv process | `korctl server reload` | Dashboard / Reload |
| Restart ocserv process | `korctl server restart` | Dashboard / Restart ocserv |
| Server status | `korctl server status` | Dashboard / Server |
| List managed processes | `korctl server process list` | Dashboard / Runtime processes |
| Control managed process | `korctl server process start/stop/restart/status NAME` | Dashboard / Runtime processes |
| List users | `korctl user list` | Users table |
| Create user | `korctl user create USER` | Users / Create |
| Delete user | `korctl user delete USER` | Users / Account / Delete |
| Enable or disable user | `korctl user enable/disable USER` | Users / Account |
| Change password | `korctl user passwd USER` | Users / Password |
| Issue user certificate | `korctl user cert create USER` | Users / Certificate / Issue |
| Revoke user certificate | `korctl user cert revoke USER` or `korctl user revoke USER` | Users / Certificate / Revoke |
| Create PKCS#12 | `korctl user p12 create USER` | Users / P12 / Create PKCS#12 |
| Apple-compatible PKCS#12 | `korctl user p12 create USER --apple-compatible` | Users / P12 / Apple |
| P12 passphrase | `korctl user p12 create USER --passphrase ...` | Users / P12 / Passphrase |
| Enable OTP | `korctl user otp enable USER` | Users / OTP / Enable |
| Disable OTP | `korctl user otp disable USER` | Users / OTP / Disable |
| Show OTP QR | `korctl user otp show-qr USER` | Users / OTP / Show OTP QR |
| Identity status | `korctl identity status` | Identity |
| Configure OIDC connector | `korctl identity oidc settings` | Identity / OIDC connector |
| Save OIDC provider | `korctl identity oidc provider-set` | Identity / OIDC provider |
| Save group policy | `korctl identity group set --file group.yaml` | Identity / Group policy |
| List sessions | `korctl sessions list` | Sessions |
| Disconnect session | `korctl sessions kick USER` | Sessions / Kick |
| Upstream status | `korctl upstream status` | Upstream / Status |
| List upstream profiles | `korctl upstream list` | Upstream / Profiles |
| Switch upstream profile | `korctl upstream switch PROFILE` | Upstream / Switch |
| Connect active upstream | `korctl upstream connect` | Upstream / Connect |
| List routes | `korctl routes list` | Routing / Routes |
| Add route | `korctl routes add CIDR_OR_IP` | Routing / Routes / Add |
| Delete route | `korctl routes delete CIDR_OR_IP` | Routing / Routes / Delete |
| Reload routes | `korctl routes reload` | Routing / nftables / Reload |
| List domains | `korctl domains list` | Routing / Domains |
| Add domain | `korctl domains add DOMAIN` | Routing / Domains / Add |
| Delete domain | `korctl domains delete DOMAIN` | Routing / Domains / Delete |
| Reload domains | `korctl domains reload` | Routing / nftables / Reload |
| Apply firewall/NAT state | `korctl nft apply` | Dashboard or Routing / Apply firewall/NAT |
| Show nftables state | `korctl nft show` | Routing / Show |
| Cleanup nftables state | `korctl nft cleanup` | Routing / Cleanup |
| Diagnostics | `korctl diagnose` | Diagnostics |
| Logs | `korctl logs NAME --lines N` | Logs |
| Runtime terminal | host `docker compose exec` or API terminal ticket | Terminal / Runtime shell |

GUI diagnostics should classify expected not-yet-ready runtime state as a warning
instead of a hard failure. Example: an `occtl` socket that is not ready while Korvus
Server is still starting. Project-owned nftables tables/chains/sets are rendered and
applied automatically during Korvus Node startup; `korctl nft apply` remains available
for manual re-apply, dry-run checks and repair after runtime changes. It applies only
Korvus Node firewall/NAT state from the rendered nftables file and does not flush
unrelated host rules.

## CLI commands

Implement at least:

```text
korctl config validate
korctl config render
korctl config diff
korctl server start
korctl server stop
korctl server reload
korctl server restart
korctl server status
korctl server process list
korctl server process start PROCESS
korctl server process stop PROCESS
korctl server process restart PROCESS
korctl server process status PROCESS
korctl user list
korctl user create USER
korctl user delete USER
korctl user enable USER
korctl user disable USER
korctl user passwd USER
korctl user cert create USER
korctl user p12 create USER
korctl user revoke USER
korctl user otp enable USER
korctl user otp disable USER
korctl user otp show-qr USER
korctl sessions list
korctl sessions kick USER
korctl upstream status
korctl upstream list
korctl upstream switch PROFILE
korctl routes list
korctl routes add CIDR_OR_IP
korctl routes delete CIDR_OR_IP
korctl routes reload
korctl domains list
korctl domains add DOMAIN
korctl domains delete DOMAIN
korctl domains reload
korctl nft apply
korctl nft show
korctl nft cleanup
korctl diagnose
korctl logs
```
