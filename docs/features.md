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
- optional client-only deployment (`server.enabled: false`): upstream/host
  routing with no VPN server of its own.

## Routing

What leaves the hub and where is one declarative policy: `egress` rules (first match wins),
named `sources` (wg-easy, Amnezia) and destination `sets` of routes and domains
(`docs/spec/02-egress-and-sources.md`). A rule says `from` (clients, host, fabric, a source),
`to` (any, a set, inline routes/domains, a node) and `via` (local, fabric, drop,
`upstream:<profile>`, `exit:<node>`). Traffic of clients and sources that no rule matches
is dropped; without an `egress` key clients leave through the uplink (D-72).

Supported:

- static subnets and IPs, domains (resolved by the service into nftables sets);
- policy routing and kill switch per exit, allocated by the compiler (marks and tables are
  not configuration);
- editing through `korctl egress|source`, `/api/egress`, `/api/sources` and the Network page;
- host DNS handoff to the built-in dnsmasq (`routing.host_dns`: `resolv_conf`/`resolved`).

## GUI pages

Top-level navigation:

- Dashboard.
- Config, with sub-sections: System, Server, Certificates, Authentication,
  Identity, Upstream (external OpenConnect profiles), Internal DNS, Web / API, Advanced -- plus a raw YAML editor with
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
| Diagnostics | `korctl diagnose` | Diagnostics |
| Logs | `korctl logs NAME --lines N` | Logs |
| Runtime terminal | host `docker compose exec` or API terminal ticket | Terminal / Runtime shell |

GUI diagnostics should classify expected not-yet-ready runtime state as a warning
instead of a hard failure. Example: an `occtl` socket that is not ready while Korvus
Server is still starting. Project-owned nftables tables, rules and routes are converged
by the reconciler at startup and on every change; `korctl net plan` shows what it
would change and `korctl net apply` runs one pass. It touches only Korvus Node
objects and does not flush unrelated host rules.

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
korctl egress show
korctl net plan
korctl agent list
korctl fabric show
korctl domains reload
korctl diagnose
korctl logs
```
