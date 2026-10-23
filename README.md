# Korvus Node

Korvus Node (`kornode`) is a Python-first management platform for OpenConnect/ocserv
VPN in Docker. It is a hub plus agents:

- the hub (this image) is an `ocserv` VPN server for users, the registry and control plane for agents, and the
  admin CLI/API/panel;
- agents (`kornode-agent` image) join the hub over ocserv/openconnect on 443/tcp and form a routed overlay (the
  interlink); each node decides where its traffic goes with one declarative egress policy and one reconciler;
- a single node also works on its own as a plain VPN server, optionally dialing external OpenConnect upstreams.

The CLI is the primary interface and always works. The Web API/GUI are optional and
disabled by default.

## Features

- typed Python backend: FastAPI, Typer, Pydantic v2, Jinja2;
- YAML-first configuration;
- configuration fallbacks via `.env` and environment variables;
- settings precedence: CLI overrides -> YAML -> environment -> `.env` -> defaults;
- generates `ocserv.conf`, `dnsmasq.conf`, `nftables.nft`, `supervisor.conf`;
- idempotent runtime initialization: missing configs and auto-certificates are created
  on container start;
- atomic writes for generated files and secret/runtime files;
- centralized secret masking in CLI/API/log-related output;
- manages users, passwords, certificates, PKCS#12, OTP;
- encrypted hub backup and non-destructive staged restore through CLI/API/panel
  (P3-09, awaiting review/runtime acceptance): [recovery runbook](docs/runbooks/hub-recovery.md);
- commands for sessions, agents, interlink, egress policy, sources, upstream profiles, DNS records and
  diagnostics;
- multi-stage Dockerfile with frontend/backend test stages;
- compose file with `/dev/net/tun`, `NET_ADMIN`, `NET_RAW` and persistent volumes.

## Disposable VM testing (redesign P3-10)

The four-VM SSH/Docker harness and protected self-hosted workflow are implemented,
**not yet accepted or executed on real VMs**. See the [E2E runbook](docs/runbooks/vm-e2e.md)
for provisioning, safety gates, recovery and explicit P4/host-network limitations.
`make e2e-plan` is entirely offline; ordinary `make check` skips all VM cases.
`make e2e` requires explicit opt-in, pinned SSH and owner-designated disposable VMs;
never run it on a development or production VPN host.

## Korvus Client

[Korvus Client](https://github.com/r4ven-me/korclient) is the companion client project,
in its own repository: an OpenConnect client in Docker with two modes - full tunnel and
split routing. Route (`route =`) and domain (`split-dns =`) lists are configured
centrally in the kornode web panel (per-user / per-group ocserv configs) and delivered
to the client through the standard AnyConnect handshake on connect; no separate sync
service is required.

## Requirements

Running in Docker requires a Linux host with:

- Docker Engine and the Docker Compose plugin;
- `/dev/net/tun` available;
- permission to run containers with `NET_ADMIN` and `NET_RAW`;
- free ports `443/tcp` and `443/udp` if using the standard VPN port.

Check TUN on the host:

```bash
test -c /dev/net/tun && echo "tun ok"
```

Rootless Docker generally isn't suitable for the full VPN networking stack.

## Quick Start

Build the image, prepare the configs and start the container:

```bash
make docker-build
mkdir -p config data logs
cp config.example.yaml config/config.yaml
cp .env.example .env
docker compose up -d
```

`compose.yaml` runs with `network_mode: host` - this is the target, recommended deployment
scheme, not just a performance tweak for special cases. The container uses the host's
network interfaces directly instead of Docker's bridge/NAT, which removes an extra
`docker-proxy` hop for VPN client traffic and lets the host's own traffic follow the egress
rules (`from: [host]`) and use the built-in `dnsmasq` as its own
resolver - neither is possible under the default bridge network, since host packets
never traverse the container's netfilter there. Two things worth knowing: `nft` rules
are applied directly to the host's netfilter in this mode (not an isolated namespace),
so the image's `nftables` userspace version (built on Debian) should match the host
kernel - a Debian host avoids the issue entirely; and `kornode` only ever creates its
own project-owned tables (`kornode`, `kornode_nat`; no global `flush
ruleset`), so it doesn't touch unrelated host rules. The `devices:` list also has a
commented-out `/dev/vhost-net` entry - an optional accelerated TUN path that `openconnect`
(including the external upstream tunnels) can use if the host supports the
`vhost_net` kernel module. It's off by default because Docker refuses to start a
container whose listed device doesn't exist on the host; uncomment it only after
checking `test -c /dev/vhost-net`. Without it, `openconnect` falls back to a plain
`tun`, only logging a harmless `Failed to open /dev/vhost-net`.

Check the status:

```bash
docker compose ps
docker compose logs -f kornode
docker compose exec kornode korctl server status
```

Expected signs of a successful start:

- the container is `healthy` or `running`;
- the logs contain `ocserv entered RUNNING state`;
- `korctl server status` shows `ocserv RUNNING`;
- `ocserv` listens on `0.0.0.0:443` over TCP and UDP.

Check listening ports inside the container:

```bash
docker compose exec kornode sh -lc 'ss -lntup | grep 443'
```

Under `network_mode: host` there's no Docker port-publishing step at all - whatever the
container binds to, the host has directly. The Web API/GUI are simply disabled
(`web.enabled: false`) by default, so `curl 127.0.0.1:8443` isn't a valid check of the
VPN server under normal operation. To check the Web component, use the separate override
described in "Web API and GUI".

Stop:

```bash
docker compose down
```

The project never deletes runtime data automatically. To start fresh, remove the local
volume directories explicitly:

```bash
docker compose down
rm -rf data logs
```

## Directory Structure

Key files:

- `backend/kornode/` - Python package, CLI, API, config models, services, renderers;
- `frontend/` - Vite/React/TypeScript GUI source;
- `templates/` - Jinja2 templates for generated system configs;
- `tests/` - pytest coverage;
- `docs/` - additional notes on architecture, security, networking, Docker and the web panel;
- `examples/` - minimal, full, hub-with-upstream (`middle-server`) and client-only configurations;
- `Dockerfile` - frontend/backend test stages and the runtime image;
- `compose.yaml` - production-like container startup;
- `config.example.yaml` - main example YAML config;
- `.env.example` - example env overrides and secret values;
- `Makefile` - local and Docker check commands.

Runtime volumes for `docker compose up`:

- `./config:/etc/kornode` - user configuration;
- `./data:/var/lib/kornode` - generated configs, secrets, certs, route/domain files;
- `./logs:/var/log/kornode` - runtime logs.

Key runtime paths inside the container:

- `/etc/kornode/config.yaml` - main YAML config;
- `/var/lib/kornode/generated/ocserv.conf` - rendered ocserv config;
- `/var/lib/kornode/generated/supervisor.conf` - rendered supervisor config;
- `/var/lib/kornode/secrets/ocpasswd` - password auth database;
- `/var/lib/kornode/secrets/users.oath` - OTP users file;
- `/var/lib/kornode/certs/` - CA/server/user certificates;
- `/var/log/kornode/` - application/supervisor logs.

## Build and Checks

CI-friendly checks:

```bash
make docker-test
make docker-build
make docker-cli-check
```

`make docker-test` builds two test stages:

- `frontend-test`: `npm ci`, `npm audit --audit-level=moderate`, production build;
- `backend-test`: install `.[dev]`, `ruff`, `mypy`, `pytest`, dry-run render.

Local backend development:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make check
make render
```

Local frontend build:

```bash
make frontend-build
make frontend-audit
```

### Releasing an image

GitHub Actions publishes two images to GHCR automatically: the hub
(`ghcr.io/r4ven-me/kornode`, `Dockerfile`) and the agent (`ghcr.io/r4ven-me/kornode-agent`,
`Dockerfile.agent`):

1. bump `version` in `pyproject.toml` and push it to `main` (directly or via a PR);
2. the `CI` workflow runs on that commit;
3. once CI passes, the `Release image` workflow (`.github/workflows/release-image.yml`)
   checks for each image whether `v<version>` already exists. If it doesn't, the workflow
   builds that image and pushes it as `v<version>` and `latest`.

Pushes that don't change the version find both tags already published and skip the build.
The workflow can also be started by hand from the Actions tab ("Run workflow"). If the
`OCSERV_SHA256` repository variable is set, the build verifies the ocserv source tarball
against it.

## Configuration

The main file is YAML:

```bash
cp config.example.yaml config/config.yaml
```

Minimal working VPN config:

```yaml
system:
  data_dir: /var/lib/kornode
  log_dir: /var/log/kornode
  generated_dir: /var/lib/kornode/generated
  secrets_dir: /var/lib/kornode/secrets

server:
  enabled: true
  listen: 0.0.0.0
  port: 443
  udp_enabled: true
  device: vpns
  cn: vpn.example.com
  ipv4_network: 10.10.10.0/24
  dns:
    - 1.1.1.1
    - 8.8.8.8

certificates:
  mode: auto
  letsencrypt:
    enabled: false
    email: null
    domains: []
    renew_reload: true
    auto_renew_enabled: true
    auto_renew_interval: 7
    auto_renew_interval_unit: days # hours | days | weeks | months

auth:
  password:
    enabled: true
  certificate:
    enabled: false
  otp:
    enabled: false
    ocserv_oath_auth: false

upstream:
  enabled: false

web:
  enabled: false
```

Validate the YAML without writing files:

```bash
docker compose run --rm --entrypoint korctl kornode \
  --config /etc/kornode/config.yaml config validate
```

Preview rendered configs without writing:

```bash
docker compose run --rm --entrypoint korctl kornode \
  --config /etc/kornode/config.yaml config render --dry-run
```

Write the rendered configs:

```bash
docker compose exec kornode korctl config render
```

Diff between the current generated files and a fresh render:

```bash
docker compose exec kornode korctl config diff
```

### Configuration Reference

Every top-level field `AppConfig` knows about is in `examples/config.full.yaml` (validated by
`tests/test_examples.py`); `config.example.yaml` is the annotated hub config. Values are illustrative, not
defaults; anything you omit falls back to the real default in `backend/kornode/config/models.py`. Other examples:
`config.minimal.yaml` (plain VPN server), `config.middle-server.yaml` (hub with an external upstream) and
`config.client.yaml` (client-only node). Addressing, `interlink`, `control`, `egress`, `sources` and `sets` are
described in "Interlink, Agents and Egress"; legacy v1 routing keys are rejected as unknown.
Section by section, beyond what's already covered in depth elsewhere in this README:

- `system` - runtime paths and log level/rotation; `project_name` feeds the ocserv
  `device` name prefix and the default nftables table prefix.
- `server` - `connect_script`/`disconnect_script` are optional host-side hooks ocserv
  runs on client connect/disconnect (absolute paths inside the container); `camouflage`
  makes `ocserv` masquerade as a plain web service until the connecting client's URL
  includes `?<camouflage.secret>`, defeating simple active probing.
- `certificates` - see "Certificates and PKCS#12" for `mode`/Let's Encrypt in depth.
- `auth` - password/certificate/OTP are covered in "Users and Passwords"/"OTP"; `oidc`
  is the experimental PAM/RADIUS bridge, covered next.
- `identity` - OIDC providers and group policies, covered in "OIDC / Identity"
  (**experimental, not verified against a real IdP in production** - see that section).
- `upstream` - external OpenConnect profiles, covered in "Upstreams";
  `cert_file_base64`/`key_file_base64` let a profile's client certificate/key travel
  as a `.env` secret instead of a mounted file, the same pattern Korvus Client uses.
- `interlink`, `control`, `egress`, `sources`, `sets` - the interlink, agent control plane and egress policy, covered in
  "Interlink, Agents and Egress"; `routing` only keeps host-level settings (`host_dns`, `main_interface`).
- `internal_dns` - the built-in blocking resolver; unlisted here beyond the minimal
  example, but every field is self-explanatory from its name (domains/files/URLs to
  block, DNS cache size, query logging, local A-record overrides).
- `web` - the panel, covered in depth in "Web API and GUI"; `tls_cert`/`tls_key` (both
  required together, or both left `null` for the auto-generated certificate) let you
  bring your own certificate for the panel independent of the VPN's own certificates;
  `admin_totp_*` is managed entirely through the panel's own two-factor setup flow, not
  meant to be hand-written - `admin_totp_secret` only exists here because it has to live
  somewhere once you enable it.
- `cli` - `enabled: false` would disable the CLI, which contradicts the project's
  "CLI is always the primary interface" principle; there's essentially no good reason to
  set this.
- `advanced.raw_ocserv_options` - an escape hatch straight into `ocserv.conf`: a mapping
  renders as `key = value` lines (`null` value for a bare flag), a list renders each
  entry verbatim as-is, for any directive the typed config doesn't model yet.

## Environment Fallbacks and Secrets

Any field omitted from YAML can be supplied with an environment variable prefixed
with `KORNODE_`. Values explicitly stored in YAML take precedence over environment
variables so settings saved through the web panel remain effective after a restart.
This is a compatibility runtime namespace kept from an earlier version of the project:
the public utility is called `korctl`, while the product is Korvus Node.
Nesting is expressed with a double underscore:

```env
KORNODE_SERVER__PORT=4443
KORNODE_SERVER__DNS='["1.1.1.1", "9.9.9.9"]'
KORNODE_INTERNAL_DNS__RESOLVER_ENABLED=true
KORNODE_INTERNAL_DNS__LISTEN=10.10.10.1
KORNODE_INTERNAL_DNS__PORT=53
KORNODE_WEB__ENABLED=false
```

Lists are passed as a JSON string.

`KORNODE_*` variables without `__` aren't treated as config overrides. You can use
them as plain secret values, e.g. `KORNODE_ADMIN_PASSWORD` for
`${SECRET:KORNODE_ADMIN_PASSWORD}`.

`.env` supports plain `KEY=value`, an optional `export` prefix, quoted values and
inline comments after unquoted values:

```env
export KORNODE_SERVER__REALM="Corp # VPN"
KORNODE_SERVER__CN=vpn.example.com # comment
```

Secrets can be kept in `.env` and referenced from YAML with `${SECRET:NAME}`:

```yaml
upstream:
  profiles:
    - name: private-main
      server: private.example.com
      username: middle-user
      password: "${SECRET:PRIVATE_MAIN_PASSWORD}"
```

`.env`:

```env
PRIVATE_MAIN_PASSWORD=change-me
```

Secrets must never end up in the README, issues, shell history or logs. The CLI/API
mask known secret values and strings like `password=...`, `token=...`, `secret=...`.

## Managing Korvus Node

Status:

```bash
docker compose exec kornode korctl server status
```

Reload `ocserv` via `korctl`:

```bash
docker compose exec kornode korctl server reload
```

Dry-run reload:

```bash
docker compose exec kornode korctl server reload --dry-run
```

`reload` sends `SIGHUP` to `ocserv`. That's enough for some changes, but not every
ocserv setting is applied via HUP. If behavior doesn't change after render/reload,
fully restart just the `ocserv` process without restarting the container:

```bash
docker compose exec kornode korctl server restart
docker compose exec kornode korctl server restart --dry-run
```

Stop the managed processes inside the container:

```bash
docker compose exec kornode korctl server stop
```

Manage individual supervisor runtime processes through the main utility:

```bash
docker compose exec kornode korctl server process list
docker compose exec kornode korctl server process restart dnsmasq
docker compose exec kornode korctl server process status certbot-renew
```

For day-to-day operation it's usually better to manage the container through Compose:

```bash
docker compose restart kornode
docker compose logs -f kornode
```

## Users and Passwords

Create a password-auth user:

```bash
docker compose exec kornode korctl user create alice
```

The CLI prompts for the password interactively and never echoes it.

List users:

```bash
docker compose exec kornode korctl user list
```

Change a password:

```bash
docker compose exec kornode korctl user passwd alice
```

Disable/enable a user:

```bash
docker compose exec kornode korctl user disable alice
docker compose exec kornode korctl user enable alice
```

Delete a user:

```bash
docker compose exec kornode korctl user delete alice
```

Without an interactive confirmation:

```bash
docker compose exec kornode korctl user delete alice --yes
```

A reload is usually enough after changing users:

```bash
docker compose exec kornode korctl server reload
```

## Certificates and PKCS#12

In:

```yaml
certificates:
  mode: auto
```

the container creates a CA and server certificate on first start if they don't already
exist.

Three practical scenarios are available for the server TLS certificate:

- `auto`: a local CA and server certificate are created inside the persistent volume;
- manual upload through the GUI: files are saved to `data/certs/external/`, the config
  switches to `certificates.mode: external`;
- Let's Encrypt through the GUI or CLI: uses `certbot certonly --standalone`, the active
  paths switch to the persistent `data/certbot/config/live/<domain>/`.

For Let's Encrypt, HTTP-01 port `80/tcp` must be reachable from outside and point at the
container. If `certificates.letsencrypt.enabled: true`, Korvus Node tries to obtain a
certificate on startup before `ocserv` starts, so the first VPN/Web TLS startup can
already use a valid chain. A certbot error at startup is logged and shouldn't crash the
container: see `/var/log/kornode/startup.log` and
`/var/log/kornode/certbot/letsencrypt.log`. After a manual upload, issue or renew, the
panel renders an up-to-date `ocserv.conf` and can immediately reload or restart
`ocserv`.

Paths:

- CA: `data/certs/ca.crt`, `data/certs/ca.key`;
- server cert/key: `data/certs/server.crt`, `data/certs/server.key`;
- external server cert/key/chain: `data/certs/external/server.crt`, `server.key`,
  `ca.crt`;
- user certs: `data/certs/users/<username>.crt`, `.key`, `.p12`.

Enable certificate auth:

```yaml
auth:
  password:
    enabled: true
  certificate:
    enabled: true
```

Create a client certificate:

```bash
docker compose exec kornode korctl user cert create alice
```

Create a PKCS#12 bundle:

```bash
docker compose exec kornode korctl user p12 create alice
```

The command supports a passphrase via `--passphrase VALUE`. Don't pass a real
passphrase through shell history on a production host; a temporary value is fine for
testing, and production should use a secure input/secret wrapper instead.

```bash
docker compose exec kornode korctl user p12 create alice --passphrase "$KORNODE_P12_PASSPHRASE"
```

Apple-compatible PKCS#12:

```bash
docker compose exec kornode korctl user p12 create alice --apple-compatible
```

Revoke a certificate and generate a CRL:

```bash
docker compose exec kornode korctl user cert revoke alice
```

## OTP

Enable OTP in YAML:

```yaml
auth:
  password:
    enabled: true
  certificate:
    enabled: false
  otp:
    enabled: true
    ocserv_oath_auth: false
    issuer: Korvus Node
```

`enabled` turns on OTP secret management in the CLI/API/GUI. `ocserv_oath_auth` adds
`auth = "oath[...]"` to `ocserv.conf`; only enable it if your `ocserv` build supports
the OATH backend, otherwise the server won't be able to start.

Enable OTP for a user:

```bash
docker compose exec kornode korctl user otp enable alice
```

Show the QR code in the terminal:

```bash
docker compose exec kornode korctl user otp show-qr alice
```

Disable OTP:

```bash
docker compose exec kornode korctl user otp disable alice
```

OTP secrets are stored in `data/secrets/users.oath`.

## OIDC / Identity

**Experimental.** This feature is implemented and covered by unit tests, but hasn't been
verified end-to-end against a real IdP in production, and doesn't have the same
real-world mileage as the rest of the project. Treat it as a starting point to adapt and
test thoroughly against your own Keycloak/Authentik/RADIUS setup before relying on it,
not as a drop-in.

`ocserv` has no native browser-redirect OIDC flow for VPN clients. Korvus Node adds
an identity model for Keycloak/Authentik-like IdPs, generates ocserv `config-per-group`
files and hooks up real VPN authentication through a PAM or RADIUS bridge. Use a
PAM/RADIUS integration, or an outpost/proxy that returns ocserv-compatible users/groups.

Example YAML:

```yaml
auth:
  password:
    enabled: false
  oidc:
    enabled: true
    connector: pam
    pam:
      service: ocserv-oidc

identity:
  config_per_group_dir: /var/lib/kornode/generated/config-per-group
  select_group_by_url: true
  default_select_group: devops
  oidc_providers:
    - name: keycloak
      issuer_url: https://sso.example.com/realms/vpn
      client_id: kornode-vpn
      client_secret: "${SECRET:OIDC_CLIENT_SECRET}"
      username_claim: preferred_username
      groups_claim: groups
      allowed_groups:
        - devops
        - finance
  group_policies:
    - name: devops
      display_name: DevOps
      routes:
        - 10.20.0.0/16
      dns:
        - 10.10.10.1
      split_dns:
        - corp.example.com
      max_same_clients: 4
```

CLI:

```bash
korctl identity status
korctl identity oidc settings --enabled --connector pam --pam-service ocserv-oidc
korctl identity oidc provider-set keycloak \
  --issuer-url https://sso.example.com/realms/vpn \
  --client-id kornode-vpn
korctl identity group set --file group-devops.yaml
```

GUI: the `Identity` tab manages connector settings, OIDC providers and group policies.
The API/GUI never return `client_secret`; keep it in `${SECRET:OIDC_CLIENT_SECRET}`.

## Sessions

List active sessions via `occtl`:

```bash
docker compose exec kornode korctl sessions list
```

Kick a user:

```bash
docker compose exec kornode korctl sessions kick alice
```

Dry-run:

```bash
docker compose exec kornode korctl sessions kick alice --dry-run
```

## Interlink, Agents and Egress

Kornode v2 is a hub plus agents. This server is the **hub** (node 1). Other machines run the `kornode-agent`
image (agents, nodes 2..254) and join the hub over ocserv/openconnect on 443/tcp, forming a routed overlay (the
interlink). Nothing else carries traffic between nodes. The data plane does not depend on the hub being up: an agent
with a cached bundle keeps forwarding and boots from cache. Addressing, the egress compiler and the kernel layout
are described in [docs/networking.md](docs/networking.md) and [docs/architecture.md](docs/architecture.md); the
contracts are in `docs/spec/`.

With default settings, node `<id>` gets interlink address `10.99.0.<id>`, client pool `10.100.<id>.0/24`, service
address `10.100.<id>.1` and DNS zone `node<id>.kornode.lan`. Overlapping prefixes are rejected
(`409 address_overlap`, `korctl` exit code 3).

### Adding an agent

The hub needs three things first: `control.enabled: true` in its config (the control plane listens on the interlink
address `10.99.0.1:8444`, reached from inside the tunnel); `server.cn` set to a name or address the new node can
reach, because the enroll token carries `server.cn:server.port` as the hub address; and that port (443/tcp by
default) open. The agent only dials out, so it needs no inbound port unless it has the `access` role.

On the hub (or in the panel: Agents → Add agent; the token is shown once and expires after
`control.enroll_token_ttl_minutes`, 60 by default):

```bash
docker compose exec kornode korctl agent create site-a --role gateway   # roles: access, gateway (optional)
docker compose exec kornode korctl agent token site-a                # one-time enroll token
```

On the new node (Docker with `/dev/net/tun`; `compose.agent.yaml`, `network_mode: host`, persistent
`./agent-data`), either build the `kornode-agent` image from a checkout of this repository or take the published
one; only `compose.agent.yaml` is needed for the latter:

```bash
# published image, no source tree
export KORNODE_AGENT_IMAGE=ghcr.io/r4ven-me/kornode-agent:latest
docker compose -f compose.agent.yaml pull

docker compose -f compose.agent.yaml run --rm agent kornode-agent enroll <token>
docker compose -f compose.agent.yaml up -d
```

Without `KORNODE_AGENT_IMAGE` the same commands build `Dockerfile.agent` from the checkout. `./agent-data` holds the
agent's keys, certificate and cached bundle: keep it, it is what lets the agent boot and forward while the hub is
down. The agent appears as `active · online` under Agents and in Interlink → Topology.

Then manage the agent from the hub: `korctl agent list|show|set|status|revoke|delete`, its exported networks
(`korctl agent prefix list|add|del`), its egress policy (`korctl agent egress show|set|edit`), sources
(`korctl agent source`), external upstreams (`korctl agent upstream`), the optional local ocserv listener for the
`access` role (`korctl agent access`, `korctl agent user`), bundle history (`korctl agent bundle`) and remote
commands (`korctl agent exec`). Every operation exists in the REST API and in the panel's Agents tab (CLI ⇄ API ⇄
Web parity). On the agent, `kornode-agent status|explain|doctor|diag|reconnect|bundle` work offline from the
cached state.

`korctl interlink show` prints the topology, prefixes, DNS and sources; `korctl interlink set` changes interlink settings
(Interlink tab in the panel). Interlink DNS records: `korctl dns record list|add|del`.

### Egress policy

What leaves where is one ordered list per node; the **first match wins**. On the hub it is in `config.yaml`; for
agents it is stored in the registry and delivered in the bundle. Without an explicit `egress`, the hub's clients
leave through the uplink (`clients -> any via local`); an explicit list replaces that rule, and traffic of clients
and sources that no rule matches is dropped.

```yaml
sources:                       # attached access servers (wg-easy, Amnezia)
  - {name: wg, interface: wg0, cidr: 10.8.1.0/24, export: true}
sets:                          # reusable destination sets
  corp:
    routes: [10.20.0.0/16]
    domains: [corp.example.com]
egress:
  - from: [clients, wg]        # clients, host, interlink or a source name
    to: {set: corp}            # any | interlink | {set: n} | {routes, domains} | {node: id}
    via: upstream:office       # local | interlink | node:<n> | upstream:<profile> | drop
  - from: [clients, wg]
    to: any
    via: local
```

Traffic assigned to a tunnel **fails closed**: while the tunnel is down or reconnecting it is rejected rather than
sent through the uplink (`kill_switch`, default `true` for every `via` except `local`). Connected networks (LANs,
docker bridges) and tunnel carrier addresses always win over rules. There is no NAT inside the interlink; masquerade is
applied only toward the internet and toward upstreams. Domains of a set are resolved into nft sets by
`DomainResolverService` (`korctl domains resolve|reload|watch`); clients routed by domain should use the node's
dnsmasq so they get the same addresses.

```bash
docker compose exec kornode korctl egress show
docker compose exec kornode korctl egress check            # validation, dead-rule warnings
docker compose exec kornode korctl egress set --help
docker compose exec kornode korctl source --help
docker compose exec kornode korctl net plan                # what the reconciler would change
docker compose exec kornode korctl net explain --help      # why traffic from SRC to DST goes where it goes
```

In the panel: Network → Egress rules and Sources (hub) and Agents → policy (agents). Sources are documented in
[docs/sources.md](docs/sources.md): run the access server in `network_mode: host` and disable its own NAT hooks,
kornode owns routing and NAT for the source subnet (`korctl doctor` reports foreign NAT rules as an error).

### Firewall and NAT

kornode owns only its objects: nft tables `inet kornode` and `ip kornode_nat`, `ip rule` priorities 90-199, route
tables 12000-12999 and `main` routes with `proto 77`. It never flushes the host ruleset. Only the reconciler writes
them; nothing needs a manual "apply" step. If `nft` exits with `signal 11` inside the container while the same
rules load on the host, the image's `nftables` userspace does not match the host kernel: update the image or use a
base image aligned with the host (Debian hosts avoid it).

## Upstreams

An upstream is an external OpenConnect server (or an existing network interface) that the node dials out to and
uses as `via: upstream:<profile>`. Profiles are defined under `upstream.profiles` on the hub, or per agent. The
rules above decide which traffic uses which profile; there is no separate routing mode. Several profiles can be
connected at once, each with its own tunnel device.

```yaml
upstream:
  enabled: true
  active_profile: private-main
  failover: true
  profiles:
    - name: private-main
      server: private.example.com
      port: "443"
      auth_type: password        # password | cert | p12
      username: middle-user
      password: "${SECRET:PRIVATE_MAIN_PASSWORD}"
      check_host: 10.11.11.1     # pinged through the tunnel by the watchdog
```

```bash
docker compose exec kornode korctl upstream list
docker compose exec kornode korctl upstream status
docker compose exec kornode korctl upstream connect private-main --dry-run
docker compose exec kornode korctl upstream switch private-main
docker compose exec kornode korctl upstream enable|disable private-main
```

A supervised watchdog (`upstream.check_interval`, `check_threshold`, `failover`) pings `check_host` through the
tunnel and redials, cycling through profiles when `failover` is on. `examples/config.middle-server.yaml` is a
complete hub with an upstream.

### Trusting the upstream certificate

`openconnect` only accepts an upstream certificate signed by a trusted public CA. The
old `--no-cert-check` switch was removed from openconnect. So when the upstream uses
its own CA (for example another Korvus Node in `auto` certificate mode), pin its
certificate in the profile's `server_cert_pin`. It is passed as `--servercert`:

1. On the **upstream** server, open Config → Certificates → *Server certificate* and
   click **Show connection pin**, or run `korctl certificates pin`. Copy the
   `pin-sha256:...` value.
2. On **this** server, paste it into the upstream profile's *Server cert pin* field.
   Or click **Fetch** next to that field (`korctl upstream fetch-pin HOST --port PORT`):
   it reads the certificate the upstream presents right now and asks you to confirm.
   Before accepting, compare the pin with the one from step 1.

The pin covers the certificate's public key, not the certificate itself, so it stays valid
across renewals that keep the key. Korvus Node always keeps it: re-issuing the auto-mode
certificate reuses `server.key`, and Let's Encrypt certificates are issued and renewed with
certbot `--reuse-key`. The pin only changes when the key is rotated on purpose (delete
`server.key`, upload other external certificates). Then update the pin on the servers that
use it.

**Automatic mode, no pin to maintain.** Leave *Server cert pin* empty and enable
*No cert check* (`trusted_cert: true`). At every connect, including the watchdog's
reconnects, kornode reads the certificate the server presents and passes its pin to
openconnect, so a changed upstream certificate never breaks the connection. If the key
differs from the last accepted one, a warning is written to the upstream log. The
trade-off is no protection against a man-in-the-middle on the path to the upstream. An
explicit `server_cert_pin` always wins over this mode.

### Using an existing interface instead of dialing out

A profile can point at an interface that already exists on the host - for example a WireGuard
interface brought up outside kornode (`wg-quick`, systemd-networkd) - instead of dialing:

```yaml
upstream:
  profiles:
    - name: site-b-wireguard
      kind: external_interface
      interface: wg0
```

Give `interface` explicitly. kornode never creates, brings up, tears down or redials this interface; it only
applies the egress rules, NAT and kill switch on top of it (`via: upstream:site_b_wireguard`, the profile slug). Dial-specific
fields (`server`, `auth_type`, ...) do not apply. The watchdog only observes the link state.

### Host DNS

`routing.host_dns` points this **host's** own resolver at the built-in dnsmasq, so the host's own lookups get the
blocklist and local-records effect. It is not needed for domain-based egress: set domains are resolved
independently of whichever resolver the host uses.

```yaml
routing:
  host_dns: resolv_conf
```

- `resolv_conf` - rewrites `/etc/resolv.conf` in place; the original is kept in
  `data_dir` and restored automatically when `host_dns` is turned off or the container
  stops.
- `resolved` - installs a `systemd-resolved` drop-in instead. After the first time this
  is enabled, run `systemctl restart systemd-resolved` on the host once - resolved only
  reads new drop-ins on (re)start, and the container cannot restart a host service
  itself. The drop-in file is removed automatically when `host_dns` is turned off or the
  container stops, but that removal needs the same manual restart to take effect.

Only takes effect while dnsmasq is running, so the host is never pointed at a resolver that isn't there. Either
mode needs the host's resolver file/directory bind-mounted into the container, on top of the `network_mode: host`
the base `compose.yaml` already uses - see "Client-only deployment" below.

### Client-only deployment

With `server.enabled: false` kornode runs purely as an outbound client - no ocserv, just the upstream tunnel(s),
egress rules for the host's own traffic and, optionally, `routing.host_dns`:

```bash
cp examples/config.client.yaml config/config.yaml
docker compose -f compose.yaml -f compose.client.yaml up -d
```

`examples/config.client.yaml` has a complete profile with `from: [host]` egress and `routing.host_dns:
resolv_conf`; `compose.client.yaml` adds the `/etc/resolv.conf` bind mount that mode needs (a commented
alternative mount is included for `resolved`).

Reconnect, failover and end-to-end access to the private network depend on the real network, the upstream
server and nftables/policy routing on the host (`NET_ADMIN` is required). Verify this on a test setup before
enabling it in production.


## Web API and GUI

Web is disabled by default:

```yaml
web:
  enabled: false
```

Web stays off by default. This is intentional: the CLI stays the primary interface, and
Web shouldn't accidentally become reachable without a deliberate, explicit config
change.

For a local Web API/GUI check, use the override:

```bash
docker compose -f compose.yaml -f compose.web.yaml up --build -d
curl -kfsS https://127.0.0.1:8443/healthz
```

`compose.web.yaml` enables Web and makes Uvicorn listen on `127.0.0.1` inside the
container over HTTPS. Since the base `compose.yaml` runs with `network_mode: host`,
that's the real host loopback directly - no Docker port publishing is needed or used,
and nothing about Web is reachable from outside the host. The `kornode`
auto-certificate is used by default; the browser will warn about a private CA until
that CA is trusted or a public certificate is configured.

If you enable `web.enabled: true`, supervisor starts the Uvicorn API and serves the
static frontend from `/usr/share/kornode/frontend`, if a frontend build is present in
the image.

What each section of the panel does, and in which order to use them, is described in
[docs/panel.md](docs/panel.md).

Health endpoint from inside the container:

```bash
docker compose exec kornode curl -kfsS https://127.0.0.1:8443/healthz
```

The GUI only sends the password to the login endpoint and gets back a short-lived
`HttpOnly`/`SameSite=Strict` cookie session. Mutating requests are additionally
protected by a CSRF token. HTTP Basic remains available for external API clients and
diagnostics. Configure:

```yaml
web:
  enabled: true
  listen: 0.0.0.0
  port: 8443
  tls: true
  admin_user: admin
  admin_password_hash: "${SECRET:KORNODE_ADMIN_PASSWORD_HASH}"
  session_lifetime: 3600
  session_cookie_secure: true
  terminal_enabled: false
  # Off by default even with web.enabled: true -- only turn this on if
  # Korvus Client sync (GET /api/client/routing) needs to reach it.
  client_sync_enabled: false
```

`.env`:

```env
KORNODE_ADMIN_PASSWORD_HASH=change-me
```

Generate a scrypt hash without passing a password through command-line arguments:

```bash
docker compose run --rm --entrypoint korctl kornode web hash-password
```

The `admin_password` field is kept for bootstrap and compatibility, but
`admin_password_hash` is preferred for production.

For a TLS-terminating reverse proxy, disable the built-in TLS and explicitly allow
internal HTTP:

```yaml
web:
  enabled: true
  listen: 127.0.0.1
  port: 8443
  tls: false
  allow_insecure_http: true
  trusted_proxies:
    - 127.0.0.1
```

The proxy should connect to this loopback/private endpoint and only publish HTTPS.
Don't expose the HTTP Web API directly.

Since `compose.yaml` runs with `network_mode: host`, `kornode` has no bridge-network
IP of its own for a separate proxy container to reach by a Docker network CIDR - the
proxy needs to reach it via the host's own `127.0.0.1`, which means running the proxy
with `network_mode: host` too (or natively on the host, outside Docker entirely).
Uvicorn will then only accept `X-Forwarded-For` and `X-Forwarded-Proto` from the trusted
proxy source. Don't widen `trusted_proxies` beyond what you actually need.

`trusted_proxies` is not scoped to just the admin panel: the same trusted
`X-Forwarded-For` value is also what login rate-limiting keys on, and what the
unauthenticated, VPN-client-facing `/api/client/routing` endpoint uses to identify
which connected client is asking for its own routes/split-DNS domains. Only list a
proxy that strictly *overwrites* `X-Forwarded-For` on anything it forwards (never one
that appends to or passes through a value it received from someone else), and that
itself only accepts connections from sources you trust - otherwise a client able to
reach that proxy could spoof another VPN user's source IP (reading their routes) or
reset their own login-lockout counter at will.

Keep `session_cookie_secure` enabled behind an HTTPS reverse proxy too. Only disable it
for isolated local HTTP development.

Compose override for this setup:

```bash
docker compose -f compose.yaml -f compose.proxy.yaml up -d
```

In the Docker override, the API listens on `127.0.0.1` inside the container - the real
host loopback, since networking is shared - which is also the address a host-networked
reverse proxy will present as its own source, matching the default
`trusted_proxies: [127.0.0.1]` above.

The interactive root terminal is disabled by default. To enable it in a controlled way:

```yaml
web:
  terminal_enabled: true
  terminal_idle_timeout: 900
  terminal_max_sessions: 2
```

Opening and closing terminal sessions, as well as mutating API requests, are logged to
`/var/log/kornode/audit.jsonl`. Request bodies, passwords and tokens never end up
there.

The `korpanel` GUI opens at `https://127.0.0.1:8443/` once Web is enabled. The static
shell can load without credentials, but no data or actions are available without
logging in. It's a full management interface over the same backend services as the
CLI:

- Dashboard: start/stop/reload/restart `ocserv`, supervisor runtime processes,
  DNS/firewall/log/config status, writing the generated config, apply firewall/NAT;
- Users: create/delete, enable/disable, change password, OTP enable/disable, OTP QR,
  issue/revoke certificate, PKCS#12 export/download, passphrase and Apple-compatible
  mode;
- Sessions: list of active sessions via `occtl` and kicking a user;
- Agents: create/revoke/delete, enroll tokens, per-agent policy (egress, sources, prefixes, upstreams), access
  listener and users, bundle history, remote commands, backup/restore of the hub;
- Interlink: topology, interlink settings, interlink DNS records;
- Network: hub egress rules, sources and sets (`/api/egress`, `/api/sources`);
- Upstream profiles: status, list/create/edit/delete, switch active profile, connect/disconnect, check host +
  auto-reconnect/failover settings;
- Config: edit the persistent `/etc/kornode/config.yaml`, validate YAML, save with an
  atomic write, rendered files, diff and write rendered files;
- Diagnostics: runtime probes split into ok/warning/error;
- Logs: tail files from the configured log directory, including nested logs like
  `certbot/letsencrypt.log`, with manual loading and a live mode in the GUI;
- Terminal: an interactive runtime `/bin/bash` PTY session over a WebSocket ticket,
  running inside the already-started container and rendered via xterm.js with support
  for ANSI, cursor control, resize and full-screen TUI programs.

The top of the GUI has a global `Dry-run` toggle for risky runtime commands and a
light/dark theme switch. The color scheme is close to the Nord palette.

Frontend checks:

```bash
make frontend-test
make frontend-e2e
make frontend-build
make frontend-audit
```

Vitest checks the cookie/CSRF API flow. The xterm.js code loads as a separate lazy
chunk only when the enabled Terminal tab is opened.

A Playwright smoke test walks every section of the panel and checks the conditional
rendering of the terminal with a mocked API. In environments without a bundled
Chromium, you can set:

```bash
PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium make frontend-e2e
```

## Connecting a Client

After the server has started and a user has been created, you can connect with an
OpenConnect client:

```bash
openconnect --protocol=anyconnect vpn.example.com
```

If using a non-standard port:

```bash
openconnect --protocol=anyconnect vpn.example.com:4443
```

To test from the host running Docker with `443` published, you can use the host's
address or a DNS name pointing at the host.

If using the auto CA, the client may need to trust `data/certs/ca.crt` or explicitly
accept the self-signed chain in a test environment.

## Diagnostics and Logs

Diagnostics without running any risky actions:

```bash
docker compose exec kornode korctl diagnose --dry-run
```

Runtime diagnostics:

```bash
docker compose exec kornode korctl diagnose
```

Docker logs:

```bash
docker compose logs -f kornode
```

Logs via the CLI:

```bash
docker compose exec kornode korctl logs api.log --lines 100
docker compose exec kornode korctl logs supervisord.log --lines 100
docker compose exec kornode korctl logs certbot/letsencrypt.log --lines 100
```

Check the generated files:

```bash
docker compose exec kornode ls -la /var/lib/kornode/generated
docker compose exec kornode sed -n '1,160p' /var/lib/kornode/generated/ocserv.conf
```

Check processes:

```bash
docker compose exec kornode korctl server process list
docker compose exec kornode pgrep -a ocserv
```

## Security Notes

- Don't commit `.env`, `data/`, `logs/`, private keys, PKCS#12 or generated secrets.
- Don't pass passwords via shell arguments in production if that ends up in history.
- CLI prompts for passwords hide the input.
- Render/diff/API output masks secrets, but secret files on the volume remain your own
  responsibility.
- `data/certs/ca.key` is the one key secret behind the whole auto-CA. Keep a separate,
  protected backup of it.
- `nft apply` and `nft cleanup` affect the container's network rules. Use `--dry-run`
  first.
- The GUI Terminal opens an interactive shell session inside the container via a
  one-time WebSocket ticket issued by the admin API. Don't expose the Web API without
  TLS, a strong password and network access restrictions.
- The project never deletes user files without an explicit command.

## Troubleshooting

Container unhealthy:

```bash
docker compose ps
docker compose logs --tail=200 kornode
docker compose exec kornode korctl server status
```

No `/dev/net/tun`:

```bash
test -c /dev/net/tun
sudo modprobe tun
```

Port 443 in use:

```bash
ss -lntup | grep ':443'
```

Change the port mapping and `server.port`, e.g.:

```yaml
server:
  port: 4443
```

`compose.yaml`:

```yaml
ports:
  - "4443:4443/tcp"
  - "4443:4443/udp"
```

Errors in YAML/env:

```bash
docker compose run --rm --entrypoint korctl kornode \
  --config /etc/kornode/config.yaml config validate
```

See what config would actually be generated:

```bash
docker compose run --rm --entrypoint korctl kornode \
  --config /etc/kornode/config.yaml config render --dry-run
```

Check whether the `occtl` control socket was created:

```bash
docker compose exec kornode sh -lc 'ls -l /var/lib/kornode/generated/occtl.sock && occtl -s /var/lib/kornode/generated/occtl.sock show status'
```

Check the internal ocserv worker IPC socket:

```bash
docker compose exec kornode sh -lc 'find /var/lib/kornode/generated -maxdepth 1 -type s -name "ocserv.sock*" -print'
```

Check the certificates:

```bash
docker compose exec kornode ls -la /var/lib/kornode/certs
```

## Verified Runtime Smoke Test

For the current version, a Docker smoke test was performed with `/dev/net/tun`,
`NET_ADMIN` and `NET_RAW`:

- the final `kornode:latest` image builds;
- the container becomes healthy;
- `supervisorctl` shows `ocserv RUNNING`;
- `korctl server status` works inside the runtime image;
- the auto CA/server certificates are created;
- `occtl.sock` and `ocserv.sock.*` are created in the generated directory;
- `ocserv` listens on `443/tcp` and `443/udp`.

Deployment-specific checks remain:

- connecting a real OpenConnect client;
- the external upstream OpenConnect tunnels;
- agent enrollment and the interlink (`korctl interlink show`, `kornode-agent status`) in your network;
- egress rules, kill switch and domain sets for your domains/networks;
- end-to-end client access to the private network.

## Useful Commands

```bash
# Build and test
make docker-test
make docker-build

# Start
mkdir -p config data logs
cp config.example.yaml config/config.yaml
cp .env.example .env
docker compose up -d

# Status
docker compose ps
docker compose logs -f kornode
docker compose exec kornode korctl server status

# Optional local Web check
docker compose -f compose.yaml -f compose.web.yaml up --build -d
curl -kfsS https://127.0.0.1:8443/healthz

# Config
docker compose exec kornode korctl config validate
docker compose exec kornode korctl config render --dry-run
docker compose exec kornode korctl config diff

# Users
docker compose exec kornode korctl user create alice
docker compose exec kornode korctl user list
docker compose exec kornode korctl user passwd alice

# Certs and OTP
docker compose exec kornode korctl user cert create alice
docker compose exec kornode korctl user p12 create alice
docker compose exec kornode korctl user otp enable alice
docker compose exec kornode korctl user otp show-qr alice

# Network
docker compose exec kornode korctl net plan
docker compose exec kornode korctl interlink show
docker compose exec kornode korctl diagnose --dry-run

# Stop
docker compose down
```

## License

Korvus Node is licensed under the [GNU General Public License v3.0](LICENSE) or
later.

## Author

Ivan Cherniy - [r4ven.me](https://r4ven.me) - [github.com/r4ven-me/kornode](https://github.com/r4ven-me/kornode)
