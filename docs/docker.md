# Docker runtime notes

## Image contents

The runtime image includes:

- Debian trixie slim base image;
- Python runtime;
- backend package;
- CLI executable `korctl`;
- optional frontend static build;
- ocserv;
- openconnect client;
- occtl;
- ocpasswd;
- certtool;
- oath-toolkit/oathtool;
- qrencode;
- dnsmasq;
- nftables;
- iproute2;
- ca-certificates;
- curl or wget for healthchecks.

## ocserv and nftables compatibility

`ocserv`, `openconnect`, `nftables`, `iproute2` and helper utilities run inside the
container, but network operations are executed against the host kernel namespace when
`network_mode: host` is used. If `nft` (run by the reconciler, see
`/var/log/kornode/reconciler.log`) segfaults inside the container with signal 11 while the same rules work on the host,
the likely cause is a userspace/kernel netfilter compatibility issue. Verify the exact
command inside the container before debugging Korvus Node rendering. Korvus Node uses
Debian trixie for the runtime image so the bundled `nft` userspace is newer than the
old bookworm package set.

## Volumes

Suggested volumes:

```yaml
volumes:
  - ./config:/etc/kornode
  - ./data:/var/lib/kornode
  - ./logs:/var/log/kornode
```

## Compose service (hub)

`compose.yaml` is the reference; it grants the minimum runtime capabilities needed for
ocserv and nftables. Image: `ghcr.io/r4ven-me/kornode:v<version>` (or build locally).

```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
network_mode: host
devices:
  - /dev/net/tun:/dev/net/tun
  # - /dev/vhost-net:/dev/vhost-net  # optional; only if it exists on the host
env_file:
  - .env
environment:
  KORNODE_CONFIG: /etc/kornode/config.yaml
  KORNODE_PROC_SYS: /host/proc/sys
volumes:
  # Required: Docker mounts /proc/sys read-only and refuses `sysctls:` with host
  # networking. The reconciler sets ip_forward/src_valid_mark/rp_filter through the
  # host's net.* only (D-83); without this mount it cannot converge and ocserv waits.
  - /proc/sys/net:/host/proc/sys/net
  - ./config:/etc/kornode
  - ./data:/var/lib/kornode
  - ./logs:/var/log/kornode
restart: unless-stopped
```

The hub image has a `HEALTHCHECK` on bounded local supervisor/reconciler signals; an
external VPN outage alone does not make the container unhealthy.

## Agent image

Agents run a separate image, `ghcr.io/r4ven-me/kornode-agent` (`Dockerfile.agent`), with
`compose.agent.yaml`: host networking, `NET_ADMIN`/`NET_RAW`, `/dev/net/tun`, the same
`/proc/sys/net:/host/proc/sys/net` mount and `./agent-data:/var/lib/kornode-agent` for
keys, certificate and the cached bundle. There is no panel and no inbound port; the agent
dials the hub on 443/tcp. The agent image has no `HEALTHCHECK`: use
`kornode-agent status` / `kornode-agent doctor` inside the container, or the node's
online state on the hub. Images are tagged with the hub release (`v<version>`); the agent's
own protocol version is reported by `kornode-agent version` and checked against
`control.min_agent_version`.

## Entrypoint

The Python entrypoint:

1. load config;
2. validate config;
3. render generated configs;
4. initialize missing CA/server cert only if configured;
5. attempt startup Let's Encrypt issuance when enabled;
6. render supervisor config and start managed processes: the reconciler first (the only
   process that changes kernel networking state), then ocserv once the reconciler has
   converged the kernel (`korctl net wait-ready`);
7. start API/GUI only if enabled;
8. keep logs visible through Docker logs.

Avoid a large Bash entrypoint. Prefer Python orchestration or a real supervisor.

Startup Let's Encrypt failures are logged to `/var/log/kornode/startup.log` and
`/var/log/kornode/certbot/letsencrypt.log`; they should not make the container crash-loop.
