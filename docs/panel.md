# Web panel guide

What each section of the panel does, which ones you need and in what order. Every
action here also exists in `korctl` and the REST API (see
[spec 08](spec/08-interfaces-parity.md)); the panel is one of three equal front ends.

## Three words first

- **Hub** — this server. It runs ocserv for VPN clients and hosts the panel.
- **Agent** — another server of yours joined to the hub over openconnect on 443/tcp. It can
  serve its own VPN clients and can be a gateway to the internet for the other nodes.
- **Interlink** — the internal network between the hub and the agents (`10.99.0.0/24` by
  default). Each node has an ID; its addresses derive from it: node 1 serves clients from
  `10.100.1.0/24`, its sources default to `10.8.1.0/24`, its interlink address is `10.99.0.1`.

A single server without agents is a valid setup: the Routing group then boils down to
Network.

## Sidebar

| Group | Section | What it is for |
| --- | --- | --- |
| — | Dashboard | Server state (start/stop/reload), software versions, configuration precedence, interface load. |
| Access | Users | VPN accounts: passwords, client certificates and `.p12`, revocation, one-time codes. |
| Access | Groups | ocserv groups: settings shared by a set of users, membership. |
| Access | Sessions | Clients connected right now; disconnect a session. |
| Routing | Network | Where client traffic goes: egress rules, destination sets and sources; kernel diagnostics. |
| Routing | Nodes | Hub and agents: topology, enrollment, agent management, interlink addressing and DNS. |
| System | Config | Server, certificates, authentication, identity, upstream profiles, DNS, Web/API, backups. |
| System | Diagnostics | Probe commands and the doctor's health checks. |
| System | Logs | Log files and rotation. |
| System | Terminal | Shell on the server; shown only when `web.terminal_enabled` is on. |

The line under the page title repeats the short description of the open section.

## A typical first setup

1. **Config** — server name and port, certificates (Let's Encrypt or the built-in CA),
   authentication.
2. **Users** — create an account, hand out the password or the `.p12`.
3. **Network → Egress rules** — check that clients have a rule. A fresh hub without an
   `egress` key behaves as `clients → any via local` (straight to the internet); once you save
   your own list, only your rules apply.
4. Connect a client, watch it in **Sessions**.

Nodes → Node list shows the hub even before a second server joins. Enrollment and agent management become useful when you add another server.

## Network

Network has two tasks, chosen at the top of the page. **Hub policy & sources** (opened by
default) edits where traffic goes; **Kernel diagnostics** inspects how the saved policy is
applied. Unsaved edits in one task survive switching to the other.

### Egress rules

An ordered list; the first matching rule wins. Traffic of clients and sources that matches
no rule is **dropped** — nothing leaves unrouted. Each rule has:

- **From** — `clients` (this node's VPN clients), `host` (the server itself), `interlink`
  (transit from other nodes) or a source name;
- **To** — `any`, inline CIDRs and domains, a named set, or the prefixes of one node;
- **Via** — `local` (this server's uplink), `upstream:<profile>` (an external VPN from
  Config → Upstream), `node:<n>` (agent node `n` with the gateway role), `interlink`, or `drop`;
- **Kill switch** — when the chosen exit is down, reject the traffic. On by default for
  everything except `local`; this is what keeps traffic meant for a tunnel from leaking
  through the uplink. Turned off on an upstream rule, the rule is skipped while that
  upstream is down and the next rules decide.

**Destination sets** above the rules are reusable lists of addresses, domains and URL
lists, referred to by name in **To**. Rules are reordered by drag or by the arrows. A rule
that can never match (an earlier rule covers it) is marked inline. **Test a saved rule**
shows which saved rule a packet would hit. `Check` validates without saving; the JSON tab
edits the same policy as text.

### Sources

A source is a network behind a third-party access server running on this host — wg-easy,
Amnezia, anything with its own interface. kornode owns routing and NAT for it: the access
server must not masquerade by itself (see [sources.md](sources.md)). Give it a name, the
interface and the CIDR; rules then refer to it by name in **From**. **Export to the interlink**
makes the network reachable from the other nodes.

Sources cannot be changed while rule edits are unsaved: saving a source stores the saved
policy, not the draft.

### Kernel diagnostics

Technical views, loaded only when this task is opened; they use the saved policy, not
unsaved edits. **Kernel sync status** is the reconciler, the background process that keeps
the kernel (routing rules, tables, nftables) in line with the saved policy; `drift` above
zero means the kernel differs from the plan. **Preview & apply network plan** lists the
compiled exits and the operations a run would perform; `Dry run` shows them without
touching the kernel, `Apply` forces a run. **Explain a packet** is the detailed form of
the rule test: matched rule, mark, table, route, NAT and a kernel check.

## Nodes

Nodes combines the hub topology and agent management in one section, with three subsections:

- **Node list** — counters (registered, online, enrolled, control API), **Add agent**, and
  the interlink topology: the hub and agents with their interlink addresses, state, roles,
  announced prefixes and configuration state. **Open node** on a card opens that node's
  workspace. Signing-key rotation is under **Control plane maintenance**: it is not a
  routine refresh.
- **Interlink addressing** — the interlink address plan: hub node ID, interlink CIDR, client and source
  pool templates, enrollment pool, domain and reserved CIDRs. This is the only structured
  editor for these settings; the duplicate Config → Interlink entry has been removed.
  Defaults fit most setups; change them only for network collisions. `{id}` is the node ID.
- **Interlink DNS** — the `kornode.lan` interlink zone. Generated records are read-only; extra A, AAAA
  and CNAME records can be hub-wide or scoped to one agent, which keeps answering its own
  node zone without the hub. This is distinct from Config → DNS (resolver/forwarding settings).

Hub prefixes are read-only: they follow the client pool and exported sources. Use
**Manage hub sources in Network** in Node list to open and focus the existing Network →
Sources editor for adding, editing, deleting or exporting hub sources; there is no second
source editor in Nodes.

### Agent management in Node list

1. **Add agent** — a name, optionally a node ID, roles: `access` (serves its own VPN
   clients) and/or `gateway` (other nodes may leave to the internet through it). The result is a
   one-time enrollment token; run the agent with it as described in the README.
2. **Open node** on the agent's card. The node workspace has tabs: **Settings & enrollment**,
   **Networks & sources**, **Egress policy** (the same rule editor as the hub's),
   **Upstreams**, **VPN access & users** (`access` role only) and **Activity & diagnostics**
   (reports, bundles, commands). Unsaved edits survive switching tabs; **← All nodes**
   returns to the list.

An agent keeps forwarding with its last signed bundle while the hub is unreachable.

### Deploying an agent

The agent is a separate image, `kornode-agent` (`Dockerfile.agent`), published as
`ghcr.io/r4ven-me/kornode-agent`.

1. **Prepare the hub once.**
   - Turn the control plane on: `control: {enabled: true}` in the hub config (Config →
     Advanced → Persistent YAML, or the file itself), then restart the hub container. The
     control API is a supervisor program rendered at start-up. Nodes → Node list shows
     Control API "Enabled".
   - Config → Server → **Common name** (`server.cn`) must be a name or address the new node
     can reach: the enroll token carries `server.cn:server.port` as the hub address.
   - That port, 443/tcp by default, must be open. The agent only dials out.
2. **Create the agent.** Nodes → Node list → Add agent → "Create agent and token". Copy the token right
   away: it is shown once and expires after 60 minutes (`control.enroll_token_ttl_minutes`).
   A new token for a pending agent: its Settings & enrollment tab → "Issue enrollment token".
3. **Start it on the new node.** It needs Docker with `/dev/net/tun`. Copy `compose.agent.yaml`
   there; the rest of the repository is not needed:

   ```bash
   export KORNODE_AGENT_IMAGE=ghcr.io/r4ven-me/kornode-agent:latest
   docker compose -f compose.agent.yaml pull
   docker compose -f compose.agent.yaml run --rm agent kornode-agent enroll <token>
   docker compose -f compose.agent.yaml up -d
   ```

   Without `KORNODE_AGENT_IMAGE`, run the same commands in a checkout of the repository; they
   build the image locally. Keep `./agent-data` next to the compose file: it holds the
   agent's keys, certificate and cached bundle.
4. **Check.** The agent's card in Nodes → Node list shows `active · online` and
   "Configuration in sync" (desired and reported versions equal). On the node,
   `docker compose -f compose.agent.yaml exec agent kornode-agent status` (or `doctor`)
   works even without the hub.

To send hub clients through the agent, give it the `gateway` role and add a rule with
`via node:<its node ID>` in Network → Hub policy & sources → Egress rules.

## Control-only hub

Config → VPN server → **Accept VPN clients** off turns the hub into a control centre (D-100): ocserv keeps serving
agents and enrollment, every VPN client login is refused, and Users, Groups and Sessions are hidden (the dashboard
shows "VPN clients: Control-only"). Create VPN users on an agent with the `access` role (Nodes → the node → VPN access
& users). Saving restarts ocserv, which drops active sessions.

## Dry-run

The **Dry-run** switch in the top bar makes server commands, certificate actions, agent
creation, signing-key rotation and backup restore return a preview instead of changing
anything. Network → Kernel diagnostics has its own `Dry run` button next to `Apply`.
