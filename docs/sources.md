# Sources: wg-easy, Amnezia and other access servers

A **source** is the network of a third-party access server (wg-easy, an Amnezia
container, a plain WireGuard interface) attached to an agent. kornode never starts or
configures that server: it only owns routing, forwarding and NAT for the source's
subnet, and exports the subnet into the fabric (spec 02, 07). WireGuard exists in
kornode **only** as such a server; nodes talk to each other over ocserv (443/tcp).

## What you configure

1. Run the server in `network_mode: host`, so that its interface (`wg0`, `awg0`)
   lives in the node's network namespace. It needs the `wireguard` (or `amneziawg`)
   kernel module on the host, `NET_ADMIN`, and `net.ipv4.ip_forward=1`.
2. Give the server a client range **inside the node's source pool**
   `10.8.<node id>.0/24` (spec 01). Use another range only with
   `allow_outside_pool: true`; it still may not overlap a prefix of another node.
3. **Turn the server's own NAT off.** kornode owns NAT for the source subnet; a second
   masquerade makes traffic leave with the wrong address or twice. In wg-easy/Amnezia
   this means empty `PostUp`/`PostDown` hooks:
   - wg-easy v14 and the Amnezia fork: environment variables `WG_POST_UP` and
     `WG_POST_DOWN` set to empty, `WG_DEFAULT_ADDRESS` inside the source pool,
     `WG_MTU` (see below);
   - wg-easy v15 moved these settings into its UI/database: clear the hooks there.
   The names above are taken from the upstream documentation; verify them against the
   version you deploy.
4. Client settings: allowed IPs `0.0.0.0/0` (the egress policy decides, not the
   client), MTU **1280** when the node's exit is the fabric over TCP (ocserv adds its
   own overhead; kornode clamps TCP MSS, UDP is not clamped), DNS = the node's service
   address `10.100.<node id>.1` so that clients ask the same resolver that fills the
   domain sets.
5. Declare the source on the hub:

```bash
korctl agent source add branch amnezia --file amnezia.json
# amnezia.json: {"interface": "awg0", "cidr": "10.8.3.0/24", "export": true}
korctl agent egress show branch      # then write the rules that use `from: [amnezia]`
```

The same is available as `PUT /api/agents/{name}/sources/{source}` and in the panel
(agent → Networks and sources).

## What kornode does with it

| Aspect | Behaviour |
| --- | --- |
| Classification | Packets entering on `awg0` **and** with a source address in the cidr are class `amnezia` (egress rules `from: [amnezia]`). A packet from `awg0` with an address outside the cidr is not of that class and follows plain routing: kornode adds no spoof filter for source interfaces, WireGuard's AllowedIPs (cryptokey routing) is what keeps a peer inside its range. |
| Default | Unrouted source traffic is rejected, never sent through the uplink. The implicit `to-fabric` rule lets sources reach the fabric (other nodes, the hub) without NAT. |
| Export | With `export: true` (default) the cidr is exported: the hub installs `iroute`/a route to it via the agent's session and every other agent routes it into the fabric (no NAT inside the fabric). The hub's monitoring sees real client addresses. `export: false` keeps it local. |
| Interface absent | Rules stay installed and match nothing; `kornode-agent doctor` warns (`missing_source`), the report shows the source as down. |
| Overlaps | The hub refuses a source overlapping another node's prefix or the node's own client pool, or colliding with `oc-hub0`/an upstream interface. |

## Foreign NAT is an error

`doctor` looks for NAT that is not kornode's:

- nftables (any table other than `inet kornode`/`ip kornode_nat`) with `masquerade`/`snat`
  that matches the source's cidr (`ip saddr`) or interface (`iifname`/`oifname`) is the
  error `foreign_nat_on_source`;
- the same for the **legacy iptables** backend (`iptables-legacy-save -t nat`, which
  `nft list ruleset` cannot show);
- interface wildcards (`wg*` in nft, `wg+` in iptables) and user chains reached from
  POSTROUTING are followed; a catch-all iptables NAT is a warning;
- other foreign NAT (for example Docker's own masquerade) is reported as a warning
  `foreign_nat`: it is not proven to touch an owned subnet.

The legacy backend is read only when its `nat` table already exists in the namespace
(`/proc/net/ip_tables_names`): asking `iptables-legacy-save -t nat` otherwise creates an empty
legacy table, which can pre-empt nftables NAT. IPv6 NAT is not inspected.

Fix an error by emptying the server's PostUp/PostDown hooks (step 3), then restart it.

## Not covered yet

Sources attached to the **hub** are not part of P4-05: the hub has no egress policy yet
(it still uses the legacy routing settings), so there is nothing a hub source could use.
They arrive with exit-via-node (P4-06, D-68). Checking the source's DNS setting is
documentation only: kornode cannot read it from a third-party server.
