# 03 — Kernel data plane

Everything here is produced by the egress compiler (02) as a `DesiredState`
and applied only by the reconciler (04). Ownership rule: kornode creates and
removes only its own objects (tables `inet kornode`, `ip kornode_nat`, rule
priorities 90–199, route tables 12000–12999). It never flushes global state.

## sysctl

| Key | Value | Scope |
| --- | --- | --- |
| `net.ipv4.ip_forward` | 1 | global |
| `net.ipv4.conf.all.src_valid_mark` | 1 | global |
| `net.ipv4.conf.all.rp_filter` | 2 if currently 1 (strict), otherwise unchanged | global |
| `net.ipv4.conf.<tun>.rp_filter` | 2 | every tunnel/source interface, on creation |
| `net.ipv4.conf.<tun>.accept_local` | 0 | unchanged default, asserted |

Kernel uses max(all, iface) for `rp_filter`; therefore strict `all=1` must be
lowered to 2 (S-06). Values the host already has looser are left untouched.
Per-interface values are applied on netlink `RTM_NEWLINK` events, so
ocserv `vpnsN` devices and openconnect tuns are covered without hooks.
A dotted device name is a literal `/proc/sys` component, e.g.
`net.ipv4.conf.eth0.100.rp_filter` maps to
`net/ipv4/conf/eth0.100/rp_filter`, not `conf/eth0/100/rp_filter`.

## Policy routing

| Priority | Rule | Purpose |
| --- | --- | --- |
| 90 | `lookup main suppress_prefixlength 0` | Connected/specific routes (LAN, docker, interlink sessions on hub) beat policies; only the default route of main is suppressed. |
| 95 | `to <carrier addr>/32 lookup main` (one per active tunnel endpoint) | Tunnel carrier never enters its own tunnel. |
| 100+i | `fwmark <mark_i>/0xffffff00 lookup <12000+i>` | One per exit. |

Exit table contents:

- `default dev <exit iface>` (+ `via <gw>` only if the exit is a broadcast
  interface, e.g. `local` with an explicit uplink);
- `unreachable default metric 4096` — permanent; when the exit device
  disappears the kernel removes the first route and the second one rejects
  traffic. This is the routing-layer kill switch (D-11).
- Exits with `kill_switch: false` get `throw default metric 4096` instead
  (falls back to further rules / main).
- On the hub, the `interlink` exit has no default: its table is populated with
  `<prefix> dev vpnsN` copies maintained from ocserv `iroute` sessions — in
  practice rule 90 already resolves them via main; the table exists for
  marking symmetry and holds `unreachable default`.

## nftables layout

```
table inet kornode {
  set interlink_ifaces   { type ifname; }                     # tun to hub / vpns* of agents
  set <set>_v4 / _v6  { type ipv4_addr; flags interval, timeout; auto-merge; }
  map exit_ok         { type mark : ifname; }              # mark → expected oif

  chain prerouting   { type filter hook prerouting priority mangle; policy accept;
                       jump session_rpf                 # where ocserv sessions need RPF
                       ct mark & 0xff000000 == 0x0c000000 meta mark set ct mark goto validate_connection
                       jump egress_classify }
  chain output       { type route hook output priority mangle; policy accept;
                       ct mark & 0xff000000 == 0x0c000000 meta mark set ct mark goto validate_connection
                       jump egress_classify_host }
  chain validate_connection {
                       ct mark & 0xffffff00 == <mark_i> ct label == <parenthesized OR of identity bit indices> return  # per current exit
                       drop }
  chain egress_classify       { … compiled rules for clients/sources/interlink … }

  chain egress_classify_host  { … compiled rules for host … }
  chain input        { type filter hook input priority mangle; policy accept;
                       ct state new iifname @tunnel_ifaces ct mark set <mark of that iface's exit>
                         ct label set <identity of that iface's exit> }
  chain forward      { type filter hook forward priority filter; policy accept;
                       tcp flags syn / syn,rst tcp option maxseg size set rt mtu
                       meta mark & 0xffffff00 != 0 meta mark & 0xffffff00 . oifname != @exit_ok … reject
                       meta mark & 0xff000000 == 0x0c000000 meta mark & 0xffffff00 != { <every exit's mark> }
                         reject }   # stale marks on any interface, D-32/A02
  chain postrouting  { type filter hook postrouting priority filter; policy accept;
                       oifname "lo" accept
                       tcp flags syn / syn,rst tcp option maxseg size set rt mtu
                       <same check for host traffic, with drop: the kernel
                        refuses reject in postrouting> }
}
table ip kornode_nat {
  chain postrouting { type nat hook postrouting priority srcnat; policy accept;
                      meta mark & 0xffffff00 == <mark_i> oifname "<if_i>" masquerade   # per NAT exit
                      meta mark & 0xffffff00 == <local_mark> oifname != "lo" masquerade }   # 'local' exit
}
```

Notes:

- The classify chains set `meta mark`, `ct mark` and the concrete exit's
  128-bit `ct label` together on the first packet of a connection; later
  packets restore from `ct mark` and must pass `validate_connection` before
  routing. Kornode owns the conntrack label of its marked flows; the kernel
  must support `CONFIG_NF_CONNTRACK_LABELS` (unsupported kernels reject apply,
  with no routing mutation if the initial guard could not be installed).
  nftables `ct_label` literals are bit **indices** (0..127), not raw hex
  bitmaps. The renderer expands the digest into a parenthesized OR expression
  such as `(0 | 1 | 127)` for both assignment and comparison, and uses explicit
  `==` for exact 128-bit equality, not implicit flag membership. Commas are
  **not** valid in assignment grammar. Native `nft --check --debug=netlink`
  regressions verify full 16-byte immediate and equality operands (not just
  Python-rendered text); packet tests also exercise actual kernel loading.
  The kernel setter ORs bits (`nft_ct_set_eval`, `NFT_CT_LABELS`), so every
  classification goes directly to identity validation **after** assignment
  too. Foreign preexisting bits or a failed label write cannot pass the
  first packet and then fail only on later packets. Kornode does not clear
  other software's labels; coexistence on its marked flows fails closed.
  Routing decisions remain stable for the life of a connection even if sets
  change (no mid-connection path flips).
- Stale marks (D-32): a connection keeps the ct mark of the exit it started
  on. When a policy change removes that exit (profile switch, upstream
  disabled, rules reordered), the mark has no ip rule and no kill-switch any
  more and would fall through to main. Forward and postrouting therefore
  reject/drop any kornode mark that is not a current exit's on **every**
  interface. Early-hook label validation also rejects a removed identity
  whose truncated numeric mark collides with a new exit. Such connections
  break instead of leaking; new connections are classified by the new policy.
  Valid old positional marks (indices 1..99) are disjoint from the new slots;
  unlabeled legacy connections are dropped on upgrade, not reclassified.
  No conntrack flush or persisted allocator is needed; callers must reconnect.
- The input chain records inbound connections arriving through a tunnel so
  replies use the same tunnel (existing behaviour, kept).
- The `local` exit also gets a mark (no ip rule needed: unmatched marks fall
  through to main). NAT is decided by the mark alone, never by source
  address, so traffic arriving from the interlink (`from: interlink`, exit-via-node)
  is masqueraded on the gateway node exactly like local clients.
- Replies destined to this node's client pool or sources are never marked
  (implicit rule 1/2 in 02).
- The full ruleset is applied as one `nft -f` transaction starting with
  `add table` / `delete table` of kornode tables (existing pattern). Sets are
  declared in the same file; domain-resolved elements are re-added by the
  resolver after a schema change (tolerable: connections keep their ct mark).
- Element-only changes (route lists, resolved addresses) use
  `add element`/`delete element` transactions without touching chains.

## MSS and MTU

- MSS clamp to route MTU in `forward` and `postrouting` for all traffic
  leaving or entering tunnel/source interfaces.
- openconnect tun MTU: as negotiated; agents report it in status.
- Interlink over TCP adds ~60–100 bytes; documented recommended client MTU for
  sources is 1280.

## Hub specifics

- Forwarding between `vpns*` devices is allowed (agent ↔ agent via hub).
- ocserv `restrict-user-to-*` is not used (it shells out to iptables,
  D-44). `enroll` sessions are limited by a static rule set: from
  `interlink.enroll_pool` only `tcp` to the hub interlink address on `control.port`
  is accepted in `input`; `forward` drops the pool in both directions.
- Those rules match by source address, so they only hold if a session cannot
  forge one. `prerouting` therefore starts with a strict reverse-path check
  scoped to IPv4 on ocserv session devices in a regular `session_rpf` chain:
  `iifname "<server.device>*" meta nfproto ipv4 fib saddr . iif oif missing drop`
  (D-47). Transit replies may return from this regular chain to skip RPF, but
  never from base prerouting: mark restore/identity validation must still run.
  The exemption requires `ct direction reply`, not merely established state.
  The tunnels' `rp_filter=2` is untouched.
- ocserv `isolate-workers` stays on; routes for agent prefixes come from
  `iroute` (S-03).
