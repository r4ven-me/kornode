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

## Policy routing

| Priority | Rule | Purpose |
| --- | --- | --- |
| 90 | `lookup main suppress_prefixlength 0` | Connected/specific routes (LAN, docker, fabric sessions on hub) beat policies; only the default route of main is suppressed. |
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
- On the hub, the `fabric` exit has no default: its table is populated with
  `<prefix> dev vpnsN` copies maintained from ocserv `iroute` sessions — in
  practice rule 90 already resolves them via main; the table exists for
  marking symmetry and holds `unreachable default`.

## nftables layout

```
table inet kornode {
  set fabric_ifaces   { type ifname; }                     # tun to hub / vpns* of agents
  set <set>_v4 / _v6  { type ipv4_addr; flags interval, timeout; auto-merge; }
  map exit_ok         { type mark : ifname; }              # mark → expected oif

  chain prerouting   { type filter hook prerouting priority mangle; policy accept;
                       ct direction reply ct mark != 0 meta mark set ct mark   # restore for replies
                       jump egress_classify }
  chain output       { type route hook output priority mangle; policy accept;
                       ct direction reply ct mark != 0 meta mark set ct mark
                       ct direction original jump egress_classify_host }
  chain egress_classify       { … compiled rules for clients/sources/fabric … }
  chain egress_classify_host  { … compiled rules for host … }
  chain input        { type filter hook input priority mangle; policy accept;
                       ct state new iifname @tunnel_ifaces ct mark set <mark of that iface's exit> }
  chain forward      { type filter hook forward priority filter; policy accept;
                       tcp flags syn / syn,rst tcp option maxseg size set rt mtu
                       meta mark & 0xffffff00 != 0 meta mark & 0xffffff00 . oifname != @exit_ok … reject
                       meta mark & 0xff000000 == 0x0c000000 meta mark & 0xffffff00 != { <every exit's mark> }
                         oifname "<uplink>" reject }   # stale marks, D-32
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

- The classify chains set `meta mark` and `ct mark` together on the first
  packet of a connection (`ct mark set meta mark`), and later packets restore
  from `ct mark`. Routing decisions are thus stable for the life of a
  connection even if sets change (no mid-connection path flips).
- Stale marks (D-32): a connection keeps the ct mark of the exit it started
  on. When a policy change removes that exit (profile switch, upstream
  disabled, rules reordered), the mark has no ip rule and no kill-switch any
  more and would fall through to main. Forward and postrouting therefore
  reject/drop any kornode mark that is not a current exit's toward the uplink
  (on every interface when the uplink is unknown). Such connections break
  instead of leaking; new connections are classified by the new policy.
- The input chain records inbound connections arriving through a tunnel so
  replies use the same tunnel (existing behaviour, kept).
- The `local` exit also gets a mark (no ip rule needed: unmatched marks fall
  through to main). NAT is decided by the mark alone, never by source
  address, so traffic arriving from the fabric (`from: fabric`, exit-via-node)
  is masqueraded on the exit node exactly like local clients.
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
- Fabric over TCP adds ~60–100 bytes; documented recommended client MTU for
  sources is 1280.

## Hub specifics

- Forwarding between `vpns*` devices is allowed (agent ↔ agent via hub).
- `restrict-user-to-routes` is **off** for `agents` (they carry transit), on
  for `enroll`.
- ocserv `isolate-workers` stays on; routes for agent prefixes come from
  `iroute` (S-03).
