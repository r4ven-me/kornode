# 04 — `kornode.net` core and reconciler

## Package layout

```
backend/kornode/net/
  __init__.py
  model.py        # EgressPolicy, Source, DestSet, Rule (pydantic, shared with bundle schema)
  addressing.py   # derive addresses from node id + interlink config; overlap validator
  state.py        # DesiredState: Sysctl, IpRule, Route, RouteTable, NftRuleset, NftElements (frozen dataclasses)
  compile.py      # (EgressPolicy, NodeFacts) -> DesiredState ; dead-rule analysis
  nftgen.py       # DesiredState.nft -> nft script text (Jinja-free, deterministic ordering)
  kernel.py       # read ActualState; apply Plan (pyroute2 + one nft transaction)
  diff.py         # diff(actual, desired) -> Plan (ordered ops, idempotent)
  reconciler.py   # loop, triggers, debounce, single-flight
  explain.py      # explain(src, dst, proto, port) -> Decision
  probes.py       # health probes used by apply-with-confirm (ICMP/TCP via a given mark)
  errors.py
```

Import rule: `kornode.net` imports only stdlib, `pydantic`, `pyroute2`, and
its own modules. A test (`tests/test_net_imports.py`) walks the AST and fails
on any other import.

## Inputs

```python
@dataclass(frozen=True)
class NodeFacts:
    node_id: int
    addresses: DerivedAddresses           # from addressing.py
    tunnels: Mapping[str, TunnelFact]     # exit name -> iface, up/down, carrier addrs, mtu
    sources: Mapping[str, SourceFact]     # name -> iface present?
    local_networks: tuple[IPv4Network, ...]
    resolved: Mapping[str, frozenset[IPv4Address | IPv6Address]]  # set name -> addresses

@dataclass(frozen=True)
class NetInputs:
    policy: EgressPolicy
    facts: NodeFacts
```

The hub builds `NetInputs` from YAML + registry + runtime; the agent from the
bundle + runtime. Nothing else is needed by the core.

## Determinism

`compile()` is a pure function. Given equal inputs it returns byte-identical
nft text and identical rule/route lists (sorted by priority, then key). Golden
tests snapshot the output for every example in `docs/spec/examples/`.

## Diff and apply

- `Plan` = ordered list of ops: `SetSysctl`, `AddRule`, `DelRule`,
  `ReplaceRoute`, `DelRoute`, `NftLoad(script)`, `NftElements(add, delete)`.
- When compiled routing rules/routes need changing, first install a temporary
  `NftLoad(guard=True)` ruleset: it classifies using the desired identities but
  drops all kornode-marked traffic in forward/postrouting. Its destination,
  source and local/carrier sets are filled in the **same transaction**:
  temporarily empty split sets would let host traffic fall through unmarked
  to main. This closes the interval during which a bounded table slot is
  reassigned to another identity.
  Failure to install this barrier aborts before any routing mutation.
- Then: sysctl → routes into exit tables (unreachable first) → rules (add new
  before deleting old) → delete stale routes/tables → final nft. Stale route
  deletion is a routing mutation too: never lift the barrier while an old
  default or prefix can still send a pinned flow down a reassigned slot.
  The final nft transaction lifts the barrier and refills its sets. A route/rule/sysctl error
  keeps an installed barrier instead of exposing partially updated routing;
  the next reconciler pass retries. Brief interruption of marked flows during
  routing mutations is intentional; element-only changes do not install it.
- Rules/routes owned by kornode are identified by priority range / table id
  range (03). Anything else is never touched.
- nft: full `NftLoad` when the chain/set schema hash changed or a routing
  barrier needs lifting; otherwise `NftElements` only. The observed schema is
  valid only while **both** `inet kornode` and `ip kornode_nat` exist. Losing
  either table forces a full reload, even if the filter table's hash still
  matches; element-only reconciliation cannot repair a missing NAT table.
- Apply is idempotent; applying the same plan twice is a no-op on the second
  run (asserted in tests).
- Except for initial routing-barrier failure, a failed op does not abort the
  pass (D-33): the remaining additive sysctl/route/rule operations still run,
  deletions are skipped and all failures are raised together at the end.
  If a barrier is installed, the final unguarded nft transaction is also
  skipped on failure (A02). One bad sysctl or a tunnel vanishing mid-pass must not
  leave the node without its fail-closed rules.

## Reconciler loop

```
triggers:  inputs_changed (in-process event / file watch / control-plane push)
           netlink: RTM_NEWLINK/DELLINK, RTM_NEWROUTE/DELROUTE (tables 12000-12999 and main default; main routes with `proto 77` are kornode-owned, D-63),
                    RTM_NEWRULE/DELRULE, address changes on tunnel/source ifaces
           timer: every 10 s (full read + diff)
debounce:  200 ms; single-flight (one apply at a time; a trigger during apply schedules one more pass)
on error:  any exception is an errored pass (never a dead loop); exponential backoff 1 s → 30 s, emit event.
           Netlink events (including those a half-applied pass causes itself) are held until the
           backoff expires; explicit wakes (`wake`, inputs changed) and the synchronous `apply` retry at once.
```

Metrics/state exposed (`reconciler.status()`): last apply time, last plan size,
last error, drift events count by type, current schema hash.

Hub: supervisor program `reconciler` (`korctl net run`). Other hub processes
signal it through a Unix socket (`generated_dir/reconciler.sock`, one JSON
line in, one out): `{"op": "wake"}` (asynchronous nudge: hooks, domain
resolver), `{"op": "apply"}` (runs one pass inside the request and replies with
the status — callers that must not proceed before the kernel converged, e.g.
the kill-switch before dialing a tunnel; `korctl net apply`, the API and
`UpstreamService` use it) and `{"op": "status"}`. A failed pass is an error for
`apply` callers (`NetService.converge` raises), never a silent success. The daemon holds an exclusive
`flock` on `generated_dir/reconciler.lock` for its whole life (D-60); a second daemon
exits. With no reconciler running, `apply` takes the same lock and runs one in-process
pass; if the lock is busy the daemon is starting, so `apply` waits for its socket
(up to 30 s, then fails) and never becomes a second kernel writer. Agent: the
reconciler runs inside the agent process.

Hub inputs that are files, all re-read on every pass: the runtime-switched
active profile (`generated_dir/active-upstream`, overrides
`upstream.active_profile`; a disabled profile is never active), per-profile
carrier addresses (`upstream-carrier/<profile>.addrs`),
and resolved domain addresses (`resolved/<set>.txt`).

## Explain

`explain(src, dst, proto=None, port=None) -> Decision`:

```json
{
  "from_class": "clients",
  "matched_rule": {"index": 1, "id": null, "to": {"set": "corp"}, "via": "upstream:office"},
  "implicit": null,
  "mark": "0x0cc63d00",
  "table": 12002,
  "route": "default dev oc-office0",
  "nat": "masquerade to 10.11.11.7",
  "kernel_check": "ip route get 10.60.1.5 from 10.100.3.15 iif vpns0 mark 0x0cc63d00 -> dev oc-office0",
  "warnings": []
}
```

`kernel_check` runs `ip route get` equivalent through pyroute2 with the mark;
a mismatch with the compiled expectation is reported as a warning (drift).

## Doctor

`doctor()` returns a list of findings `{severity, code, message, hint}`:
sysctl mismatch, overlapping networks, missing source interface, foreign NAT
on owned subnets, nft userspace/kernel mismatch, exit tables missing
`unreachable`, carrier exclusion missing, MTU < 1280 on a tunnel, clock skew
(agent vs hub > 60 s, from reports).
