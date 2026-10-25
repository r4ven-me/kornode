# 09 — Testing

Three layers. Data-plane changes are accepted only with netlab evidence.

| Layer | Where | What |
| --- | --- | --- |
| Unit | every CI run | compiler golden tests, diff/plan, validators, registry, bundle sign/verify/seal, API contract tests, parity |
| Netlab | CI (`netlab` job, ubuntu-latest + sudo), local `make netlab` | real kernel, namespaces, nft, ocserv/openconnect |
| E2E | 4 VMs via self-hosted runner, `make e2e` | real hosts, Docker images, real Internet path, DPI-like conditions |

## Netlab

Framework in `tests/netlab/`:

- `Lab` fixture creates namespaces with a unique prefix per test, veth pairs,
  optional bridges; guaranteed teardown (also on SIGINT); `@pytest.mark.netlab`.
- Processes inside namespaces via `ip netns exec`; kornode components are run
  from the source tree (no Docker) so failures map to code lines.
- Helpers: `tcp_check(ns, host, port)`, `http_get(ns, url)`, `dns_query(ns,
  name, server)`, `capture(ns, iface, filter) -> packets`, `netem(ns, iface,
  loss=..., delay=...)`.
- On failure: per-namespace dump of `ip rule`, `ip route show table all`,
  `nft list ruleset`, `ss -tanp`, kornode logs, `explain` for the failing
  flow → attached to the pytest report and uploaded as CI artefact.

Topology:

```
            inet (203.0.113.0/24: http echo, dns, "public" addresses)
          /     |        \          \
       hub    node2     node3       ext (external ocserv)
        |       |        |  \
     (docker  lan2     cli3  awg3 (source iface, client 10.8.3.2)
      bridge)
```

Scenario list (must all exist by the end of P4; each maps to a task "Done when"):

| ID | Scenario | Expectation |
| --- | --- | --- |
| NL-01 | hub Prometheus stub → node3 agent `:9100` | real source address seen, no NAT |
| NL-02 | node3 agent → `monitoring.kornode.lan` on hub | resolves, TCP ok |
| NL-03 | cli3 → internet | exit per rules, MSS ≤ path MTU |
| NL-04 | cli3 → service in node2 LAN | via hub, no NAT |
| NL-05 (`test_routed_interlink.py`, done) | awg3 client → internet via `upstream:office` | via ext; ext down → ICMP unreachable, nothing on uplink |
| NL-06 | awg3 client → hub monitoring | via interlink, hub sees `10.8.3.2` |
| NL-07 | hub client → hub docker bridge with `via: upstream` rule | local delivery |
| NL-08 | openconnect bounce under traffic | zero marked packets on uplink |
| NL-09 (`test_p0_upstream.py`, done) | 5 % loss + 50 ms on carrier | 50 MB transfer completes |
| NL-10 | delete policy route manually | restored ≤ 2 s |
| NL-11 | bundle cutting the interlink | rollback ≤ 70 s, reported |
| NL-12 | tampered bundle | rejected, version unchanged |
| NL-13 | hub down 10 min | agent clients keep internet; agent restart boots from cache |
| NL-14 | overlapping prefix in registry | rejected with conflict details |
| NL-15 | carrier exclusion with `host → any via interlink` | no loop, tunnel stays up |
| NL-16 | regression set from v1.1.5 incidents (P1-06) | green |
| NL-17 (`tests/netlab/test_p4_exit_set.py`, done) | two-host topology: source `wgusers` on hub, `via: node:2` by set, rest `local` | listed destinations leave via node2's uplink with node2's address, others via hub; node2 offline → listed destinations get ICMP unreachable, never hub uplink |
| NL-18 (same file, done) | same topology, full tunnel (`to: any via node:2`) + hub Prometheus scrapes node2 agent | all source traffic exits node2; scrape works by node2's real interlink address |

NL-08 is `test_tunnel_drop_and_reconnect_through_a_running_reconciler_leaks_nothing`:
openconnect is killed and redialled under traffic while `korctl net run` is
running, so the connect converges through the reconciler socket (D-30) and
races the daemon's netlink passes. Its companion
`test_reconciler_restart_with_the_tunnel_dying_meanwhile_leaks_nothing`
covers the reconciler being down while the tunnel dies and its first pass
after the restart. Both count packets to the internet target on the uplink
(expected 0).

### Regression baseline (P1-06)

The P0 scenarios (`tests/netlab/test_p0_upstream.py`) must fail on code
before P0 and pass after it. There is no `v1.1.5` tag; the pre-P0 baseline
is the `raven` tag. Procedure (root on a disposable machine):

```bash
git worktree add /tmp/kornode-baseline raven
cp -r tests/netlab /tmp/kornode-baseline/tests/
cd /tmp/kornode-baseline
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'   # own venv: korctl
sudo .venv/bin/python -m pytest tests/netlab -v                # inside netns must be baseline code
```

The harness itself (hub server, topology) has to stay version-agnostic, so
a red baseline points at the routing bugs and not at test setup.

Recorded result (2026-10-12, Debian 13 VM, ocserv 1.3.0, nft 1.1.3):

| Scenario | `raven` (pre-P0) | `main` (P0 + netlab fixes) |
| --- | --- | --- |
| carrier exclusion, full host tunnel | fail: host traffic leaves from node3's own address | pass |
| kill-switch after tunnel loss | fail: no `unreachable default` in the policy table | pass |
| suppress rule / local networks in `full` | fail: internet traffic leaks past the tunnel | pass |
| sysctls on the tunnel | fail: `src_valid_mark`/`ip_forward` not managed | pass |
| MSS clamp for host traffic | fail: no ruleset loaded at all | pass |
| framework, topology, artifacts (6) | pass | pass |

## E2E (VMs)

**P3-10 status (2026-10-17): harness implemented, not accepted or executed on
real VMs.** D-58 is a pending implementation choice, not permission to weaken
phase acceptance. Operational details: [disposable VM runbook](../runbooks/vm-e2e.md),
review: [P3-10-REVIEW](../redesign/P3-10-REVIEW.md).

Inventory is environment-only (repository/environment variables and secrets, never
committed): `E2E_HUB_HOST`, `E2E_AGENT_A_HOST`, `E2E_AGENT_B_HOST`, `E2E_EXT_HOST`,
`E2E_HUB_ADDRESS` (optional advertised name/address), `E2E_SSH_USER`, `E2E_SSH_PORT`;
secrets `E2E_SSH_KEY` and operator-verified `E2E_SSH_KNOWN_HOSTS`. Local execution
uses private file paths `E2E_SSH_KEY_FILE` / `E2E_KNOWN_HOSTS_FILE`. Four distinct
management IPv4 addresses and four distinct machine IDs are required.

### Target topology (full phase acceptance, not current coverage)

| VM | OS | Role in suite |
| --- | --- | --- |
| hub | Debian 13 | hub image, Prometheus container, self-hosted runner |
| agent-a | Debian 13, behind NAT | agent, role `access`, test client via openconnect in a container |
| agent-b | Ubuntu 24.04, public IP | agent, wg-easy (Amnezia) as source, node-exporter |
| ext | Debian 13 | plain ocserv as `upstream:office` |

The full topology requires agent-a behind NAT (or equivalent test-owned ingress
ACL except runner SSH). **The current harness does not change host ingress ACLs**:
both agents use Docker bridge NAT, so public agent-b topology, VM-level NAT
emulation, Prometheus, wg-easy and access-client roles remain unvalidated.

### Implemented harness boundary and safety contract

- `tests/e2e/` uses strict pinned SSH and actual CLI/mTLS over inter-VM TCP;
  faults and kornode kernel changes stay in Docker **container** network namespaces.
  This is not host networking. Docker itself manages its normal host bridge/NAT
  and published ports; the harness never globally flushes host nft/routes/sysctls.
- Default pytest, including root, skips every VM case. Execution requires both
  `--e2e-run` and exact `E2E_ALLOW_DESTRUCTIVE=I_ACKNOWLEDGE_DISPOSABLE_VMS`.
  `make e2e-plan` reads no inventory and makes no network/runtime changes.
- Every remote action verifies the owner-provisioned root-owned
  `/etc/kornode-e2e-vm.json` role/purpose/machine ID. Claims take an exclusive lease
  that never expires automatically; cleanup/recovery refuse foreign ownership.
  Runner machine ID must match hub. Docker is pinned to the local rootful socket
  and builds use the default builder, not inherited production contexts.
- No privileged/host-PID containers or Docker socket mounts. Case metadata,
  config and Compose mounts are read-only, state/recovery submounts are writable.
  Fault removal is armed independently of pytest/SSH and targets only the immutable
  original container ID. Restore wipes only the stopped owned case's hub data.
- Tokens/passphrases use stdin/private files, never OS argv. Remote stdout/stderr
  is withheld, `--showlocals` and parallel pytest workers are refused. Only sanitized
  bounded agent diagnostics, summary and short JUnit are eligible for upload;
  no raw configs/logs/backup/key archives. Normal and failed setup paths tear down;
  hard runner/VM loss still requires explicit owned-run recovery.

Workflow `.github/workflows/e2e.yml` uses `[self-hosted, kornode-e2e]` on hub:
manual `DISPOSABLE_VMS` dispatch from a protected branch (no PR trigger), plus
protected `kornode-e2e` Environment approval configured by the owner. The variable
`E2E_ENVIRONMENT_APPROVAL_CONFIGURED=true` only acknowledges that configuration,
it does not create or prove protection. No forks or `pull_request_target`;
checkout does not persist credentials. Concurrency is singleton, no cancellation
of active runs. Steps: private SSH files → local harness checks → remote preflight /
leases → build both images once → bounded `docker save`/SSH `load` → fresh Compose
case → sanitized diagnostics → teardown; `always()` recovery/upload/key removal.
No commit/push/workflow execution is authorized by implementing this file.

### Scenario targets (full coverage still required)

E2E scenarios must ultimately mirror NL-01..NL-13 on real hosts plus:

| ID | Scenario |
| --- | --- |
| E2E-01 | fresh enroll of agent-a and agent-b ≤ 30 s each |
| E2E-02 | registry change → agent applied ≤ 10 s |
| E2E-03 | 60 s blackhole of agent-b's uplink → auto recovery (P3 implementation: namespaced nft fault, never host iptables) |
| E2E-04 | revoke agent-b → interlink down, control API 403 |
| E2E-05 | hub backup → wipe → restore → agents reconnect without re-enroll |
| E2E-06 | upgrade hub and agents from previous pre-release with live traffic, ≤ 30 s interruption |
| E2E-07 | two-host run with only `hub` (wg-easy attached as a source) and `agent-a` (role `gateway`): a wg-easy client exits via agent-a by domain/subnet list, then in full mode; hub Prometheus scrapes agent-a |

### Current executable scope, not execution evidence

`test_control_plane.py` has 10 opt-in cases: E2E-01…06, NL-10 route repair,
NL-11 signed bad-bundle rollback/report, NL-12 real incoming signature tamper,
and **partial** NL-13 (≥600 s hub outage, cache boot, external tunnel/ICMP traffic).
E2E-04 checks actual mTLS HTTP 403 through a test-only TCP relay; CA/client cert
verification stays on, hostname checking is disabled only for that relay probe.
E2E-05 includes announced rotation keys, owned wipe/staged restore activation,
original certs and restored high-water recovery. E2E-06 observes continuous interlink
mTLS probes (not access-client forwarding); it requires paired **different immutable**
`E2E_PREVIOUS_HUB_IMAGE` / `E2E_PREVIOUS_AGENT_IMAGE` digest refs with compatible
CLI/schema. Missing baselines skip; identical images fail rather than pass as an upgrade.

`test_routed_interlink.py` runs NL-01…NL-04 and NL-06 on real VMs (case `routed`; all passed on 2026-10-20: D-65, D-66, D-67, D-68) and keeps explicit P4 skips: NL-07…09, full NL-13
client forwarding and E2E-06 client continuity. They are listed in offline plan
and run summary. There is no claimed wg-easy/domain/leak/throughput/host-network
coverage. None of the real VM cases has been run; local faked SSH/Docker safety
tests do not close any runtime assertion. First VM acceptance must record timings,
image identities/sizes, sanitized diagnostics, cleanup evidence and remaining skips.

## Unit test conventions

- Compiler golden files: `tests/golden/<example>.nft`, `.rules`, `.routes`;
  regenerate with `pytest --update-golden`, reviewed in PR diffs.
- Contract tests validate every API response model against the OpenAPI
  schema and bundle bodies against `schemas/bundle.v2.schema.json`.
- No test sleeps longer than needed: poll with timeouts.
