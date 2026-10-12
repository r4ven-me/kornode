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
| NL-02 | node3 agent → `monitoring.kornode.internal` on hub | resolves, TCP ok |
| NL-03 | cli3 → internet | exit per rules, MSS ≤ path MTU |
| NL-04 | cli3 → service in node2 LAN | via hub, no NAT |
| NL-05 | awg3 client → internet via `upstream:office` | via ext; ext down → ICMP unreachable, nothing on uplink |
| NL-06 | awg3 client → hub monitoring | via fabric, hub sees `10.8.3.2` |
| NL-07 | hub client → hub docker bridge with `via: upstream` rule | local delivery |
| NL-08 | openconnect bounce under traffic | zero marked packets on uplink |
| NL-09 | 5 % loss + 50 ms on carrier | 50 MB transfer completes |
| NL-10 | delete policy route manually | restored ≤ 2 s |
| NL-11 | bundle cutting the fabric | rollback ≤ 70 s, reported |
| NL-12 | tampered bundle | rejected, version unchanged |
| NL-13 | hub down 10 min | agent clients keep internet; agent restart boots from cache |
| NL-14 | overlapping prefix in registry | rejected with conflict details |
| NL-15 | carrier exclusion with `host → any via fabric` | no loop, tunnel stays up |
| NL-16 | regression set from v1.1.5 incidents (P1-06) | green |
| NL-17 | two-host topology: source `wgusers` on hub, `via: exit:2` by set, rest `local` | listed destinations leave via node2's uplink with node2's address, others via hub; node2 offline → listed destinations get ICMP unreachable, never hub uplink |
| NL-18 | same topology, full tunnel (`to: any via exit:2`) + hub Prometheus scrapes node2 agent | all source traffic exits node2; scrape works by node2's real fabric address |

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

Inventory (repository variables/secrets, never committed): `E2E_HUB_HOST`,
`E2E_AGENT_A_HOST`, `E2E_AGENT_B_HOST`, `E2E_EXT_HOST`, SSH key
`E2E_SSH_KEY`, public domain for the hub if available.

| VM | OS | Role in suite |
| --- | --- | --- |
| hub | Debian 13 | hub image, Prometheus container, self-hosted runner |
| agent-a | Debian 13, behind NAT | agent, role `access`, test client via openconnect in a container |
| agent-b | Ubuntu 24.04, public IP | agent, wg-easy (Amnezia) as source, node-exporter |
| ext | Debian 13 | plain ocserv as `upstream:office` |

If agent-a is not actually behind NAT, the suite emulates it: inbound
connections to agent-a are dropped with a test-owned nft table except SSH from
the runner.

Workflow `.github/workflows/e2e.yml`: runs on `[self-hosted, kornode-e2e]` (the runner on hub), on manual
dispatch and on PRs labelled `e2e`. Steps: build both images → push to a
local registry on hub (or `docker save | ssh docker load`) → deploy with
compose over SSH → run `tests/e2e/` (pytest driving SSH + `korctl`/
`kornode-agent --json`) → collect `collect_diag` from all agents as artefacts
→ tear down to a clean baseline (keeps VMs reusable).

E2E scenarios mirror NL-01..NL-13 on real hosts plus:

| ID | Scenario |
| --- | --- |
| E2E-01 | fresh enroll of agent-a and agent-b ≤ 30 s each |
| E2E-02 | registry change → agent applied ≤ 10 s |
| E2E-03 | 60 s blackhole of agent-b's uplink (iptables on agent-b) → auto recovery |
| E2E-04 | revoke agent-b → fabric down, control API 403 |
| E2E-05 | hub backup → wipe → restore → agents reconnect without re-enroll |
| E2E-06 | upgrade hub and agents from previous pre-release with live traffic, ≤ 30 s interruption |
| E2E-07 | two-host run with only `hub` (wg-easy attached as a source) and `agent-a` (role `exit`): a wg-easy client exits via agent-a by domain/subnet list, then in full mode; hub Prometheus scrapes agent-a |

## Unit test conventions

- Compiler golden files: `tests/golden/<example>.nft`, `.rules`, `.routes`;
  regenerate with `pytest --update-golden`, reviewed in PR diffs.
- Contract tests validate every API response model against the OpenAPI
  schema and bundle bodies against `schemas/bundle.v1.schema.json`.
- No test sleeps longer than needed: poll with timeouts.
