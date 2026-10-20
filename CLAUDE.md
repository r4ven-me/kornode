# CLAUDE.md — kornode redesign

You are implementing the kornode redesign: hub + agents architecture, a routed
ocserv fabric over 443/tcp, a declarative egress model and one reconciler.
This file is your operating manual. Read it fully before any change.

## Sources of truth (read in this order)

1. `docs/redesign/PLAN.ru.md` — the approved plan (Russian). Why and what.
2. `docs/redesign/ROADMAP.md` — phases, tasks with IDs, definition of done.
3. `docs/spec/*.md` — contracts. How, precisely.
4. `docs/spec/schemas/*.json` — machine-readable contracts (bundle, egress).
5. `docs/redesign/DECISIONS.md` — decisions already taken and spikes to run.
6. `AGENTS.md` (in the kornode repo) — existing project rules. They still apply
   unless a spec here explicitly supersedes them.

If the plan and a spec disagree, the spec wins. If a spec is silent, follow
`DECISIONS.md` defaults; if still undecided, take the most conservative option
(fails closed, no traffic leak, no data loss), record it as a new entry in
`DECISIONS.md` and continue. Do not stop to ask the owner about details the
docs leave to engineering judgment; ask only when a decision is irreversible
for user data or contradicts a stated requirement.

## Hard requirements (non-negotiable)

- **Inter-node transport is ocserv/openconnect on 443/tcp.** No WireGuard,
  IPsec or other transport between nodes. DTLS is allowed opportunistically
  (`transport: auto`) but TCP alone must work.
- **WireGuard exists only as a third-party access server** (wg-easy, Amnezia)
  attached to an agent as a named `source`. kornode owns routing and NAT for its
  subnet; wg-easy hooks must not reference kornode interfaces.
- **Data plane never depends on control plane.** An agent with a cached bundle
  keeps forwarding when the hub is down, and boots from cache.
- **No NAT inside the fabric.** Masquerade only toward the internet and toward
  external upstreams.
- **Fail closed.** Traffic assigned to a tunnel never leaks via the uplink,
  including during tunnel reconnects and reconciler restarts.
- **CLI ⇄ API ⇄ Web parity on the hub.** Every hub capability exists in
  `korctl`, in the REST API and in the panel, all calling the same service.
  Enforced by `parity.yaml` + `tests/test_parity.py` (see
  `docs/spec/08-interfaces-parity.md`). The control plane runs even with
  `web.enabled: false`.
- **Only `kornode.net` touches the kernel** (sysctl, ip rule/route, nftables).
  Everything else changes inputs and wakes the reconciler.
- Existing rules from `AGENTS.md`: no secrets in logs, explicit argv (no
  `shell=True`), atomic writes, dry-run for network changes, typed Python
  (`mypy --strict`), ruff, pytest.

## Workflow

- One phase = one or more PRs from branch `redesign/p<N>-<slug>`, never a
  single giant PR. Each PR maps to task IDs from `ROADMAP.md` (e.g. `P2-03`)
  listed in its description.
- Order inside a task: spec check → tests first (unit + netlab where the task
  touches the data plane) → implementation → docs update → `make check` →
  netlab suite → PR.
- A phase is done only when every "Done when" item in `ROADMAP.md` is
  demonstrated by an automated test, not by manual observation.
- Keep `CHANGELOG.md` updated per PR under an `Unreleased` heading.
- Update `docs/` in the same PR as behaviour changes. Specs are living
  documents: when implementation reveals a better contract, update the spec in
  the same PR and explain why in the PR description.
- Never weaken an existing test to make a change pass. If a test encodes old
  behaviour that the plan removes, delete it in the PR that removes the
  behaviour and say so.

## Commands

```bash
make check                      # ruff + mypy --strict + pytest (unit)
make netlab                     # namespace data-plane suite, needs root (added in P1)
make parity                     # CLI/API/Web parity check (added in P2)
npm --prefix frontend test && npm --prefix frontend run build
make e2e                        # 4-VM suite via self-hosted runner (added in P3)
```

## Test environment

- Netlab (network namespaces) runs in CI on GitHub-hosted runners with `sudo`.
- E2E runs on 4 VMs provided by the owner (`hub`, `agent-a`, `agent-b`, `ext`)
  through a self-hosted GitHub runner on `hub`. Inventory lives in repository
  secrets/variables, never in the repo. See `docs/spec/09-testing.md`.
- Your own shell may not reach the VMs directly; drive them through CI.

## Style of reporting back

At the end of each PR: what changed, which task IDs are done, test evidence
(suite names and counts), anything recorded in `DECISIONS.md`.
