# Approved network acceptance — 2026-10-23

## Final status (supersedes historical snapshots below)

Final local validation: **1334 passed / 104 opt-in skipped**; backend Ruff/strict
mypy, render/parity clean; frontend **48 passed**, build passed, Playwright
**44 passed**. Real netlab: **83 unique passed** across bounded runs, not one
uninterrupted full-suite pass. NL-05 abrupt-loss fix passed twice.

A distinct baseline from `15b87a68940390eeaa7a37bb9256199265be21ff` was built
under new unique tags, verifying bundle/v2, interlink SNI and agent 2.1.0:

- Hub: `192.168.122.123:5000/kornode-baseline-hub@sha256:e67e0139c24b3f6eabc6bbc3440946add847bbb2e65c5287f134bfdbf684662e`
- Agent: `192.168.122.123:5000/kornode-baseline-agent@sha256:00929886bc7f4ae91c3c4df5b944c541721be02cd4607d7cd1bead7d2aa38c04`

Old registry tags, private runner env and GitHub variables were not overwritten.
Only unused Docker build cache was reclaimed to satisfy the unchanged disk gate.

Final run `3168f99d0b3d4658ce3519b0` was interrupted at the owner's request due
to duration. JUnit: **17 cases, 15 passed, 1 failure, 1 error, 0 skipped** — not
a green or complete suite. E2E-06 fails with `upgrade access-client forwarding
did not recover automatically`, on this compatible baseline. Thus the remaining
client failure cannot be dismissed as the older SNI flag-day exception.
Read saved upgrade diagnostics before another long run. Private JUnit on hub:
`artifacts/acceptance/post-d85-full-e2e.xml`.

Pytest has exited; explicit owned cleanup passed and the ledger is closed with
no claimed roles. No more long runs were started, no code committed/pushed, and
no workflow dispatched. Acceptance remains pending E2E-06 diagnosis and a clean
requested run. D-82 retains composite examples acceptance; synthetic netlab
forwarding does not prove example-specific TLS/P12/DNS/failover behavior.

Coordinator approved the existing owner-marked disposable VMs. Current sources
were rsynced to the hub after reviewing a dry run, excluding `.git`, virtualenvs,
node_modules, artifacts, data, logs, local config/environment and build caches.
No broad `--delete` was used. Fifteen obsolete rename-source files were removed
only after checking their bytes against the old tracked versions. Baseline images
and registry were not rebuilt, pushed or replaced. No branches or commits.

## Earlier broad validation (before the targeted NL-05 fix)

| Check | Result |
| --- | --- |
| Owned E2E/netlab/harness Ruff | Passed |
| E2E + harness strict mypy | Passed, 10 source files |
| Local harness + example unit tests | 87 passed |
| Safety-gated four-VM preflight | Passed, all four roles |
| Real netlab | All 83 collected node IDs passed across two bounded runs, 0 skipped |
| Real four-VM E2E, unique scenarios | 19 passed, 2 failed, 0 skipped; not accepted as green |

The full E2E invocation was interrupted at its finite deadline (2254.27 s).
It recorded 10 passes and the E2E-06 failure before reaching most routed cases.
The complete routed module then ran separately: 10 passed, 1 failed in 1734.75 s.
A focused NL-05 rerun reproduced the remaining failure in 347.42 s. This is NOT a
claim that one uninterrupted full E2E invocation passed.

The first netlab run was invalidated by the wrapper's restrictive umask: ocserv's
privilege-dropped workers could not access their IPC sockets. Raw evidence remains
private. With the normal subprocess umask restored, the full attempt reached 50
passing cases before its 550-second deadline; all 33 remaining collected node IDs
then passed in 111.19 s. The union of passing node IDs is exactly the 83-node
collection. NL-09 completed in 194.418 s. All four example forwarding cases passed.

The example assertions were corrected to match existing kernel contracts:
D-26 NATs VPN clients toward connected LANs; D-28 drops host packets in
postrouting, where nft cannot reject. Forwarded-client fast rejection and
upstream no-fallback assertions remain mandatory.

## Follow-up findings and current acceptance status

### NL-05: root cause proven and authorized fix validated

The original failure was a live openconnect process retrying a dead upstream,
not a missing kernel unreachable route or an AWG/admin-prohibited errno mismatch.
The abrupt-loss reproduction (`4dc72e47953cff95c9cc42b8`) showed:

- At 33.670, 58.115 and 82.711 seconds, the configured health target was
  unreachable, but `oc-office` remained UP and its PID remained alive.
- Table 12002 retained both the unicast default via `oc-office` and the
  unreachable default at metric 4096. Unicast still won.
- 57 TCP/9100 SYNs went into the dead upstream, no ICMP returned on `wg0`, and
  zero cleartext target packets appeared on the physical uplink.
- A diagnostic-only link-down removed that unicast default while the retrying
  PID was still alive. The next SYN produced ICMP type 3/code 1 and
  EHOSTUNREACH in 0.014103428 seconds. The test retained its natural failure.

The earlier graceful-stop diagnostic (`a30705ab6cfdd37e99156fac`) also showed
that terminating openconnect naturally exposes the guard: 15 source SYNs,
15 ICMP type 3/code 1 replies, 0 uplink packets. Thus the kernel reject and AWG
return path worked; the missing transition from a retrying transport to DOWN
was the failure. No EACCES or admin-prohibited code caused these failures.

After this evidence was presented, the coordinator authorized a targeted change
to `backend/kornode_agent/tunnels.py` only. It reuses the existing bounded health
probe for configured upstream `check_host`, at five-second intervals. Three
consecutive failures stop the retrying process and invoke the reconciler before
redialing, allowing the unreachable default to take effect. A successful probe
resets the failure count. Interlink behavior and upstreams without a configured
health target are unchanged; no config/schema/GUI fields were introduced.

The strengthened NL-05 kills only the verified owned ext container, disables
its automatic restart until harness recreation, keeps the original fast-ICMP
requirement, and additionally requires captured ICMP unreachable on the AWG
source. Diagnostic intervention cannot turn a failed natural outage into a pass.

| Fixed abrupt-loss run | Result | Final rejection | Captured ICMP 3/1 | Uplink leak |
| --- | --- | --- | --- | --- |
| `ecf75192d3e6558dd9050dc3` | passed, 343.25 s | EHOSTUNREACH, 0.014443192 s | 13 | 0 |
| `e73bccb2eebaa41549724d2f` | passed, 294.33 s | EHOSTUNREACH, 0.014901896 s | 12 | 0 |

Both runs stayed in the natural-outage stage (no diagnostic link-down), and
both passed forwarding recovery through ext after it restarted. Targeted local
harness/tunnel/apply/source/input/example checks: 129 passed; owned-path Ruff
and strict mypy: clean (11 checked source files). The earlier full-netlab and
broad E2E results below predate this targeted fix; no new full-suite pass is
claimed. NL-05 is now validated; compatible-baseline E2E-06 remains pending.

### E2E-06-clients: compatible post-D85 baseline still required

The recorded immutable `f0d68ed` baseline enrolled successfully, accepted the
access-client policy and established the client forwarding baseline. After the
hub and both agent images were replaced with current images, agents did not
reconnect within the 120-second deadline. The failure is
`upgrade did not reconnect agents`; it occurs before successful post-upgrade
client recovery/SLA validation. Private diagnostic archives show TLS failures
in both agents' interlink logs. The <=30-second client SLA is **not accepted**.

Coordinator clarification: the SNI flag day is intentional in PLAN D85.
Transparent upgrades are required only between compatible post-D85 releases;
`f0d68ed` is not such a baseline. Cached bundle/v1 readability is not a promise
of transparent TLS/network reconnection across that boundary. The failure above
is retained as historical evidence, not a supported-upgrade regression.

Read-only inspection of historical `15b87a6` confirms bundle/v2, interlink SNI
and agent 2.1.0. A coordinator may build that candidate under new unique tags and
supply paired immutable digests after compatibility checks. No such images were
built or selected by this worker. Do not overwrite old registry references or
use the current image as its own baseline; the post-D85 client SLA remains
pending a real compatible-baseline run.

## Coverage and evidence

- NL-07/08/09 are executable netlab coverage, not `BLOCKED` placeholder skips.
  This run exercised their real kernel/transport tests successfully.
- Example configs all converge and forward in netlab; synthetic resolved sets
  and IPIP are not full example-specific VM/TLS/P12/DNS/failover acceptance.
- Full example-specific E2E remains a coverage gap, not an infrastructure
  prerequisite silently waived by these results.
- `docs/redesign/PLAN.ru.md` remains outside this worker's allowed edit paths.
  Its coordinator should retain the above incomplete acceptance items.

Private evidence on the hub (do not publish raw logs/archives):

| Run | Private evidence path |
| --- | --- |
| Corrected full netlab attempt | `artifacts/acceptance/netlab-neysoctl/` |
| Remaining netlab cases | `artifacts/acceptance/netlab-remaining-97rg7a_e/` |
| Full E2E deadline attempt | `artifacts/acceptance/e2e-wx5yn1p_/` |
| Complete routed module | `artifacts/acceptance/e2e-routed-zvvtfn3_/` |
| Focused NL-05 reproduction | `artifacts/acceptance/e2e-nl05-53cekgte/` |
| Graceful-stop ICMP trace | `artifacts/acceptance/e2e-nl05-trace-0d_zkvgj/` |
| Proven abrupt-loss blackhole and counterfactual | `artifacts/acceptance/e2e-nl05-abrupt-tc6lvs7y/` |
| Fixed abrupt-loss acceptance | `artifacts/acceptance/e2e-nl05-healthfix-_iz08zd6/` |
| Fixed abrupt-loss repeat | `artifacts/acceptance/e2e-nl05-healthfix-repeat-1jbnc5p8/` |

E2E run IDs: `370ac8072ef6f8c3b21b8298`, `ca32d5fb90e70ccf79740f3c`,
`75dd7f8f1587bd81a8c59c0e`. Each ledger reports `closed: true`, with no case cleanup
failures. Explicit idempotent harness cleanup passed for all three IDs; a final
four-role preflight also passed, and the host has zero named netlab namespaces.
No global Docker/network deletion or manual lease removal was performed.

Follow-up runs `a30705ab6cfdd37e99156fac`, `4dc72e47953cff95c9cc42b8`,
`ecf75192d3e6558dd9050dc3` and `e73bccb2eebaa41549724d2f` also report closed
ledgers and no cleanup failures. Explicit harness cleanup succeeded for all four;
a final four-role preflight passed after the two fixed abrupt-loss runs.
