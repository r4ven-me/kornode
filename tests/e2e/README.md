# Network acceptance: executable scope and pending runtime evidence

Approved VM/kernel results, the resolved NL-05 root cause and the baseline requirement are in
[ACCEPTANCE-2026-10-23.md](ACCEPTANCE-2026-10-23.md). The redesign acceptance is not green.

All VM scenarios require coordinator approval, `--e2e-run`, the exact destructive
acknowledgement, pinned SSH, four owner-marked disposable VMs, and the hub runner.
Ordinary pytest (including root) must not deploy them. Never use `--showlocals`
or xdist. See `docs/runbooks/vm-e2e.md` for inventory, leases and owned cleanup.

## Checks

- **NL-05** (`test_routed_interlink.py`): existing real AmneziaWG source, NAT hooks
  disabled; the destination sees ext's exit IP. An agent-a uplink capture is
  ready before ext is abruptly killed (automatic restart disabled for the owned
  container) and counts cleartext destination TCP/9100 packets, excluding the
  encrypted carrier. Correlated source/tunnel TCP and ICMP type/code counters
  distinguish a retrying blackhole from the unreachable guard. The AWG client
  must receive EHOSTUNREACH or ENETUNREACH in <2 seconds, not a silent timeout. Repeated attempts must reach
  neither the destination listener nor the uplink. Capture completion and
  forwarding recovery after ext restarts are mandatory. Capture returns counts
  only, never packet payloads; it runs in the owned node namespace and expires
  after 180 seconds even if the runner disappears. If natural rejection fails,
  a separately labeled diagnostic link-down proves the counterfactual while the
  original test still fails; it can never satisfy acceptance. The authorized
  agent fix probes configured upstream `check_host` values at five-second
  intervals and stops/reconciles after three consecutive failures, rather than
  trusting a retrying openconnect PID and an UP TUN. Two abrupt-loss runs passed
  with real ICMP type 3/code 1, ~14–15 ms EHOSTUNREACH, zero leakage and recovery.
  Unconfigured upstream health targets and interlink dialing are unchanged.
- **E2E-06-clients** (`test_control_plane.py`, case `upgrade`): one access-client
  session starts on previous images and reconnects itself while hub and both
  agents are replaced. A continuous observer in the independent client container
  requires the VPN route and agent-a's exit IP, measures the client forwarding
  gap, and requires fresh success after all replacements. Both the existing mTLS
  gap and the client gap must be <=30 seconds. Wrong-exit success fails. Bounded
  600-second observers disappear on case cleanup. No operator relogin occurs
  during measurement; identities and differing immutable image checks remain.
- **NL-07/08/09** are not infrastructure blockers or placeholder VM skips.
  `NETLAB_COVERAGE` in `test_routed_interlink.py` references the accepted suppress
  rule, live openconnect bounce/reconciler restart leak captures, and 50 MB
  transfer with 5% loss + 50 ms. The examples forwarding test additionally checks
  NL-07's exact forwarded client -> connected Docker-like subnet (D-26 LAN NAT), with
  the middle-server example's matching upstream rule, before and after upstream
  loss. Offline plan/summary distinguish these references from blocked contracts.
- **Examples**: `tests/netlab/test_examples_kernel.py` still converges every
  example. `test_examples_forwarding.py` adds just four cases (one per file):
  selected and unselected host/client forwarding, expected exit addresses,
  resolved-set membership, upstream-down no local fallback (fast ICMP rejection
  for forwarded clients; D-28 postrouting drop for host traffic), and
  continued unlisted/local delivery. Original policy and real `HubNetInputs`
  are used; state directories are isolated. IPIP substitutes upstream transport,
  and resolved addresses are synthetic. These are NOT example-specific TLS,
  P12, camouflage, DNS-resolution, failover or full VM acceptance. In particular
  `config.full.yaml` still needs controlled P12/backup/external-interface peers
  for end-to-end acceptance; public example endpoints are not test infrastructure.

## Safe validation (no VM/network mutation)

```sh
python3 -m pytest tests/test_e2e_harness.py -q
python3 -m mypy --explicit-package-bases tests/e2e
python3 -m tests.e2e plan
python3 -m pytest tests/e2e --collect-only -q
```

## Only after coordinator approval

Run on the designated hub runner with its existing private inventory loaded
without echoing it. First run the read-only preflight, then focused acceptance:

```sh
python3 -m tests.e2e preflight
python3 -m pytest tests/e2e --e2e-run -k 'nl_05 or e2e_06' -q --tb=short
```

E2E-06 requires paired `E2E_PREVIOUS_HUB_IMAGE` / `E2E_PREVIOUS_AGENT_IMAGE` digest
references, accessible from all four VMs and different from the built images.
The recorded `f0d68ed` images are pre-D85 and are not a valid transparent-upgrade
baseline: D85 intentionally changes the listener SNI from `fabric.<domain>` to
`interlink.<domain>`. Reading a cached bundle/v1 does not imply transparent network
reconnection across that flag day. E2E-06 targets distinct, compatible post-D85
images only. A distinct baseline from historical `15b87a6` (bundle/v2,
interlink SNI and agent 2.1.0) was built and used; immutable digests and the
remaining client-recovery failure are in `ACCEPTANCE-2026-10-23.md`.
This is not a claim that E2E-06 passed.
Coordinator-approved baseline builds must use new unique tags/digests, without
replacing old registry references or using the current image on both sides.
NL-05 additionally needs the existing wg-easy image pull on both agent VMs and
UDP/51820, TCP/8443 and TCP/9100 between the designated peers; faults never change
host ingress rules. Do not broaden host firewall rules to make a test pass.

For kernel evidence, on an approved disposable root-capable Linux runner with
netlab dependencies installed:

```sh
sudo .venv/bin/python -m pytest tests/netlab/test_examples_kernel.py tests/netlab/test_examples_forwarding.py tests/netlab/test_p0_upstream.py -q --tb=short
```

Preserve sanitized summary/JUnit and cleanup evidence. A green local harness or
successful collection is not runtime acceptance. Do not mark the redesign plan
complete until these approved runs have passed; that document is outside this
change's ownership.
