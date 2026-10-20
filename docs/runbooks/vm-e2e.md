# Disposable four-VM E2E (P3-10)

**Real VM acceptance demonstrated 2026-10-19: 9 passed, 13 skipped (E2E-06 needs previous image digests; the rest are P4 blockers) on four disposable Debian 13 VMs, run from hub over SSH (no GitHub Actions).**
Never run this suite on dev/production. Practical notes from that run: VM root disks need
≥10 GB and RAM ≥2 GB with swap for `apt`; set `TMPDIR` to a disk path on hub (a 1 GB
tmpfs `/tmp` cannot hold the image archive); install `docker.io docker-cli docker-compose
docker-buildx`; the first image build after a source change needs working PyPI access.

## What this stage covers

`tests/e2e/` drives SSH + Docker Compose on four **owner-designated disposable**
VMs (`hub`, `agent-a`, `agent-b`, `ext`). The runner is on hub. Each scenario gets
fresh bind-mounted state and its own Compose project/container network namespaces.
Images are built once on hub, `docker save`d and streamed over pinned SSH to
`docker load` on each VM. No external registry push or Git push is performed.

This is deliberately **not `network_mode: host`**: kornode/netlink/nft faults run
inside the disposable containers. Docker creates/removes its normal bridge/NAT and
published ports on the VMs; the harness does not snapshot/flush host nftables,
host routes or host sysctls. It does not validate production host-network startup
races or P4 routed fabric. Transport still traverses four real VM kernels/networks.
Both agent containers are genuinely behind Docker NAT; agent-b's intended public
VM topology and agent-a's VM-level NAT ACL emulation remain deployment extensions,
not claims made by this isolated P3 implementation. See implementation choice D-58.

| Scenario | Implemented assertion |
| --- | --- |
| E2E-01 | fresh registry create → enroll → real fabric mTLS ping ≤30 s, both agents; then confirmed bundle |
| E2E-02 | registry transport mutation → confirmed applied version ≤10 s, no shortened confirm window |
| E2E-03 | agent-b container uplink blackholed for 60 s, independent watchdog, automatic fabric recovery |
| E2E-04 | revoke agent-b: fabric unusable and actual mTLS HTTP 403 via a test-only TCP relay |
| E2E-05 | announce signing rotation, confirm agents, encrypted backup, advance agent version, stop/wipe ONLY owned hub data, restore/activate, same certs, monotonic high-water recovery |
| E2E-06 | two different digest-pinned previous images → current hub/agents under continuous fabric mTLS probes, maximum good-probe gap ≤30 s, same certs |
| NL-01 | hub container connects to a TCP listener in agent-a over the fabric; the listener sees the hub fabric address `10.99.0.1` (no NAT) |
| NL-04 | a dummy LAN `192.168.30.0/24` on agent-b is exported (`agent prefix add`); agent-a (source = its fabric address) connects to it through the hub; agent-b sees agent-a's fabric address (no NAT); the hub route is installed by its reconciler (`proto 77`) |
| NL-10 | delete an owned fabric unicast route via `kornode.net.Kernel` inside agent; running reconciler repairs ≤2 s |
| NL-11 | inject a validly signed bundle that dials fabric port 1; real apply rolls back ≤70 s and reports to hub |
| NL-12 | deliver a body changed after signing; require agent's actual signature-rejection evidence, unchanged applied/high-water versions |
| NL-13 (partial) | hub stopped ≥600 s; agent restarts from confirmed cache; external ocserv tunnel and real ICMP probes remain healthy; reconnect when hub returns |

Missing previous-image digests explicitly skip E2E-06; identical images are refused,
not called an upgrade. The baseline must support the current CLI/config/bundle
contracts (P3-07+) and forward-only DB schema. This does not attempt a downgrade of
already-current data: the upgrade scenario starts fresh on previous images.

**P4 blockers stay skipped**, with reasons in `test_routed_fabric.py`, the offline
plan and summary: E2E-07; NL-03, NL-05…09; access-client traffic during upgrade and hub
outage. An existing upstream tunnel is not proof of access-client forwarding,
wg-easy integration, no fabric NAT, domain-based exit selection or no traffic leak.
No production P4 feature or GUI/AppConfig field is added by test tooling.
Running (case `routed`): NL-01, NL-04 and NL-02 (fabric DNS: the agent resolves its
own zone locally and `monitoring.<domain>` through the hub, then connects with its
fabric address).

## Safety gates

1. Ordinary `pytest`/`make check` **always skip VM cases**, even as root. Execution
   requires `--e2e-run` plus exact env opt-in
   `E2E_ALLOW_DESTRUCTIVE=I_ACKNOWLEDGE_DISPOSABLE_VMS`.
2. Inventory is environment-only: four distinct non-loopback IPv4 addresses, explicit
   SSH account/port, private key file (regular, nonempty, private permissions) and
   a pre-provisioned known_hosts file. No automatic `ssh-keyscan`/TOFU or password
   fallback; `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, no agent forwarding,
   no SSH config inheritance. Docker operations are pinned to the local rootful
   `unix:///var/run/docker.sock` (builds use the default builder), not an inherited
   remote production Docker context. Do not commit real inventory or credentials.
3. Every remote action first checks a root-owned, non-group/world-writable regular
   `/etc/kornode-e2e-vm.json`, exact role/purpose/local machine ID and UID 0. Four
   machine IDs must differ; runner machine ID must match hub's. Clone images must
   have their machine IDs regenerated correctly before designation.
4. Exclusive root-owned leases at `/var/lib/kornode-e2e/lease.json` use a random
   24-hex run ID; they are never timed out or stolen. Case names/actions are
   allowlisted; there is no generic remote exec/upload/delete method.
5. Workload containers have `NET_ADMIN`/`NET_RAW`/TUN only in their namespaces,
   no Docker socket, host PID mode or host network. Case metadata/config/Compose
   mounts are **read-only**; only explicit state/recovery subdirectories are RW.
   A guest cannot edit the host cleanup Compose file through its writable state.
6. All dangerous operations require owned cases/leases. Wipe targets only the
   stopped hub case's `data/`; a symlink is refused. Staged restore activation
   verifies the expected regular config path stays inside owned recovery storage.
   No global `prune`, global firewall flush or unrelated volume deletion.
7. Tokens/passwords travel on stdin/inside encrypted SSH, not OS argv. Enrollment
   calls the real CLI entrypoint with stdin-fed arguments, without creating an
   OS process whose command line contains a token. Remote stdout/stderr and
   inventory are not dumped on errors. Pytest `--showlocals` and xdist workers
   are forbidden for opted-in runs. Do not enable shell/SSH/pytest debug tracing.
8. A detached, 60-second host watchdog removes only the fault table **inside the
   exact original container ID**. Losing SSH/pytest cannot leave a permanent host
   blackhole; stopping the container also destroys the test network namespace.
9. Every case collects safe diagnostics then tears down in a fixture `finally`,
   including setup failures. Artifact storage failure must not prevent cleanup.
   Session finalization removes only run-specific image tags and releases leases.
   GitHub `always()` also attempts owned-run recovery and deletes ephemeral SSH
   files. Hard cancellation/VM failure can still leave leases/state: recover
   explicitly, never bypass the marker/lease guard. Cancellation is not atomic DR.

SSH necessarily invokes a remote login shell. The entire fixed Python worker
command is `shlex.join`-quoted as argv; JSON payloads are stdin. Neither controller
nor worker uses `shell=True`. The standalone worker needs only stdlib on the VM;
application imports/CLI run inside built images. The `worker.py` single-file form
is intentional so remote hosts do not need a checkout or an installed hub package.

## Owner provisioning (required before any real run)

Prepare dedicated snapshot/reimage-able VMs with the specified OS matrix from
spec 09, Docker Engine + Compose v2, Python ≥3.12, sudo noninteractive for the E2E
account and `/dev/net/tun`. Budget at least 8 GiB free at the worker base (more for
Docker builds/cache; 16+ GiB recommended). Image transfer is bounded to 3 GiB;
controller transfer uses a private extra disk copy rather than GB-sized RAM buffers.
Do not install the runner on a real VPN host. There must be no unrelated service
using hub/ext TCP 443 or hub TCP 18444.

For each VM, the owner creates the marker **locally on that VM** as root, replacing
only `role` with its exact role (`hub`, `agent-a`, `agent-b`, `ext`):

```sh
sudo python3 - <<'PY'
import json, os
from pathlib import Path
role = 'hub'  # set explicitly per disposable VM
value = {'purpose': 'kornode-e2e-disposable', 'role': role,
         'machine_id': Path('/etc/machine-id').read_text().strip()}
path = '/etc/kornode-e2e-vm.json'
fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'w') as handle:
    json.dump(value, handle)
PY
```

The harness never creates this authorization marker. Granting sudo Python to the
SSH account is effectively root access: **only on these disposable VMs**. Use a
dedicated key and operator-verified host fingerprints. Restrict VM firewall ingress
to the runner/agents as appropriate; no host firewall is reconfigured by the harness.
Allow agent → hub/ext TCP 443 and agent → hub TCP 18444 for the test relay.

TCP 18444 is **test-only**: the hub container forwards raw TLS bytes to its
fabric-only control listener. It is used solely to observe an actual authenticated
HTTP 403 after fabric revocation. The probe keeps CA validation and agent mTLS but
disables hostname matching for this relay hop (different dial address); production
control TLS and the normal direct fabric probes retain normal verification. Never
publish this relay or reuse its Compose definition in production.

Register a dedicated/ephemeral GitHub runner on hub with labels
`self-hosted,kornode-e2e`. Restrict it to this repository/approved workflows; rebuild
or reimage it between trust boundaries. Privileged test code can control the VMs:
labels and same-repository PR checks alone are **not** a security boundary.

## Inventory and workflow configuration

Repository/environment **variables** (no real values are stored here):

- `E2E_HUB_HOST`, `E2E_AGENT_A_HOST`, `E2E_AGENT_B_HOST`, `E2E_EXT_HOST`: distinct VM
  management IPv4 addresses, reachable by the runner. The advertised hub address
  defaults to `E2E_HUB_HOST` and must also be reachable by agents.
- `E2E_HUB_ADDRESS`: optional advertised DNS name or IPv4; blank uses hub host.
- `E2E_SSH_USER`: explicit E2E SSH account, with noninteractive sudo Python.
- `E2E_SSH_PORT`: optional common port (default 22).
- `E2E_PREVIOUS_HUB_IMAGE`, `E2E_PREVIOUS_AGENT_IMAGE`: optional **paired immutable
  `@sha256:` references**, compatible previous pre-release images. Registry auth, if
  needed, is provisioned separately on VMs; never embed credentials in image refs.
- `E2E_ENVIRONMENT_APPROVAL_CONFIGURED=true`: owner acknowledgement, set **only after**
  configuring the protected `kornode-e2e` GitHub Environment with required reviewers,
  self-approval prevention and suitable branch/deployment restrictions.

**Secrets**: `E2E_SSH_KEY`, `E2E_SSH_KNOWN_HOSTS`. The workflow writes them to private
runner-temp files, exports only their paths to later steps, and removes them in
`always()`. It does not print them or upload that directory.

`.github/workflows/e2e.yml` runs on manual dispatch with explicit
`confirmation=DISPOSABLE_VMS` and only from a protected branch (`github.ref_protected`).
There is **no `pull_request` or `pull_request_target` trigger**: a PR-triggered run would use
the PR's own workflow file on the privileged runner. No credential-persisting checkout,
checkout runs with `clean: false` so a previous run's recovery ledger survives,
evidence artifacts are kept 7 days,
and no untrusted shell interpolation. Code is checked out by the triggering SHA.
A protected environment approval is required; the acknowledgement variable does
not itself configure or cryptographically prove that protection. Do not set it
without actual protection. A single concurrency group does not cancel an active
run; remote leases also prevent overlap with manual runs. Timeout: 90 minutes.
No workflow is uploaded/run until the owner separately permits commit/push.

Steps: private SSH setup → dev environment → local harness type/unit checks →
remote preflight/claims → both image builds → pinned image distribution → per-case
Compose deploy/enroll/tests → safe evidence → teardown → best-effort recovery →
allowlisted artifact upload → SSH secret removal.

## Commands

Always safe/offline (no inventory, SSH, Docker or kernel operations):

```sh
make e2e-plan
.venv/bin/python -m pytest tests/test_e2e_harness.py -q
.venv/bin/python -m mypy --explicit-package-bases tests/e2e
```

On the prepared **hub runner only**, after provisioning inventory/credentials:

```sh
# E2E_SSH_KEY_FILE and E2E_KNOWN_HOSTS_FILE are private absolute paths;
# no key/passphrase material is a command argument.
export E2E_ALLOW_DESTRUCTIVE=I_ACKNOWLEDGE_DISPOSABLE_VMS
.venv/bin/python -m tests.e2e preflight
make e2e
```

Ordinary `python -m pytest tests/e2e -q` skips all VM tests without reading inventory.
Real runs require both the CLI switch and env acknowledgement; defaults never
silently activate VM access. Normal `make typecheck` also checks the harness.

## Artifacts and recovery after interruption

Only these paths are eligible for CI upload:

- the agent diagnostic archives (`agent-a.tar.gz`, `agent-b.tar.gz`) stay on the runner:
  the repository is public and masking is heuristic (D-59, code review 2026-10-18);
- per-run `summary.json`: outcomes, timing metrics, blocked contracts, cleanup status,
  previous-baseline availability (not raw inventory/config/command output);
- `artifacts/e2e/junit.xml` (short tracebacks, no `--showlocals`).

Never upload Docker logs/inspect dumps, raw agent or hub directories, YAML configs,
backup archives, passphrase files, TLS/seal/master/signing keys or SSH credentials.
Diagnostics can still contain operational metadata: restrict artifact access/retention.
Raw command output is withheld; sanitized agent diagnostics and fixed role/case
failure locations are the initial troubleshooting evidence. If all diagnostics are
unavailable because startup failed, inspect the **disposable VM locally**, without
posting secrets/log dumps into public CI output.

`active.json` is a private local recovery ledger, deliberately not uploaded. Best-effort cleanup after a normal interrupted test process:

```sh
.venv/bin/python -m tests.e2e cleanup --all-owned --yes
```

If checkout cleanup/runner loss removed the local ledger, obtain the original
non-secret 24-hex `run_id` from the designated VM's root-only lease file and use:

```sh
.venv/bin/python -m tests.e2e cleanup --run-id ORIGINAL_RUN_ID --yes
```

This still requires inventory, explicit env opt-in and valid markers. Recovery is
idempotent when that run is already absent; it refuses a different run's lease or
unknown case contents. Do not delete the lease by hand to make preflight pass over
running workloads. Inspect/recover or revert the dedicated VM snapshots instead.
The harness does not create snapshots or reimage VMs automatically.

## Acceptance still required

1. Claude review of P3-07…P3-10, especially privileged SSH/worker boundaries,
   environment approval, read-only metadata, failure cleanup and fault injection.
2. Privileged P3-07/P3-08/P3-09 netlab and all existing P2 prerequisites.
3. Separate fix for existing clock-dependent enrollment tests; green full check.
4. Owner-provisioned runner/inventory/SSH and permission to push/run workflow.
5. First real four-VM execution; record image sizes/digests, actual scenario timing,
   sanitized diagnostics and cleanup evidence. Current local fake-worker tests are
   not that execution. Container-isolated E2E does not close host-network risks.
6. Compatible previous images for E2E-06 and P4 runtime/client scenarios for full
   spec coverage. No phase/task is marked finally Done by this implementation.
