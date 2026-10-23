# Audit remediation — `fix/audit-hardening`

This is the implementation follow-up to [the original audit](audit-2026-10-22.md).
The original report is historical evidence, not a statement that all those defects
remain present. Changes were developed in an isolated worktree and integrated with
main's gateway/node naming, panel layout, and dual-image release workflow.

## Findings and implementation

| Finding | Remediation |
| --- | --- |
| A01 | Password-only Basic is rejected while admin TOTP is enabled. Password and MFA changes require current-password verification and the current OTP when applicable. |
| A02 | Stable exit-identity marks, exact 128-bit conntrack identity labels, collision rejection, and populated fail-closed routing barriers prevent positional mark reuse and unsafe table transitions. |
| A03 | Partial/invalid CA state fails closed. Key/certificate generation uses private staging, validates pairs, and rolls back handled publication failures. |
| A04 | Ocserv remains registered with supervisor; start/stop transitions are applied independently of desired disabled state and optional reload. |
| A05–A06 | Central redaction covers inline key/P12 values; validation errors omit input, unsafe exception text, and context. |
| A07 | Named masked collections restore secrets by identity, not position; unknown/ambiguous masks are rejected. |
| A08–A09 | Credential/MFA changes revoke sessions. Reauthenticated mutations recheck their authority under the config lock. Basic Origin checks use the full origin and reject opaque/malformed values. |
| A10 | A detached, bounded streaming sink redacts before persistence; READY/flush barriers synchronize command results. Private-key suppression operates before secret replacement. |
| A11 | Settings mutate raw collections under the shared lock, preserving secret references. Omitted OIDC secrets remain unchanged; explicit null removes them. |
| A12–A13 | API/CLI/live config writers share a serialized mutation service. Source saves enforce ETags. Rendering is preflighted; postcommit failures explicitly report `saved_but_not_applied`. |
| A14–A15 | Top-level env collections work; loader/API/CLI share validation provenance. Symlink paths retain their original environment-discovery context throughout a transaction. |
| A16–A17 | `upstream:active` follows selection; named profiles stay pinned. Disabled targets remain known but fail closed. External disconnect accurately reports that the external interface/policy is untouched. |
| A18–A20 | Partial NAT-table loss invalidates observed schema; connect dry-run does not materialize files; dotted interface sysctls use literal directory names. |
| A21 | Host DNS changes require local resolver readiness; an outage does not silently enable an unsafe fallback. |
| A22–A23 | Nullable group controls support inheritance. Control settings, source fields, and destination sets have structured controls and field-inventory regressions. Admin password changes use a dedicated flow. |
| A24 | Container test stages include required repository fixtures; CI builds those stages. |
| A25 | Documentation now states CLI > YAML > process env > .env > defaults. |

The field inventory checks the repaired ControlConfig, Source, DestSet, and nullable
group fields. It is deliberately not presented as an exhaustive proof of every
historical AppConfig control.

## Additional hardening

- Hub DNS sets preserve their existing group snapshot on transient lookup failures
  and retry after 30 seconds. Authoritative negatives/completed cycles replace the
  snapshot; removed groups are not retained. During partial failure the retained
  set is a conservative group-level superset, not per-domain provenance.
- Docker readiness checks bounded local supervisor/reconciler signals instead of
  treating socket existence or static web liveness as proof of runtime health.
  An external VPN outage alone is not a container-health failure.
- Default ocserv 1.5.0 source SHA-256 is pinned and mandatory. The digest was checked
  against the upstream HTTPS checksum and independently downloaded tarball.
- Version tags are not deleted/replaced. Local release publication requires a clean
  tree, an explicit reviewed HEAD SHA, and complete checks. The GitHub workflow
  retains hub/agent publication and gates it on the exact main commit's CI and
  branch protection, with SBOM/provenance enabled.

## Upgrade and API changes

1. **Schedule reconnects.** Legacy unlabeled or old-identity connections fail closed
   under the new identity guard. They must reconnect. Conntrack-label kernel support
   is required. Canonical `node:<n>` identities differ from historical `exit:<n>`
   identities. Routing mutations may briefly block marked traffic; failed mutations
   retain their guard until successful reconciliation.
2. **No password-only API bypass of MFA.** Scripted Basic remains available only
   while TOTP is off. MFA-enabled automation must use an authenticated session flow.
3. **Reauthentication and sign-in.** Password/TOTP mutations require current
   credentials and revoke existing sessions. Their responses request sign-in again.
   Generic config writes cannot change password/MFA fields to bypass these flows.
4. **Version full YAML saves.** Obtain `etag` from `GET /api/config/source`, send it
   as `If-Match` or JSON `etag` to `POST /api/config/source`. Missing version is 428;
   stale/invalid version is 412. The panel preserves unsaved edits on conflicts.
5. **Partial apply is explicit.** A postcommit runtime failure is reported as
   `saved_but_not_applied`; YAML and running config may already be updated. Reload
   source, repair/rerender runtime files, and only then reload services.
6. **Empty collections remain explicit.** YAML `sets` replaces lower-priority sets;
   `{}` clears inherited sets. Ordinary nested settings sections still merge.
7. **PKI recovery is deliberate.** Restore a complete matching CA pair from backup;
   startup never repairs a partial pair by creating a new authority. Rotation is an
   explicit action with separate handling of dependent certificates and trust.
8. **Release invocation changed.** Commit/review/push separately, then use
   `make release RELEASE_COMMIT=<full-reviewed-HEAD-SHA>`. Floating `EXTRA_TAG` is
   explicitly mutable; semantic version tags are not.

## Follow-up review fixes (2026-10-23)

Independent PR review found three uncovered paths; these are now fixed with
regression tests:

- CLI profile/provider/group collection mutations run against the latest raw data
  under the shared source lock, preserving named entries and secret references.
  Omitted OIDC secrets stay unchanged; `--clear-client-secret` explicitly clears one.
- Explicit render, delayed blocklist refresh, DNS apply and server start/restart
  reload the authoritative source under the same lock, retained through dependent
  runtime actions. Symlink and explicit `.env` contexts remain unchanged; embedded
  apps with unsaved initialization candidates retain their deliberate overrides.
- Password/TOTP mutations validate using the supplied source path rather than its
  resolved alias, keeping symlink-specific environment discovery consistent.

Final follow-up local validation: **1831 backend tests passed**, 120 privileged/VM
cases deselected; **78 frontend tests passed**, TypeScript/build, Ruff, both mypy
targets, render and parity passed. The original head's GitHub CI run `39965496145`
also passed backend, frontend, container-tests and **97 full netlab cases**. Fresh
CI must pass on the follow-up commit before merge; the original result does not
validate later edits. No disposable-VM E2E or production deployment was performed
as part of this review.

## Validation boundaries

Final ordinary validation: **1789 backend tests passed** (120 privileged/VM cases
excluded), **78 frontend tests passed**, Ruff, both mypy targets, TypeScript and
production frontend build passed. Both Docker `backend-test` (Python 3.12) and
`frontend-test` stages built successfully; the latter also runs npm audit at the
moderate threshold. There is also real-kernel validation in a privileged **isolated**
container using private network/PID namespaces, no host mounts, and no host networking.
The kernel slice passed 35 cases after the gateway merge, including established-flow
routing edits, alias switching, deletion/collision/legacy guards and barrier updates.
A separate previously failing policy-route netlab case also passed after correcting
its fixture to propagate `KORNODE_CONFIG` into the session hook.

The full netlab attempt exceeded a 14-minute bound and is **not** claimed as passed.
Its pre-timeout fixture failure was reproduced and fixed separately. Disposable-VM
E2E, production deployment, upgrade acceptance, and minimum supported kernel/nftables
combinations still require their dedicated environments. The pull request records
these boundaries; successful test stages are not a claim of a tested production
runtime-image deployment.

Remaining constraints:

- Pair publication at fixed filenames is atomic per file, not crash-atomic across a
  pair. Handled errors roll back; restore/recovery remains necessary after abrupt loss.
- Readiness does not prove an exact applied config revision or control-app readiness;
  current reconciler status lacks those acknowledgements.
- No complete Python dependency lock/base-image/apt reproducibility guarantee is
  added. Registry-side immutable tags remain necessary to constrain external writers.
- The DNS last-known-good change is hub-side; agent resolver policy is not silently
  changed by this patch.
