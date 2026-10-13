# 11 — Security model

## Trust anchors

| Anchor | Where | Protects |
| --- | --- | --- |
| kornode CA (existing) | hub `secrets_dir` | agent and client certificates, control API mTLS |
| Bundle signing key (Ed25519) | hub `data_dir/control/` 0600 | integrity of desired state, including cached bundles; signs only `kornode.bundle.v1\0`-prefixed messages (05) |
| Hub master key (32 bytes) | hub `secrets_dir/master.key` 0600 | registry secrets at rest (upstream credentials) |
| Agent TLS key, seal key | agent `/var/lib/kornode-agent` 0600 | agent identity, confidentiality of sealed secrets |
| Hub server cert pin | enroll token, `agent.yaml` | prevents MITM on the fabric session |

All three hub keys are included in `hub backup` (encrypted with a passphrase,
Argon2id KDF + ChaCha20-Poly1305). Losing the signing key means re-enrolling
all agents; the backup procedure must say so prominently.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Stolen enroll token | One-time, TTL ≤ 60 min, bound to one node id, enroll group restricted to the control API port, rate-limited, audit-logged. |
| Compromised agent | Its cert only authorizes its own bundle/commands; sealed secrets of other agents unreadable; revoke → CRL; hub never executes anything sent by agents (reports are data, size-limited, schema-validated). |
| Compromised hub | Full control by design (it is the controller). Reduce blast radius: no arbitrary shell command type; agents verify schema and refuse bundles that remove the fabric exit without a replacement (would be rolled back anyway). |
| Network attacker on the fabric path | TLS (ocserv) with pinned server cert; DPI resistance via standard 443/tcp and optional camouflage. |
| Tampered cache on agent disk | Signature verified at boot; sealed values are bound to their JSON path (05), so moving ciphertexts between fields fails to unseal. |
| Replay of an old bundle | Versions strictly increasing; agent rejects ≤ `high_water` (the highest version it ever verified), not just ≤ applied, so a local rollback does not reopen old versions (except explicit local rollback to a cached confirmed version). |
| Secrets in logs | Existing masker extended to bundle fields marked secret, tokens, CSR private parts; tests assert no secret appears in logs/API output (existing pattern). |
| Admin API exposure | Unchanged (existing auth, TOTP); control API never exposed publicly (bound to fabric address). |

## Permissions

- Agent container: `NET_ADMIN`, `NET_RAW`, `/dev/net/tun`; no Docker socket.
- Hub control API process runs with the same privileges as the admin API
  (no kernel access needed — it only touches the registry and files); the
  reconciler is the only privileged network actor.
