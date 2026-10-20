# Hub backup, disaster recovery and signing-key rotation (P3-09)

> **Losing the bundle signing keys can require re-enrolling every agent.**
> Losing the CA key prevents certificate issuance/renewal; losing the master key
> prevents decrypting registry credentials. A DB-only snapshot is NOT a hub backup.
> Keep encrypted archives **off-host** and passphrases separately. Test recovery.

## Contract and limits

`BackupService` is shared by `korctl hub backup|restore`, authenticated admin
`POST /api/hub/backup|restore`, and **Config → Backup / Restore**. The CLI works
with `web.enabled: false`; restore does not require the control API or ocserv.
Backup requires an initialized fabric hub with all three trust anchors present.
No new `AppConfig` fields, automatic retention policy or scheduler are introduced.
The existing nightly registry snapshots remain separate and unencrypted/DB-only.

Archive `.knbackup` v1 uses a fixed binary header, random 16-byte salt, random
12-byte nonce, **Argon2id** (64 MiB, 3 iterations, 4 lanes, 32-byte derived key)
and **ChaCha20-Poly1305**; the complete header is AEAD associated data. No costs
are taken from untrusted input. `cryptography >=44` is required. Passphrases are
12–1024 UTF-8 bytes, no normalization/trimming (CLI file drops one final newline).
Maximum archive size: 128 MiB, 10,000 files; capture bounds raw file data below
64 MiB to allow JSON/base64 overhead. There is no compression or tar extraction.

The encrypted payload contains a versioned strict manifest, per-file SHA-256,
file data, resolved effective `AppConfig`, and a portable path map. It includes:

- consistent SQLite backup (including committed WAL state): registry, policies,
  commands/results, reports, bundle history/signatures, tokens, quarantine, rotation;
- `data_dir/certs/`: CA key/certificate, ocserv/control TLS identities, agent/client
  certificates, private keys/PKCS#12 and revocation material;
- actual hub master key at `data_dir/control/master.key` (not an assumed
  `secrets_dir/master.key`), all persisted control key files;
- configured `control.signing_key` **and both authoritative `control_rotation`
  private-key paths**, including custom paths outside `data_dir`, before/after
  promotion and across repeated rotations;
- persistent data and `secrets_dir` files (including ocpasswd/OATH), per-user and
  per-group files, configured external TLS/upstream key/cert files and custom hooks;
- runtime route/domain lists when present, and all resolved config values,
  including environment/`.env` fallbacks and admin credentials/TOTP.

Excludes generated configs (regenerated on startup), logs, `data_dir/run`, caches,
backups/restores, hidden tree entries, lock/temp/socket files and SQLite WAL/SHM.
Explicit configured file references and rotation references are captured even
outside these trees. The **managed ocserv connect hook is regenerated**, with
restored user-directory paths, not copied with old absolute paths embedded in it.
Application/static assets belong to the image, not the backup. Compose files,
external PAM/RADIUS services, OS packages, DNS records, and arbitrary file paths
embedded in `advanced.raw_ocserv_options` or custom script contents are NOT inferred:
back these up separately and review them before activation. Recursive symlinks and
special files are refused; an explicitly configured TLS file may be a Let's Encrypt
symlink, in which case its regular-file content is captured and restored as a file.
Renewal deployment/ACME state is still an operator responsibility.

Backup serializes with agent-management/signing rotation and reserves the registry
writer while copying DB + files. Source inode/mtime/size/ctime and directory changes
are checked; a detected concurrent file change refuses the archive. **This is not a
universal filesystem transaction:** quiesce other administrators, config saves, VPN
user/OTP/CA changes, external certificate renewal and out-of-band file writers for a
maintenance-window backup. It does not pause client traffic or the single reconciler.
No online whole-hub transaction across every legacy file writer is claimed.
Temporary DB validation/snapshot files are under a private 0700 temporary directory,
removed on completion; decrypted file payloads stay in memory until explicit restore.
Use protected/encrypted temporary storage if crash remnants are a concern.

## Create and verify a backup

Run locally, or inside the container with the output on a persistent mount:

```sh
korctl --config /etc/kornode/config.yaml hub backup --out /backup/hub.knbackup
```

A hidden prompt asks for the passphrase twice; no passphrase flag/environment
variable is provided. Existing outputs (including symlinks) are never overwritten;
publication is atomic and 0600. For automation, provision a private passphrase file
through your secret manager, **not through a command containing the secret**:

```sh
korctl --config /etc/kornode/config.yaml hub backup \
  --out /backup/hub.knbackup --passphrase-file /run/secrets/hub-backup-passphrase --json
korctl --config /etc/kornode/config.yaml hub restore /backup/hub.knbackup \
  --target /recovery/hub-verified --passphrase-file /run/secrets/hub-backup-passphrase \
  --dry-run --json
```

Dry-run authenticates/decrypts the whole archive, verifies paths/checksums, SQLite
integrity/foreign keys/schema, CA/server key pairs, master key and rotation key
coverage, and validates relocated config. It does **not** create the restore tree
or touch live networking; a transient validation DB and the operation lock are used.
A newer registry schema is refused; forward migrations only run in temporary/staged
copies. Keep the original archive and use matching/newer compatible hub code.

## Stage and activate after a disaster

1. Prepare a clean host/container and matching kornode version. The original hub
   must be fenced/stopped before activation: never run two clones of one identity.
   Preserve agent state and the hub's public hostname/address/certificate pin.
2. Use a recovery YAML whose data/generated/secrets/log paths point at dedicated,
   writable recovery directories. Do not start runtime initialization on an empty
   original volume: it would generate a different CA/signing/master identity.
3. Validate, then explicitly stage to a **nonexistent** destination:

   ```sh
   korctl --config /etc/kornode/recovery.yaml hub restore /backup/hub.knbackup \
     --target /recovery/hub --passphrase-file /run/secrets/hub-backup-passphrase \
     --yes --json
   ```

   `config.yaml` is published last; a failed restore removes only the newly claimed
   tree. No existing file/tree is replaced, no runtime reload/start/network change
   occurs. The default target is a random `data_dir/restores/hub-<id>/` directory;
   API/GUI never accept a caller-controlled destination path.
4. Review the returned **restored config path**. Typed config paths and authoritative
   DB rotation paths have been remapped inside this tree; bundle bodies/signatures
   and secret ciphertext are unchanged. Do not move the tree to a different path
   afterwards without deliberately updating both YAML and DB key pointers.
5. Keep the tree private while inspecting. For activation, ocserv workers that drop
   privileges need directory traversal and readable non-secret per-user/group
   configs. With a root-owned deployment, grant **only traversal** to the outer tree
   (`chmod 0711 /recovery/hub`); keep config/private keys/secrets 0600, cert/secret
   directories 0700. Startup recreates generated/user/group directory permissions.
   Readable user/group files retain 0644; custom executable hooks retain executable
   owner/public mode. Audit custom hook permissions and all parent directories.
6. Mount the tree at the **same absolute path inside the new container** as the path
   recorded in restored YAML/DB (e.g. `/recovery/hub:/recovery/hub`). Set
   `KORNODE_CONFIG=/recovery/hub/config.yaml`; do not reuse old volume mounts that
   shadow restored directories. Use the existing reviewed Docker privileges/TUN/
   network setup, not a newly invented firewall writer. Image startup performs
   normal idempotent config render and the single reconciler initialization.
   This activation is runtime-dependent and can change host networking; do it only
   in the intended namespace/maintenance window.
7. Before admitting traffic, check the CA/server/signing identities, CRL and revoked
   agent guards. An old backup necessarily loses **changes after its timestamp**:
   reconcile later revocations, deletions, credentials and policies before reconnects.
   For an expired CRL regenerate from the restored revocation ledger with the existing
   certificate tooling before starting listeners; never clear the revocation list.
8. Check `korctl control status`, agent mTLS ping/poll and reports. If agents have
   newer high-water versions, the existing D-37/D-52 poll recovery recompiles above
   them; do not reset agent high-water/cache to make old bundles pass.
9. Keep the encrypted backup/offline old volumes until verification, then dispose
   of recovery material using your storage policy. No automatic deletion is performed.

A restored tree is sensitive plaintext state. Never expose its `config.yaml`, paths
or private files via an unauthenticated static mount or include them in diagnostics.

## API and panel

- `POST /api/hub/backup`: bounded JSON `{"passphrase": "..."}`, binary streaming
  attachment, no-store. Cookie authentication requires `X-Kornode-CSRF`.
- `POST /api/hub/restore?dry_run=true`: encrypted binary request body, passphrase in
  `X-Kornode-Backup-Passphrase` as base64 of UTF-8. This is HTTP header encoding,
  **not encryption**; use HTTPS, configure proxy access logs not to record request
  bodies or this header. No passphrase in query strings or audit details.
- To stage, use `dry_run=false&confirm=restore`; the result reports `staged`,
  `restart_required`, `config_path`, file count and backup timestamp, never secrets.
- Config → Backup / Restore: masked passphrase+confirmation, encrypted download,
  upload → validation → explicit staging confirmation. Passphrases are cleared after
  success/failure and never put in browser storage. Re-enter after validation to
  stage. Global dry-run disables staging. The panel **does not** claim live activation.

## Signing rotation and restore caveats

P3-08 rotation announces the upcoming public key for seven days in old-signed
bundles. Back up before and after rotation, retaining all referenced private files.
A newer key restored from an archive does not magically teach it to an agent that
missed the whole announcement. Such agents can require re-enrollment (D-56).
Do not replace missing referenced keys with newly generated ones.

## Required runtime acceptance

On the disposable privileged netlab VM, run `tests/netlab/test_p3_backup.py`
with the installed development dependencies (`cryptography >=44`). It enrolls a
real certificate, announces rotation, backs up, stops hub listeners, wipes **only
its fixture tree**, restores, explicitly activates, reconnects using the original
agent certificate/pin, and checks monotonic poll recovery. Also rerun P3-07/P3-08
netlab and the full netlab suite. This smoke is not P3-10's four-VM E2E-05.
