import { Download, ShieldCheck, Upload } from "lucide-react";
import { useState } from "react";
import { ActionButton } from "../../components/ui";
import { createHubBackup, restoreHub, type RestoreResult } from "../../hubApi";

// Backend detail helps the operator, but is dropped if it echoes any passphrase in play.
function reason(e: unknown, ...secrets: string[]): string {
  if (!(e instanceof Error) || !e.message) return "";
  return secrets.some(secret => secret && e.message.includes(secret)) ? "" : ` Server said: ${e.message}`;
}

export function BackupPanel({ dryRun = false }: { dryRun?: boolean }) {
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [restorePassword, setRestorePassword] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<RestoreResult | null>(null);
  const [result, setResult] = useState<RestoreResult | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [downloaded, setDownloaded] = useState(false);

  async function backup() {
    setBusy(true); setError(""); setDownloaded(false);
    try {
      const blob = await createHubBackup(password);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url; link.download = `hub-${new Date().toISOString().replace(/[:.]/g, "-")}.knbackup`;
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      setDownloaded(true);
      setPassword(""); setRepeat("");  // kept on failure so the operator can retry
    } catch (e) {
      setError("Backup failed. Check the initialized hub, key files, permissions and available disk space." + reason(e, password, repeat));
    } finally { setBusy(false); }
  }

  async function restore(dryRun: boolean) {
    if (!file) return;
    setBusy(true); setError("");
    try {
      const response = await restoreHub(file, restorePassword, dryRun);
      if (dryRun) { setPreview(response); setResult(null); }
      else { setResult(response); setPreview(null); setConfirmed(false); }
      setRestorePassword("");
    } catch (e) {
      setPreview(null); setConfirmed(false);
      setError("Restore failed. Check the passphrase and archive. Live hub state was not replaced." + reason(e, restorePassword));
    } finally { setBusy(false); }
  }

  return <div className="view-stack hub-backup">
    <section className="panel config-section-panel" data-capability="hub.backup" aria-labelledby="hub-backup-title">
      <div><h2 id="hub-backup-title">Encrypted hub backup</h2>
        <p className="muted-line">Registry, CA, TLS identity, master key, signing rotation keys, users and resolved configuration.</p></div>
      <p className="warning-banner">Losing the signing keys can require re-enrolling every agent. Store the archive off-host and keep its passphrase separately. Use HTTPS; do not log backup request bodies or headers.</p>
      <div className="settings-grid">
        <label><span>Backup passphrase</span><input type="password" autoComplete="new-password" value={password} disabled={busy} onChange={e => setPassword(e.target.value)} /></label>
        <label><span>Confirm backup passphrase</span><input type="password" autoComplete="new-password" value={repeat} disabled={busy} onChange={e => setRepeat(e.target.value)} /></label>
      </div>
      <p className="muted-line">Argon2id + ChaCha20-Poly1305. Use at least 12 UTF-8 bytes. Maximum encrypted archive: 128 MiB. Passphrases are cleared after each successful operation.</p>
      <div className="hub-backup-actions"><ActionButton label="Download encrypted backup" icon={Download} primary busy={busy} disabled={!password || password !== repeat} onClick={() => void backup()} /></div>
      {downloaded && <p role="status">Encrypted archive downloaded. Test restoring it before relying on it.</p>}
    </section>
    <section className="panel config-section-panel" data-capability="hub.restore" aria-labelledby="hub-restore-title">
      {dryRun && <p className="muted-line">Global dry-run is enabled: archive validation is available, staging is disabled.</p>}
      <div><h2 id="hub-restore-title">Validate and stage restore</h2>
        <p className="muted-line">Never overwrites the live hub. Restores to a new private directory with remapped paths.</p></div>
      <div className="settings-grid">
        <label><span>Encrypted archive</span><input type="file" accept=".knbackup,application/octet-stream" disabled={busy} onChange={e => { setFile(e.target.files?.[0] ?? null); setPreview(null); setResult(null); setConfirmed(false); }} /></label>
        <label><span>Restore passphrase</span><input type="password" autoComplete="off" disabled={busy} value={restorePassword} onChange={e => setRestorePassword(e.target.value)} /></label>
      </div>
      <div className="hub-backup-actions"><ActionButton label="Validate archive" icon={ShieldCheck} primary={!preview} busy={busy} disabled={!file || !restorePassword} onClick={() => void restore(true)} /></div>
      {preview && <div className="view-stack">
        <p role="status">Archive validated: {preview.files} files, created {preview.created_at}. No restore tree written.</p>
        <p className="muted-line">Re-enter the passphrase to stage the restore. Activation requires stopping the old hub and starting with the restored config; running two copies of one identity is unsafe.</p>
        <label className="switch"><input type="checkbox" checked={confirmed} disabled={busy} onChange={e => setConfirmed(e.target.checked)} /><span>I understand this stages a restore, not a live switch</span></label>
        <div className="hub-backup-actions"><ActionButton label="Stage hub restore" icon={Upload} danger busy={busy} disabled={dryRun || !confirmed || !restorePassword} onClick={() => void restore(false)} /></div>
      </div>}
      {result && <div role="status" className="view-stack">
        <p>Restore staged. Live hub unchanged; manual activation required.</p>
        <label><span>Restored configuration path</span><input readOnly value={result.config_path} /></label>
        <p className="muted-line">{result.warning} Follow docs/runbooks/hub-recovery.md before switching volumes or starting services.</p>
      </div>}
    </section>
    {error && <p role="alert" className="warning-banner">{error}</p>}
  </div>;
}
