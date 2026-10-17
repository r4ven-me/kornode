import { requestBlob, requestJson } from "./api";

export type RestoreResult = {
  dry_run: boolean; staged: boolean; target: string; config_path: string;
  files: number; created_at: string; restart_required: boolean; warning: string;
};

export function createHubBackup(passphrase: string): Promise<Blob> {
  return requestBlob("/api/hub/backup", "", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase }), cache: "no-store"
  });
}

export function restoreHub(file: File, passphrase: string, dryRun: boolean): Promise<RestoreResult> {
  const encoded = btoa(String.fromCharCode(...new TextEncoder().encode(passphrase)));
  return requestJson<RestoreResult>(`/api/hub/restore?dry_run=${dryRun}${dryRun ? "" : "&confirm=restore"}`, null, {
    method: "POST", body: file, cache: "no-store",
    headers: { "Content-Type": "application/octet-stream", "X-Kornode-Backup-Passphrase": encoded }
  });
}
