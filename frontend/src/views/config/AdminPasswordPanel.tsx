import { useState } from "react";
import { requestJson } from "../../api";

type Props = {
  onNotice: (kind: "ok" | "warning" | "error", text: string) => void;
  onReauthenticate?: () => void;
};

export function AdminPasswordPanel({ onNotice, onReauthenticate = () => window.location.reload() }: Props) {
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return <section className="panel" data-capability="web.password.change">
    <div className="panel-header"><h2>Change administrator password</h2></div>
    <p className="field-help">All administrator sessions will be signed out. Sign in again with the new password. Enter a current authenticator code if two-factor authentication is enabled.</p>
    <form onSubmit={async event => {
      event.preventDefault();
      if (!current || !password || password !== confirmation) return;
      setBusy(true); setError("");
      try {
        await requestJson("/api/auth/password", "session", { method: "POST", body: JSON.stringify({ current_password: current, new_password: password, totp_code: totp.trim() || undefined }) });
        setCurrent(""); setPassword(""); setConfirmation(""); setTotp("");
        onNotice("ok", "Administrator password changed. Sign in again.");
        onReauthenticate();
      } catch {
        // Never render arbitrary API errors that might echo a submitted secret.
        setError("Password change failed. Check your current password and authenticator code, then try again.");
      } finally { setBusy(false); }
    }}>
      <fieldset className="settings-grid" disabled={busy}>
        <label><span>Current administrator password</span><input type="password" autoComplete="current-password" maxLength={1024} required value={current} onChange={event => setCurrent(event.target.value)} /></label>
        <label><span>New administrator password</span><input type="password" autoComplete="new-password" maxLength={1024} required value={password} onChange={event => setPassword(event.target.value)} /></label>
        <label><span>Confirm new administrator password</span><input type="password" autoComplete="new-password" maxLength={1024} required value={confirmation} onChange={event => setConfirmation(event.target.value)} /></label>
        <label><span>Current authenticator code (if enabled)</span><input autoComplete="one-time-code" inputMode="numeric" maxLength={6} value={totp} onChange={event => setTotp(event.target.value)} /></label>
      </fieldset>
      {confirmation && password !== confirmation && <p role="status">New passwords must match.</p>}
      {error && <p role="alert">{error}</p>}
      <div className="panel-footer"><button className="action-button primary" disabled={busy || !current || !password || password !== confirmation} data-capability="web.password.change">{busy ? "Working" : "Change administrator password"}</button></div>
    </form>
  </section>;
}
