import { Ban, CheckCircle2, ShieldCheck, X } from "lucide-react";
import { useEffect, useState } from "react";
import { ActionButton, Pill } from "../../components/ui";
import { confirmAction } from "../../lib/async";
import { type TotpSetup, confirmTotp, disableTotp, fetchTotpStatus, setupTotp } from "../../api";

export function AdminTotpPanel({
  onNotice,
  onReauthenticate = () => window.location.reload()
}: {
  onNotice: (kind: "ok" | "warning" | "error", text: string) => void;
  onReauthenticate?: () => void;
}) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [currentCode, setCurrentCode] = useState("");
  const credentials = { current_password: password, totp_code: currentCode.trim() || undefined };
  const clearCredentials = () => { setPassword(""); setCurrentCode(""); };
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    void fetchTotpStatus("session")
      .then((status) => setEnabled(status.enabled))
      .catch(() => setEnabled(null));
  }, []);

  const handleEnable = async () => {
    setBusy("totp-setup");
    try {
      const result = await setupTotp("session", credentials);
      setSetup(result);
      setCode("");
    } catch {
      onNotice("error", "Two-factor action failed. Check your password and authenticator code, then try again.");
    } finally {
      setBusy(null);
    }
  };

  const handleConfirm = async () => {
    if (!setup) {
      return;
    }
    setBusy("totp-confirm");
    try {
      await confirmTotp("session", setup.secret, code.trim(), credentials);
      setEnabled(true);
      setSetup(null);
      setCode("");
      clearCredentials();
      onNotice("ok", "Two-factor authentication enabled. Sign in again.");
      onReauthenticate();
    } catch {
      onNotice("error", "Two-factor action failed. Check your password and authenticator code, then try again.");
    } finally {
      setBusy(null);
    }
  };

  const handleDisable = async () => {
    if (!confirmAction("Disable two-factor authentication for the admin panel?")) {
      return;
    }
    setBusy("totp-disable");
    try {
      await disableTotp("session", credentials);
      setEnabled(false);
      clearCredentials();
      onNotice("ok", "Two-factor authentication disabled. Sign in again.");
      onReauthenticate();
    } catch {
      onNotice("error", "Two-factor action failed. Check your password and authenticator code, then try again.");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="panel" data-capability="web.totp.status">
      <div className="panel-header">
        <h2>Admin two-factor authentication</h2>
        {enabled !== null && <Pill kind={enabled ? "ok" : "muted"}>{enabled ? "Enabled" : "Disabled"}</Pill>}
      </div>
      <p className="muted-line">
        Require a TOTP code from an authenticator app (Google Authenticator, Authy, etc.) when
        signing in to this panel.
      </p>
      <div className="settings-grid">
        <label><span>Current password for two-factor changes</span><input type="password" autoComplete="current-password" value={password} disabled={busy !== null} onChange={event => setPassword(event.target.value)} /></label>
        {enabled && <label><span>Current two-factor code</span><input autoComplete="one-time-code" inputMode="numeric" maxLength={6} value={currentCode} disabled={busy !== null} onChange={event => setCurrentCode(event.target.value)} /></label>}
      </div>
      {!enabled && !setup && (
        <div className="panel-footer">
          <ActionButton label="Enable" icon={ShieldCheck} primary busy={busy === "totp-setup"} disabled={!password || enabled === null} onClick={handleEnable} data-capability="web.totp.setup" />
        </div>
      )}
      {setup && (
        <div className="totp-setup">
          <div className="qr-preview" dangerouslySetInnerHTML={{ __html: setup.qr_svg ?? "" }} />
          <label>
            <span>Secret</span>
            <div className="totp-secret">{setup.secret}</div>
          </label>
          <label>
            <span>Authenticator code</span>
            <input
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              autoFocus
            />
          </label>
          <div className="panel-footer">
            <ActionButton
              label="Cancel"
              icon={X}
              onClick={() => {
                setSetup(null);
                setCode("");
                clearCredentials();
              }}
            />
            <ActionButton
              label="Confirm"
              icon={CheckCircle2}
              primary
              busy={busy === "totp-confirm"}
              disabled={code.trim().length !== 6 || !password || (enabled === true && currentCode.trim().length !== 6)}
              onClick={() => void handleConfirm()}
              data-capability="web.totp.confirm"
            />
          </div>
        </div>
      )}
      {enabled && !setup && (
        <div className="panel-footer">
          <ActionButton
            label="Disable"
            icon={Ban}
            danger
            busy={busy === "totp-disable"}
            disabled={!password || currentCode.trim().length !== 6}
            onClick={handleDisable}
            data-capability="web.totp.disable"
          />
        </div>
      )}
    </section>
  );
}
