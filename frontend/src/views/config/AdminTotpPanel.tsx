import { Ban, CheckCircle2, ShieldCheck, X } from "lucide-react";
import { useEffect, useState } from "react";
import { ActionButton, Pill } from "../../components/ui";
import { confirmAction } from "../../lib/async";
import { errorMessage } from "../../lib/errors";
import { type TotpSetup, confirmTotp, disableTotp, fetchTotpStatus, setupTotp } from "../../api";

export function AdminTotpPanel({
  onNotice
}: {
  onNotice: (kind: "ok" | "warning" | "error", text: string) => void;
}) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    void fetchTotpStatus("session")
      .then((status) => setEnabled(status.enabled))
      .catch(() => setEnabled(null));
  }, []);

  const handleEnable = async () => {
    setBusy("totp-setup");
    try {
      const result = await setupTotp("session");
      setSetup(result);
      setCode("");
    } catch (error) {
      onNotice("error", errorMessage(error));
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
      await confirmTotp("session", setup.secret, code.trim());
      setEnabled(true);
      setSetup(null);
      setCode("");
      onNotice("ok", "Two-factor authentication enabled");
    } catch (error) {
      onNotice("error", errorMessage(error));
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
      await disableTotp("session");
      setEnabled(false);
      onNotice("ok", "Two-factor authentication disabled");
    } catch (error) {
      onNotice("error", errorMessage(error));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Admin two-factor authentication</h2>
        {enabled !== null && <Pill kind={enabled ? "ok" : "muted"}>{enabled ? "Enabled" : "Disabled"}</Pill>}
      </div>
      <p className="muted-line">
        Require a TOTP code from an authenticator app (Google Authenticator, Authy, etc.) when
        signing in to this panel.
      </p>
      {!enabled && !setup && (
        <div className="panel-footer">
          <ActionButton label="Enable" icon={ShieldCheck} primary busy={busy === "totp-setup"} onClick={handleEnable} />
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
              }}
            />
            <ActionButton
              label="Confirm"
              icon={CheckCircle2}
              primary
              busy={busy === "totp-confirm"}
              disabled={code.trim().length !== 6}
              onClick={() => void handleConfirm()}
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
            onClick={handleDisable}
          />
        </div>
      )}
    </section>
  );
}
