import { Ban, CheckCircle2, Eye, Fingerprint, Power, RefreshCw, Save, Upload } from "lucide-react";
import type { FormEvent } from "react";
import type { CommandOutput } from "../../app/types";
import { LastCommandPanel } from "../../components/CommandOutput";
import { FilePicker } from "../../components/FilePicker";
import { SettingsTabs } from "../../components/SettingsTabs";
import { CopyField } from "../../components/CopyField";
import { ActionButton, EmptyState, Pill } from "../../components/ui";
import { splitLines } from "../../lib/drafts";
import { AuthorityPathsView, CertificatePathsView } from "./CertificatePaths";
import type { CertificatePin, CertificateStatus, IntervalUnit } from "../../api";

export function CertificatesView({
  status,
  externalFiles,
  caFiles,
  caRevokeDraft,
  certificateSettingsDraft,
  letsEncryptDraft,
  busy,
  dryRun,
  commandOutput,
  onClearCommand,
  onExternalFilesChange,
  onCaFilesChange,
  onCaRevokeDraftChange,
  onCertificateSettingsDraftChange,
  onSaveCertificateSettings,
  onLetsEncryptDraftChange,
  onUploadExternal,
  onIssueLetsEncrypt,
  onRenewLetsEncrypt,
  onSaveLetsEncryptSettings,
  onSetLetsEncryptEnabled,
  onRegenerateCa,
  onUploadCa,
  onRevokeCaCert,
  onShowRevokedCerts,
  serverPin,
  onShowServerPin,
  onShowAuthorityCertificateContent,
  onShowServerCertificateContent,
  onShowLetsEncryptCertificateContent
}: {
  status: CertificateStatus | null;
  serverPin: CertificatePin | null;
  onShowServerPin: () => void;
  onShowAuthorityCertificateContent: () => void;
  onShowServerCertificateContent: () => void;
  onShowLetsEncryptCertificateContent: () => void;
  externalFiles: { serverCert: File | null; serverKey: File | null; caCert: File | null };
  caFiles: { caCert: File | null; caKey: File | null };
  caRevokeDraft: { certificateB64: string; certificateFile: File | null };
  certificateSettingsDraft: { mode: "auto" | "external"; caName: string };
  letsEncryptDraft: {
    enabled: boolean;
    email: string;
    domains: string;
    staging: boolean;
    reload: boolean;
    autoRenew: boolean;
    interval: number;
    intervalUnit: IntervalUnit;
    http01Address: string;
    http01Port: number;
  };
  busy: string | null;
  dryRun: boolean;
  commandOutput: CommandOutput;
  onClearCommand: () => void;
  onExternalFilesChange: (value: {
    serverCert: File | null;
    serverKey: File | null;
    caCert: File | null;
  }) => void;
  onCaFilesChange: (value: { caCert: File | null; caKey: File | null }) => void;
  onCaRevokeDraftChange: (value: { certificateB64: string; certificateFile: File | null }) => void;
  onCertificateSettingsDraftChange: (value: { mode: "auto" | "external"; caName: string }) => void;
  onSaveCertificateSettings: () => void;
  onLetsEncryptDraftChange: (value: {
    enabled: boolean;
    email: string;
    domains: string;
    staging: boolean;
    reload: boolean;
    autoRenew: boolean;
    interval: number;
    intervalUnit: IntervalUnit;
    http01Address: string;
    http01Port: number;
  }) => void;
  onUploadExternal: (event: FormEvent<HTMLFormElement>) => void;
  onIssueLetsEncrypt: (event: FormEvent<HTMLFormElement>) => void;
  onRenewLetsEncrypt: () => void;
  onSaveLetsEncryptSettings: () => void;
  onSetLetsEncryptEnabled: (enabled: boolean) => void;
  onRegenerateCa: () => void;
  onUploadCa: () => void;
  onRevokeCaCert: () => void;
  onShowRevokedCerts: () => void;
}) {
  const activeReady = status
    ? status.active.server_cert_exists && status.active.server_key_exists && status.active.ca_cert_exists
    : false;
  const leDomains = splitLines(letsEncryptDraft.domains);
  const leEnabled = Boolean(letsEncryptDraft.enabled);
  return (
    <div className="view-stack">
      <SettingsTabs ariaLabel="Certificate settings">
        <details>
          <summary>Certificate authority</summary>
          <div className="view-stack">
      <section className="panel">
        <div className="panel-header">
          <h2>Authority certificates</h2>
          <Pill
            kind={
              status?.authority.ca_cert_exists && status.authority.ca_key_exists
                ? "ok"
                : "warning"
            }
          >
            {status?.authority.ca_cert_exists && status.authority.ca_key_exists
              ? "Ready"
              : "Incomplete"}
          </Pill>
        </div>
        {status ? (
          <AuthorityPathsView authority={status.authority} />
        ) : (
          <EmptyState text="No CA status" />
        )}
        <div className="settings-grid">
          <label>
            <span>Mode</span>
            <select
              aria-describedby="certificate-mode-help"
              value={certificateSettingsDraft.mode}
              onChange={(event) =>
                onCertificateSettingsDraftChange({
                  ...certificateSettingsDraft,
                  mode: event.target.value as "auto" | "external"
                })
              }
            >
              <option value="auto">Auto (local CA)</option>
              <option value="external">External</option>
            </select>
            <small className="field-help" id="certificate-mode-help">
              {certificateSettingsDraft.mode === "auto"
                ? "Auto uses the Korvus-managed local CA to generate and maintain certificates."
                : "External uses a certificate and private key supplied by you; Korvus does not generate them."}
            </small>
          </label>
          <label>
            <span>CA name</span>
            <input
              value={certificateSettingsDraft.caName}
              onChange={(event) =>
                onCertificateSettingsDraftChange({
                  ...certificateSettingsDraft,
                  caName: event.target.value
                })
              }
            />
          </label>
        </div>
        <div className="panel-footer">
          <ActionButton
            label="View certificate"
            icon={Eye}
            disabled={!status?.authority.ca_cert_exists}
            busy={busy === "authority-cert-info"}
            onClick={onShowAuthorityCertificateContent}
          />
          <ActionButton
            label="Regenerate CA"
            icon={RefreshCw}
            danger
            busy={busy === "ca-regenerate"}
            onClick={onRegenerateCa}
          />
          <ActionButton
            label="Save"
            icon={Save}
            primary
            busy={busy === "certificate-settings"}
            onClick={onSaveCertificateSettings}
          />
        </div>
      </section>

      <div className="split">
        <section className="panel">
          <div className="panel-header">
            <h2>Upload custom CA</h2>
          </div>
          <div className="settings-grid">
            <div className="field-label">
              <span>CA certificate</span>
              <FilePicker
                accept=".pem,.crt"
                file={caFiles.caCert}
                label="Select CA cert"
                title="Upload a PEM CA certificate used to sign user and server certificates"
                onChange={(event) =>
                  onCaFilesChange({ ...caFiles, caCert: event.target.files?.[0] ?? null })
                }
              />
            </div>
            <div className="field-label">
              <span>CA private key</span>
              <FilePicker
                accept=".pem,.key"
                file={caFiles.caKey}
                label="Select CA key"
                title="Upload the PEM private key for the CA certificate"
                onChange={(event) =>
                  onCaFilesChange({ ...caFiles, caKey: event.target.files?.[0] ?? null })
                }
              />
            </div>
          </div>
          <div className="panel-footer">
            <ActionButton
              label="Upload CA"
              icon={Upload}
              primary
              disabled={!caFiles.caCert || !caFiles.caKey}
              busy={busy === "ca-upload"}
              onClick={onUploadCa}
            />
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Revoke user certificate</h2>
          </div>
          <div className="settings-grid">
            <label>
              <span>Certificate (PEM)</span>
              <textarea
                rows={4}
                placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
                value={caRevokeDraft.certificateB64}
                onChange={(event) =>
                  onCaRevokeDraftChange({
                    ...caRevokeDraft,
                    certificateB64: event.target.value
                  })
                }
              />
            </label>
            <div className="field-label">
              <span>Certificate file</span>
              <FilePicker
                accept=".pem,.crt"
                file={caRevokeDraft.certificateFile}
                label="Select cert"
                title="Upload a PEM user certificate that should be added to the CRL"
                onChange={(event) =>
                  onCaRevokeDraftChange({
                    ...caRevokeDraft,
                    certificateFile: event.target.files?.[0] ?? null
                  })
                }
              />
            </div>
          </div>
          <div className="panel-footer">
            <ActionButton label="View revoked" icon={Eye} onClick={onShowRevokedCerts} />
            <ActionButton
              label={dryRun ? "Dry-run revoke" : "Revoke"}
              icon={Ban}
              danger
              disabled={!caRevokeDraft.certificateB64.trim() && !caRevokeDraft.certificateFile}
              busy={busy === "ca-revoke"}
              onClick={onRevokeCaCert}
            />
          </div>
        </section>
      </div>
          </div>
        </details>

        <details>
          <summary>Server certificate</summary>
          <div className="view-stack">
      <section className="panel">
        <div className="panel-header">
          <h2>Active certificate</h2>
          <Pill kind={activeReady ? "ok" : "warning"}>{activeReady ? "Ready" : "Incomplete"}</Pill>
        </div>
        {status ? (
          <CertificatePathsView paths={status.active} caLabel="Client certificate CA" />
        ) : (
          <EmptyState text="No status" />
        )}
        <div className="pin-panel">
          <div className="toolbar">
            <ActionButton
              label="View certificate"
              icon={Eye}
              busy={busy === "server-cert-info"}
              disabled={!activeReady}
              onClick={onShowServerCertificateContent}
            />
            <ActionButton
              label="Show connection pin"
              icon={Fingerprint}
              busy={busy === "server-pin"}
              disabled={!activeReady}
              title="Pin other OpenConnect clients use to trust this server's certificate"
              onClick={onShowServerPin}
            />
          </div>
          {serverPin && (
            <>
              <CopyField label="Server certificate pin" value={serverPin.pin} />
              <CopyField label="SHA-256 fingerprint" value={serverPin.sha256} />
              <p className="muted-line">
                On another Korvus Node, paste the pin into the upstream profile's
                "Server cert pin" field (openconnect: --servercert). The pin follows the
                key, so it survives a certificate renewal that keeps the same key; the
                fingerprint changes with every new certificate.
              </p>
            </>
          )}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Manual upload</h2>
          <Pill kind={status?.mode === "external" && !status.letsencrypt.enabled ? "ok" : "muted"}>
            External
          </Pill>
        </div>
        <form onSubmit={onUploadExternal}>
        <div className="settings-grid">
          <div className="field-label">
            <span>Server certificate</span>
            <FilePicker
              accept=".pem,.crt"
              file={externalFiles.serverCert}
              label="Select certificate"
              title="Upload the public certificate PEM used by Korvus Node"
              onChange={(event) =>
                onExternalFilesChange({
                  ...externalFiles,
                  serverCert: event.target.files?.[0] ?? null
                })
              }
            />
          </div>
          <div className="field-label">
            <span>Server private key</span>
            <FilePicker
              accept=".pem,.key"
              file={externalFiles.serverKey}
              label="Select private key"
              title="Upload the private key PEM matching the server certificate"
              onChange={(event) =>
                onExternalFilesChange({
                  ...externalFiles,
                  serverKey: event.target.files?.[0] ?? null
                })
              }
            />
          </div>
          <div className="field-label">
            <span>CA / chain certificate</span>
            <FilePicker
              accept=".pem,.crt"
              file={externalFiles.caCert}
              label="Select CA chain"
              title="Upload the CA or full-chain PEM presented to clients"
              onChange={(event) =>
                onExternalFilesChange({ ...externalFiles, caCert: event.target.files?.[0] ?? null })
              }
            />
          </div>
          <label className="switch" title="Reload ocserv after installing uploaded certificates">
            <input
              checked={letsEncryptDraft.reload}
              onChange={(event) =>
                onLetsEncryptDraftChange({ ...letsEncryptDraft, reload: event.target.checked })
              }
              type="checkbox"
            />
            <span>Reload server</span>
          </label>
        </div>
          <div className="panel-footer">
            <button
              className="primary-button"
              disabled={
                busy === "cert-upload" ||
                !externalFiles.serverCert ||
                !externalFiles.serverKey ||
                !externalFiles.caCert
              }
              title="Install uploaded certificates and optionally reload Korvus Node"
              type="submit"
            >
              <Upload size={18} aria-hidden="true" />
              <span>{busy === "cert-upload" ? "Working" : "Install"}</span>
            </button>
          </div>
        </form>
      </section>
          </div>
        </details>

        <details>
          <summary>Let's Encrypt</summary>
      <section className="panel">
        <div className="panel-header">
          <h2>Let's Encrypt</h2>
          <div className="toolbar">
            <Pill kind={leEnabled ? "ok" : "muted"}>{leEnabled ? "Enabled" : "Disabled"}</Pill>
            <Pill kind={status?.certbot_available ? "ok" : "warning"}>
              certbot {status?.certbot_available ? "available" : "missing"}
            </Pill>
          </div>
        </div>
        <form onSubmit={onIssueLetsEncrypt}>
        <div className="settings-grid">
          <label title="Email registered with Let's Encrypt for expiration notices">
            <span>Email</span>
            <input
              autoComplete="email"
              disabled={!leEnabled}
              onChange={(event) =>
                onLetsEncryptDraftChange({ ...letsEncryptDraft, email: event.target.value })
              }
              placeholder={status?.letsencrypt.email ?? "admin@example.com"}
              value={letsEncryptDraft.email}
            />
          </label>
          <label title="One DNS name per line; the first domain becomes the primary certificate path">
            <span>Domains</span>
            <textarea
              disabled={!leEnabled}
              onChange={(event) =>
                onLetsEncryptDraftChange({ ...letsEncryptDraft, domains: event.target.value })
              }
              placeholder={(status?.letsencrypt.domains ?? ["vpn.example.com"]).join("\n")}
              rows={2}
              value={letsEncryptDraft.domains}
            />
          </label>
          <label title="Address certbot binds to for the HTTP-01 challenge; leave blank to follow the VPN server's listen address">
            <span>HTTP-01 address</span>
            <input
              disabled={!leEnabled}
              onChange={(event) =>
                onLetsEncryptDraftChange({
                  ...letsEncryptDraft,
                  http01Address: event.target.value
                })
              }
              placeholder={status?.letsencrypt.http01_address ?? "0.0.0.0"}
              value={letsEncryptDraft.http01Address}
            />
          </label>
          <label title="Port certbot binds to for the HTTP-01 challenge">
            <span>HTTP-01 port</span>
            <input
              disabled={!leEnabled}
              max={65535}
              min={1}
              onChange={(event) =>
                onLetsEncryptDraftChange({
                  ...letsEncryptDraft,
                  http01Port: Math.min(65535, Math.max(1, Number(event.target.value) || 80))
                })
              }
              type="number"
              value={letsEncryptDraft.http01Port}
            />
          </label>
          <label className="switch" title="Use the Let's Encrypt staging CA for test certificates">
            <input
              checked={letsEncryptDraft.staging}
              disabled={!leEnabled}
              onChange={(event) =>
                onLetsEncryptDraftChange({ ...letsEncryptDraft, staging: event.target.checked })
              }
              type="checkbox"
            />
            <span>Staging</span>
          </label>
          <label className="switch" title="Reload ocserv after issue or renew succeeds">
            <input
              checked={letsEncryptDraft.reload}
              disabled={!leEnabled}
              onChange={(event) =>
                onLetsEncryptDraftChange({ ...letsEncryptDraft, reload: event.target.checked })
              }
              type="checkbox"
            />
            <span>Reload server</span>
          </label>
          <label className="switch" title="Let supervisor run certbot renew periodically">
            <input
              checked={letsEncryptDraft.autoRenew}
              disabled={!leEnabled}
              onChange={(event) =>
                onLetsEncryptDraftChange({
                  ...letsEncryptDraft,
                  autoRenew: event.target.checked
                })
              }
              type="checkbox"
            />
            <span>Auto-renew</span>
          </label>
          <label className="renewal-interval-field" title="How often certbot should check for renewal">
            <span>Renewal check interval</span>
            <div className="compact-field">
            <input
              min={1}
              disabled={!leEnabled}
              onChange={(event) =>
                onLetsEncryptDraftChange({
                  ...letsEncryptDraft,
                  interval: Math.max(1, Number(event.target.value) || 7)
                })
              }
              type="number"
              value={letsEncryptDraft.interval}
            />
            <select
              disabled={!leEnabled}
              onChange={(event) =>
                onLetsEncryptDraftChange({
                  ...letsEncryptDraft,
                  intervalUnit: event.target.value as IntervalUnit
                })
              }
              value={letsEncryptDraft.intervalUnit}
            >
              <option value="hours">hours</option>
              <option value="days">days</option>
              <option value="weeks">weeks</option>
              <option value="months">months</option>
            </select>
            </div>
          </label>
        </div>
          <div className="panel-footer">
            <ActionButton
              label={leEnabled ? "Disable" : "Enable"}
              icon={Power}
              danger={leEnabled}
              primary={!leEnabled}
              busy={busy === "le-settings"}
              onClick={() => onSetLetsEncryptEnabled(!leEnabled)}
            />
            <ActionButton
              label="Save"
              icon={Save}
              title="Save Let's Encrypt renewal settings to persistent YAML"
              busy={busy === "le-settings"}
              disabled={!leEnabled}
              onClick={onSaveLetsEncryptSettings}
            />
            <button
              className="primary-button"
              disabled={
                busy === "le-issue" ||
                !leEnabled ||
                !status?.certbot_available ||
                !letsEncryptDraft.email ||
                leDomains.length === 0
              }
              title="Request a new Let's Encrypt certificate for the listed domains"
              type="submit"
            >
              <CheckCircle2 size={18} aria-hidden="true" />
              <span>{busy === "le-issue" ? "Working" : dryRun ? "Dry-run issue" : "Issue"}</span>
            </button>
            <ActionButton
              label={dryRun ? "Dry-run renew" : "Renew"}
              icon={RefreshCw}
              title="Run certbot renew now"
              disabled={!leEnabled || !status?.certbot_available}
              busy={busy === "le-renew"}
              onClick={onRenewLetsEncrypt}
            />
            <ActionButton
              label="View certificate"
              icon={Eye}
              disabled={!status?.letsencrypt.paths?.server_cert_exists}
              busy={busy === "letsencrypt-cert-info"}
              onClick={onShowLetsEncryptCertificateContent}
            />
          </div>
        </form>
        {status?.letsencrypt.paths && <CertificatePathsView paths={status.letsencrypt.paths} />}
      </section>
        </details>
      </SettingsTabs>

      {commandOutput && (
        <LastCommandPanel title="Last certificate command" result={commandOutput} onClose={onClearCommand} />
      )}
    </div>
  );
}
