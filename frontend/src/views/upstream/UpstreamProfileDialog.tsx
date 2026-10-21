import { Fingerprint, Save, X } from "lucide-react";
import { type FormEvent, useState } from "react";
import { CertSourceField, type CertSourceMode } from "../../components/CertSourceField";
import { SettingsTabs } from "../../components/SettingsTabs";
import { ActionButton, IconButton } from "../../components/ui";
import type { UpstreamProfileDraft } from "../../api";

export function UpstreamProfileDialog({
  draft,
  isEdit,
  busy,
  onDraftChange,
  onClose,
  onSave,
  onFetchPin
}: {
  draft: UpstreamProfileDraft;
  // Fixed by the caller when the dialog opens (create vs. edit an existing
  // profile) -- must NOT be derived from draft.name here, which changes on
  // every keystroke and would flip a brand-new profile into "edit mode"
  // (disabling the Name field below) after the first character typed.
  isEdit: boolean;
  busy: string | null;
  onDraftChange: (value: UpstreamProfileDraft) => void;
  onClose: () => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
  onFetchPin: () => void;
}) {
  const [certMode, setCertMode] = useState<CertSourceMode>(draft.cert_file ? "path" : "base64");
  const [keyMode, setKeyMode] = useState<CertSourceMode>(draft.key_file ? "path" : "base64");
  const [certFileName, setCertFileName] = useState<string | null>(null);
  const [keyFileName, setKeyFileName] = useState<string | null>(null);
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>{isEdit ? `${draft.name} profile` : "New profile"}</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        <form className="settings-grid" onSubmit={onSave}>
          <div className="settings-grid field-full-width">
            <label>
              <span>Name</span>
              <input
                disabled={isEdit}
                title={isEdit ? "Delete and recreate the profile to rename it" : undefined}
                value={draft.name}
                onChange={(event) => onDraftChange({ ...draft, name: event.target.value })}
                required
              />
            </label>
            <label>
              <span>Kind</span>
              <select
                disabled={isEdit}
                title={isEdit ? "Delete and recreate the profile to change its kind" : undefined}
                value={draft.kind}
                onChange={(event) =>
                  onDraftChange({
                    ...draft,
                    kind: event.target.value as UpstreamProfileDraft["kind"]
                  })
                }
              >
                <option value="openconnect">OpenConnect (kornode dials out)</option>
                <option value="external_interface">Existing interface (externally managed)</option>
              </select>
            </label>
          </div>

          <div className="field-full-width">
          <SettingsTabs ariaLabel="Profile settings">
            <details className="settings-details">
              <summary>Connection &amp; auth</summary>
              <div className="settings-grid settings-details-body">
                {draft.kind === "openconnect" && (
                  <>
                    <label>
                      <span>Server</span>
                      <input
                        value={draft.server}
                        onChange={(event) => onDraftChange({ ...draft, server: event.target.value })}
                        placeholder="vpn.example.com"
                        required
                      />
                    </label>
                    <label>
                      <span>Port</span>
                      <input
                        value={draft.port}
                        onChange={(event) => onDraftChange({ ...draft, port: event.target.value })}
                        required
                      />
                    </label>
                  </>
                )}
                <label
                  title={
                    draft.kind === "external_interface"
                      ? "Device already brought up outside kornode (e.g. an externally-managed WireGuard interface). kornode never creates, brings up, or tears this down."
                      : "Tunnel device for this profile's own connection; each profile needs its own so several can stay connected at once. Leave empty for an auto-assigned name."
                  }
                >
                  <span>Interface</span>
                  <input
                    value={draft.interface}
                    onChange={(event) => onDraftChange({ ...draft, interface: event.target.value })}
                    placeholder={draft.kind === "external_interface" ? "wg0" : "auto"}
                    required={draft.kind === "external_interface"}
                  />
                </label>
                {draft.kind === "openconnect" && (
                  <>
                    <label>
                      <span>Auth</span>
                      <select
                        value={draft.auth_type}
                        onChange={(event) =>
                          onDraftChange({
                            ...draft,
                            auth_type: event.target.value as UpstreamProfileDraft["auth_type"]
                          })
                        }
                      >
                        <option value="password">Password</option>
                        <option value="cert">Certificate</option>
                        <option value="p12">PKCS#12</option>
                      </select>
                    </label>
                    <label
                      title={
                        draft.auth_type === "password"
                          ? undefined
                          : "Only if the upstream also asks for a username and password after the certificate (its ocserv combines certificate and password authentication)"
                      }
                    >
                      <span>{draft.auth_type === "password" ? "Username" : "Username (if required)"}</span>
                      <input
                        value={draft.username}
                        onChange={(event) => onDraftChange({ ...draft, username: event.target.value })}
                        required={draft.auth_type === "password"}
                      />
                    </label>
                    <label>
                      <span>{draft.auth_type === "password" ? "Password" : "Password (if required)"}</span>
                      <input
                        type="password"
                        value={draft.password}
                        placeholder={isEdit ? "Blank keeps the saved password" : undefined}
                        onChange={(event) => onDraftChange({ ...draft, password: event.target.value })}
                        required={draft.auth_type === "password" && !isEdit}
                      />
                    </label>
                    {draft.auth_type === "cert" && (
                      <>
                        <CertSourceField
                          label="Certificate"
                          mode={certMode}
                          pathValue={draft.cert_file}
                          base64Value={draft.cert_file_base64}
                          fileName={certFileName}
                          pathPlaceholder="/etc/kornode/upstream/client.crt"
                          onModeChange={setCertMode}
                          onPathChange={(value) =>
                            onDraftChange({ ...draft, cert_file: value, cert_file_base64: "" })
                          }
                          onBase64Change={(value) =>
                            onDraftChange({ ...draft, cert_file_base64: value, cert_file: "" })
                          }
                          onFileSelected={(base64, name) => {
                            setCertFileName(name);
                            onDraftChange({ ...draft, cert_file_base64: base64, cert_file: "" });
                          }}
                        />
                        <CertSourceField
                          label="Key"
                          mode={keyMode}
                          pathValue={draft.key_file}
                          base64Value={draft.key_file_base64}
                          fileName={keyFileName}
                          pathPlaceholder="/etc/kornode/upstream/client.key"
                          onModeChange={setKeyMode}
                          onPathChange={(value) =>
                            onDraftChange({ ...draft, key_file: value, key_file_base64: "" })
                          }
                          onBase64Change={(value) =>
                            onDraftChange({ ...draft, key_file_base64: value, key_file: "" })
                          }
                          onFileSelected={(base64, name) => {
                            setKeyFileName(name);
                            onDraftChange({ ...draft, key_file_base64: base64, key_file: "" });
                          }}
                        />
                        <label className="field-full-width">
                          <span>Key passphrase</span>
                          <input
                            type="password"
                            value={draft.cert_pass}
                            onChange={(event) =>
                              onDraftChange({ ...draft, cert_pass: event.target.value })
                            }
                            placeholder="only if the key is encrypted"
                          />
                        </label>
                      </>
                    )}
                    {draft.auth_type === "p12" && (
                      <>
                        <CertSourceField
                          label="PKCS#12 file"
                          mode={certMode}
                          pathValue={draft.cert_file}
                          base64Value={draft.cert_file_base64}
                          fileName={certFileName}
                          pathPlaceholder="/etc/kornode/upstream/client.p12"
                          onModeChange={setCertMode}
                          onPathChange={(value) =>
                            onDraftChange({ ...draft, cert_file: value, cert_file_base64: "" })
                          }
                          onBase64Change={(value) =>
                            onDraftChange({ ...draft, cert_file_base64: value, cert_file: "" })
                          }
                          onFileSelected={(base64, name) => {
                            setCertFileName(name);
                            onDraftChange({ ...draft, cert_file_base64: base64, cert_file: "" });
                          }}
                        />
                        <label className="field-full-width">
                          <span>P12 passphrase</span>
                          <input
                            type="password"
                            value={draft.cert_pass}
                            onChange={(event) =>
                              onDraftChange({ ...draft, cert_pass: event.target.value })
                            }
                          />
                        </label>
                      </>
                    )}
                    <div
                      className="field-label field-full-width"
                      title="Trust exactly this server certificate (openconnect --servercert). Needed when the upstream's certificate isn't signed by a public CA, e.g. another Korvus Node with its own CA."
                    >
                      <span id="upstream-server-cert-pin-label">Server cert pin</span>
                      <div className="field-with-action">
                        <input
                          aria-labelledby="upstream-server-cert-pin-label"
                          value={draft.server_cert_pin}
                          onChange={(event) =>
                            onDraftChange({ ...draft, server_cert_pin: event.target.value })
                          }
                          placeholder="pin-sha256:..."
                        />
                        <ActionButton
                          label="Fetch"
                          icon={Fingerprint}
                          busy={busy === "upstream-fetch-pin"}
                          disabled={!draft.server.trim()}
                          title="Read the certificate the server presents and pin it after you confirm"
                          onClick={onFetchPin}
                          data-capability="upstream.fetch_pin"
                        />
                      </div>
                      <p className="field-help">
                        The pin follows the server's key, not the certificate, so renewals that
                        keep the key (Korvus Node does, including Let's Encrypt) don't break it.
                        To have no pin to maintain at all, leave this empty and enable "No cert
                        check": the current certificate is then accepted automatically on every
                        connect (a key change is only logged).
                      </p>
                    </div>
                    <label
                      className="field-full-width"
                      title="Optional: only if the upstream ocserv server has camouflage enabled"
                    >
                      <span>Camouflage secret</span>
                      <input
                        value={draft.camouflage_secret}
                        onChange={(event) =>
                          onDraftChange({ ...draft, camouflage_secret: event.target.value })
                        }
                        placeholder={isEdit ? "leave blank to keep existing" : "optional"}
                      />
                    </label>
                  </>
                )}
              </div>
            </details>
          </SettingsTabs>
          </div>

          <div className="profile-status-switches">
            {draft.kind === "openconnect" && (
              <label
                className="switch"
                title="Automatic mode: accept whatever certificate the server presents at each connect, so a changed upstream certificate never breaks the connection (a key change is logged). No protection against a man-in-the-middle. Ignored when Server cert pin is set."
              >
                <input
                  checked={draft.trusted_cert}
                  onChange={(event) => onDraftChange({ ...draft, trusted_cert: event.target.checked })}
                  type="checkbox"
                />
                <span>No cert check</span>
              </label>
            )}
            <label
              className="switch"
              title="This profile only -- not the whole Upstream profiles feature (see the toggle above for that). Whether the watchdog keeps THIS specific profile dialed. Off disconnects it (if it's the default profile, that also clears the default selection) and keeps the watchdog from redialing it -- independent of failover, which only controls automatic switching."
            >
              <input
                checked={draft.enabled}
                onChange={(event) => onDraftChange({ ...draft, enabled: event.target.checked })}
                type="checkbox"
              />
              <span>This profile enabled</span>
            </label>
          </div>
          <div className="modal-actions">
            <button
              className="primary-button"
              disabled={busy === "upstream-profile"}
              type="submit"
              data-capability="upstream.profile.save"
            >
              <Save size={18} aria-hidden="true" />
              <span>Save profile</span>
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
