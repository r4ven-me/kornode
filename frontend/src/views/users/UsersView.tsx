import { Ban, CheckCircle2, Clock, Download, Eye, FileSliders, KeyRound, Plus, Power, QrCode, Save, Trash2, Users } from "lucide-react";
import type { FormEvent } from "react";
import type { P12Draft } from "../../app/types";
import { LastCommandPanel } from "../../components/CommandOutput";
import { PasswordGeneratorButton } from "../../components/PasswordGeneratorButton";
import { ActionButton, EmptyState, Pill } from "../../components/ui";
import { p12DraftFor } from "../../lib/userConfig";
import type { CommandResult, OtpRecord, UserRecord } from "../../api";

export function UsersView({
  users,
  otpRecords,
  busy,
  newUser,
  passwordDrafts,
  p12Drafts,
  commandOutput,
  onClearCommand,
  onNewUserChange,
  onPasswordDraftChange,
  onP12DraftChange,
  onCreate,
  onChangePassword,
  onEnable,
  onDelete,
  onOtp,
  onOtpQr,
  onCert,
  onRevokeCert,
  onP12,
  onDownloadP12,
  onDownloadCert,
  onDownloadKey,
  onViewP12Base64,
  onOpenConfig,
  onOpenGroups
}: {
  users: UserRecord[];
  otpRecords: OtpRecord[];
  busy: string | null;
  newUser: { username: string; password: string };
  passwordDrafts: Record<string, string>;
  p12Drafts: Record<string, P12Draft>;
  commandOutput: CommandResult | CommandResult[] | null;
  onClearCommand: () => void;
  onNewUserChange: (value: { username: string; password: string }) => void;
  onPasswordDraftChange: (username: string, value: string) => void;
  onP12DraftChange: (username: string, value: Partial<P12Draft>) => void;
  onCreate: (event: FormEvent<HTMLFormElement>) => void;
  onChangePassword: (username: string) => void;
  onEnable: (username: string, enabled: boolean) => void;
  onDelete: (username: string) => void;
  onOtp: (username: string, enabled: boolean) => void;
  onOtpQr: (username: string) => void;
  onCert: (username: string) => void;
  onRevokeCert: (username: string) => void;
  onP12: (username: string) => void;
  onDownloadP12: (username: string) => void;
  onDownloadCert: (username: string) => void;
  onDownloadKey: (username: string) => void;
  onViewP12Base64: (username: string) => void;
  onOpenConfig: (username: string) => void;
  onOpenGroups: (username: string) => void;
}) {
  const otpEnabled = new Set(otpRecords.map((record) => record.username));
  return (
    <div className="view-stack">
      <section className="panel user-create-panel">
        <div className="panel-header">
          <div>
            <h2>Add user</h2>
            <p className="muted-line">Create an account, then open it below to manage access and credentials.</p>
          </div>
        </div>
        <form className="inline-form" onSubmit={onCreate}>
          <label>
            <span>Username</span>
            <input
              value={newUser.username}
              onChange={(event) => onNewUserChange({ ...newUser, username: event.target.value })}
              required
            />
          </label>
          <div className="inline-tools password-tools password-tools-compact">
            <label>
              <span>Password</span>
              <input
                type="password"
                value={newUser.password}
                onChange={(event) => onNewUserChange({ ...newUser, password: event.target.value })}
                required
              />
            </label>
            <PasswordGeneratorButton
              onApply={(password) => onNewUserChange({ ...newUser, password })}
            />
          </div>
          <button className="primary-button" disabled={busy === "create-user"} type="submit">
            <Plus size={18} aria-hidden="true" />
            <span>Create</span>
          </button>
        </form>
      </section>

      {users.length === 0 ? (
        <section className="panel">
          <EmptyState text="No users" />
        </section>
      ) : (
        <section className="panel users-panel">
          <div className="panel-header">
            <div>
              <h2>User accounts</h2>
              <p className="muted-line">Open an account to manage its password, OTP and certificates.</p>
            </div>
            <Pill kind="muted">{users.length}</Pill>
          </div>
          <div className="user-card-list">
            {users.map((user) => {
              const p12 = p12DraftFor(p12Drafts, user.username);
              const hasOtp = otpEnabled.has(user.username);
              return (
                <details className="user-card" key={user.username}>
                  <summary>
                    <div className="user-card-identity">
                      <strong>{user.username}</strong>
                      <div className="user-card-statuses">
                        <Pill kind={user.disabled ? "muted" : "ok"}>
                          {user.disabled ? "Disabled" : "Enabled"}
                        </Pill>
                        <Pill kind={hasOtp ? "ok" : "muted"}>OTP {hasOtp ? "on" : "off"}</Pill>
                        <Pill kind={user.certificate_exists ? "ok" : "muted"}>
                          Certificate {user.certificate_exists ? "ready" : "missing"}
                        </Pill>
                      </div>
                    </div>
                    <span className="user-card-disclosure">Manage</span>
                  </summary>
                  <div className="user-card-body">
                    <section className="user-management-section user-account-section">
                      <h3>Account</h3>
                      <div className="user-action-row">
                        <ActionButton
                          label={user.disabled ? "Enable user" : "Disable user"}
                          icon={user.disabled ? Power : Ban}
                          busy={busy === `${user.disabled ? "enable" : "disable"}-${user.username}`}
                          onClick={() => onEnable(user.username, user.disabled)}
                        />
                        <ActionButton
                          label="Groups"
                          icon={Users}
                          busy={busy === `user-groups-load-${user.username}`}
                          onClick={() => onOpenGroups(user.username)}
                        />
                        <ActionButton
                          label="Per-user config"
                          icon={FileSliders}
                          busy={busy === `user-config-load-${user.username}`}
                          onClick={() => onOpenConfig(user.username)}
                        />
                        <ActionButton
                          label="Delete user"
                          icon={Trash2}
                          danger
                          busy={busy === `delete-${user.username}`}
                          onClick={() => onDelete(user.username)}
                        />
                      </div>
                    </section>

                    <section className="user-management-section">
                      <h3>Password</h3>
                      <div className="inline-tools password-tools">
                        <label className="user-secret-field">
                          <span>New password</span>
                          <input
                            aria-label={`New password for ${user.username}`}
                            type="password"
                            value={passwordDrafts[user.username] ?? ""}
                            onChange={(event) =>
                              onPasswordDraftChange(user.username, event.target.value)
                            }
                          />
                        </label>
                        <PasswordGeneratorButton
                          onApply={(password) => onPasswordDraftChange(user.username, password)}
                        />
                        <ActionButton
                          label="Change password"
                          icon={KeyRound}
                          disabled={!passwordDrafts[user.username]}
                          busy={busy === `password-${user.username}`}
                          onClick={() => onChangePassword(user.username)}
                        />
                      </div>
                    </section>

                    <section className="user-management-section">
                      <div className="user-section-heading">
                        <h3>One-time password</h3>
                        <Pill kind={hasOtp ? "ok" : "muted"}>{hasOtp ? "On" : "Off"}</Pill>
                      </div>
                      <div className="user-action-row">
                        <ActionButton
                          label="Enable OTP"
                          icon={Clock}
                          disabled={hasOtp}
                          busy={busy === `otp-on-${user.username}`}
                          onClick={() => onOtp(user.username, true)}
                        />
                        <ActionButton
                          label="Disable OTP"
                          icon={Power}
                          disabled={!hasOtp}
                          busy={busy === `otp-off-${user.username}`}
                          onClick={() => onOtp(user.username, false)}
                        />
                        <ActionButton
                          label="Show OTP QR"
                          icon={QrCode}
                          disabled={!hasOtp}
                          busy={busy === `otp-qr-${user.username}`}
                          onClick={() => onOtpQr(user.username)}
                        />
                      </div>
                    </section>

                    <section className="user-management-section">
                      <div className="user-section-heading">
                        <h3>Certificate</h3>
                        <Pill kind={user.certificate_exists ? "ok" : "muted"}>
                          {user.certificate_exists ? "Issued" : "Missing"}
                        </Pill>
                      </div>
                      <div className="user-action-row">
                        <ActionButton
                          label="Issue certificate"
                          icon={CheckCircle2}
                          disabled={user.certificate_exists}
                          busy={busy === `cert-${user.username}`}
                          onClick={() => onCert(user.username)}
                        />
                        <ActionButton
                          label="Revoke certificate"
                          icon={Ban}
                          danger
                          disabled={!user.certificate_exists}
                          busy={busy === `revoke-cert-${user.username}`}
                          onClick={() => onRevokeCert(user.username)}
                        />
                        <ActionButton
                          label="Download certificate"
                          icon={Download}
                          disabled={!user.certificate_exists}
                          busy={busy === `download-cert-${user.username}`}
                          onClick={() => onDownloadCert(user.username)}
                        />
                        <ActionButton
                          label="Download private key"
                          icon={Download}
                          disabled={!user.certificate_exists}
                          busy={busy === `download-key-${user.username}`}
                          onClick={() => onDownloadKey(user.username)}
                        />
                      </div>
                    </section>

                    <section className="user-management-section user-p12-section">
                      <div className="user-section-heading">
                        <h3>PKCS#12 bundle</h3>
                        <Pill kind={user.p12_exists ? "ok" : "muted"}>
                          {user.p12_exists ? "Ready" : "Not created"}
                        </Pill>
                      </div>
                      <div className="user-p12-tools">
                        <label className="user-secret-field">
                          <span>Passphrase</span>
                          <input
                            aria-label={`PKCS#12 passphrase for ${user.username}`}
                            type="password"
                            value={p12.passphrase}
                            onChange={(event) =>
                              onP12DraftChange(user.username, { passphrase: event.target.value })
                            }
                          />
                        </label>
                        <PasswordGeneratorButton
                          onApply={(password) =>
                            onP12DraftChange(user.username, { passphrase: password })
                          }
                        />
                        <label
                          className="mini-check"
                          title="Generate a macOS/iOS-compatible PKCS#12 bundle"
                        >
                          <input
                            checked={p12.appleCompatible}
                            onChange={(event) =>
                              onP12DraftChange(user.username, {
                                appleCompatible: event.target.checked
                              })
                            }
                            type="checkbox"
                          />
                          <span>Apple compatible</span>
                        </label>
                      </div>
                      <div className="user-action-row">
                        <ActionButton
                          label="Create PKCS#12"
                          icon={Save}
                          primary
                          disabled={!user.certificate_exists}
                          busy={busy === `p12-${user.username}`}
                          onClick={() => onP12(user.username)}
                        />
                        <ActionButton
                          label="Download PKCS#12"
                          icon={Download}
                          disabled={!user.p12_exists}
                          busy={busy === `download-p12-${user.username}`}
                          onClick={() => onDownloadP12(user.username)}
                        />
                        <ActionButton
                          label="View as Base64"
                          icon={Eye}
                          disabled={!user.p12_exists}
                          busy={busy === `view-p12-base64-${user.username}`}
                          onClick={() => onViewP12Base64(user.username)}
                        />
                      </div>
                    </section>
                  </div>
                </details>
              );
            })}
          </div>
        </section>
      )}
      {commandOutput && (
        <LastCommandPanel title="Last user command" result={commandOutput} onClose={onClearCommand} />
      )}
    </div>
  );
}
