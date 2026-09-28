import { Ban, CheckCircle2, Clock, Download, Eye, FileSliders, KeyRound, Plus, Power, QrCode, Save, Trash2, Users } from "lucide-react";
import type { FormEvent } from "react";
import type { P12Draft } from "../../app/types";
import { LastCommandPanel } from "../../components/CommandOutput";
import { PasswordGeneratorButton } from "../../components/PasswordGeneratorButton";
import { Table } from "../../components/Table";
import { EmptyState, IconButton, Pill } from "../../components/ui";
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
          <Table
            columns={[
              "Username",
              "Access",
              "Password",
              "OTP",
              "Certificate",
              "PKCS#12",
              "Config"
            ]}
            empty="No users"
          >
            {users.map((user) => {
              const p12 = p12DraftFor(p12Drafts, user.username);
              const hasOtp = otpEnabled.has(user.username);
              return (
                <tr key={user.username}>
                  <td className="strong-cell user-name-cell">{user.username}</td>
                  <td>
                    <div className="inline-tools account-tools">
                      <Pill kind={user.disabled ? "muted" : "ok"}>
                        {user.disabled ? "Disabled" : "Enabled"}
                      </Pill>
                      <IconButton
                        label={user.disabled ? "Enable user" : "Disable user"}
                        icon={user.disabled ? Power : Ban}
                        busy={busy === `${user.disabled ? "enable" : "disable"}-${user.username}`}
                        onClick={() => onEnable(user.username, user.disabled)}
                      />
                      <IconButton
                        label="Delete user"
                        icon={Trash2}
                        danger
                        busy={busy === `delete-${user.username}`}
                        onClick={() => onDelete(user.username)}
                      />
                      <IconButton
                        label="Groups"
                        icon={Users}
                        busy={busy === `user-groups-load-${user.username}`}
                        onClick={() => onOpenGroups(user.username)}
                      />
                    </div>
                  </td>
                  <td>
                    <div className="inline-tools password-tools">
                      <input
                        type="password"
                        value={passwordDrafts[user.username] ?? ""}
                        onChange={(event) =>
                          onPasswordDraftChange(user.username, event.target.value)
                        }
                        placeholder="New password"
                      />
                      <PasswordGeneratorButton
                        onApply={(password) => onPasswordDraftChange(user.username, password)}
                      />
                      <IconButton
                        label="Change password"
                        icon={KeyRound}
                        disabled={!passwordDrafts[user.username]}
                        busy={busy === `password-${user.username}`}
                        onClick={() => onChangePassword(user.username)}
                      />
                    </div>
                  </td>
                  <td>
                    <div className="inline-tools">
                      <Pill kind={hasOtp ? "ok" : "muted"}>{hasOtp ? "On" : "Off"}</Pill>
                      <IconButton
                        label="Enable OTP"
                        icon={Clock}
                        disabled={hasOtp}
                        busy={busy === `otp-on-${user.username}`}
                        onClick={() => onOtp(user.username, true)}
                      />
                      <IconButton
                        label="Disable OTP"
                        icon={Power}
                        disabled={!hasOtp}
                        busy={busy === `otp-off-${user.username}`}
                        onClick={() => onOtp(user.username, false)}
                      />
                      <IconButton
                        label="Show OTP QR"
                        icon={QrCode}
                        disabled={!hasOtp}
                        busy={busy === `otp-qr-${user.username}`}
                        onClick={() => onOtpQr(user.username)}
                      />
                    </div>
                  </td>
                  <td>
                    <div className="inline-tools">
                      <IconButton
                        label="Issue certificate"
                        icon={CheckCircle2}
                        disabled={user.certificate_exists}
                        busy={busy === `cert-${user.username}`}
                        onClick={() => onCert(user.username)}
                      />
                      <IconButton
                        label="Revoke certificate"
                        icon={Ban}
                        danger
                        disabled={!user.certificate_exists}
                        busy={busy === `revoke-cert-${user.username}`}
                        onClick={() => onRevokeCert(user.username)}
                      />
                    </div>
                  </td>
                  <td>
                    <div className="inline-tools p12-tools">
                      <input
                        type="password"
                        value={p12.passphrase}
                        onChange={(event) =>
                          onP12DraftChange(user.username, { passphrase: event.target.value })
                        }
                        placeholder="Passphrase"
                      />
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
                        <span>Apple</span>
                      </label>
                      <div className="p12-actions">
                        <IconButton
                          label="Create PKCS#12"
                          icon={Save}
                          disabled={!user.certificate_exists}
                          busy={busy === `p12-${user.username}`}
                          onClick={() => onP12(user.username)}
                        />
                        <IconButton
                          label="Download PKCS#12"
                          icon={Download}
                          disabled={!user.p12_exists}
                          busy={busy === `download-p12-${user.username}`}
                          onClick={() => onDownloadP12(user.username)}
                        />
                        <IconButton
                          label="Download certificate"
                          icon={Download}
                          disabled={!user.certificate_exists}
                          busy={busy === `download-cert-${user.username}`}
                          onClick={() => onDownloadCert(user.username)}
                        />
                        <IconButton
                          label="Download private key"
                          icon={Download}
                          disabled={!user.certificate_exists}
                          busy={busy === `download-key-${user.username}`}
                          onClick={() => onDownloadKey(user.username)}
                        />
                        <IconButton
                          label="View PKCS#12 as Base64"
                          icon={Eye}
                          disabled={!user.p12_exists}
                          busy={busy === `view-p12-base64-${user.username}`}
                          onClick={() => onViewP12Base64(user.username)}
                        />
                      </div>
                    </div>
                  </td>
                  <td>
                    <IconButton
                      label="Per-user config"
                      icon={FileSliders}
                      busy={busy === `user-config-load-${user.username}`}
                      onClick={() => onOpenConfig(user.username)}
                    />
                  </td>
                </tr>
              );
            })}
          </Table>
        </section>
      )}
      {commandOutput && (
        <LastCommandPanel title="Last user command" result={commandOutput} onClose={onClearCommand} />
      )}
    </div>
  );
}
