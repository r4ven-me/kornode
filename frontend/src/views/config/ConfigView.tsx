import { CheckCircle2, FileDiff, RefreshCw, Save, Send } from "lucide-react";
import type { ConfigSection } from "../../app/types";
import { KorclientHint } from "../../components/KorclientHint";
import { SettingsTabs } from "../../components/SettingsTabs";
import { ActionButton, EmptyState, Pill } from "../../components/ui";
import type { AuthMethodsDraft, GeneralSettingsDraft, ServerSettingsDraft, WebSettingsDraft } from "../../lib/drafts";
import { AdminTotpPanel } from "./AdminTotpPanel";
import { type ConfigSource } from "../../api";

export function ConfigView({
  section,
  config,
  source,
  draft,
  dirty,
  rendered,
  diff,
  validation,
  serverSettingsDraft,
  authMethodsDraft,
  webSettingsDraft,
  generalSettingsDraft,
  onServerSettingsDraftChange,
  onAuthMethodsDraftChange,
  onWebSettingsDraftChange,
  onGeneralSettingsDraftChange,
  onSaveServerSettings,
  onSaveAuthMethodsSettings,
  onTestOtpEmail,
  onTestOtpTelegram,
  onSaveWebSettings,
  onSaveGeneralSettings,
  busy,
  onDraftChange,
  onReloadSource,
  onRender,
  onValidate,
  onDiff,
  onSave,
  onWrite,
  onNotice
}: {
  section: ConfigSection;
  config: Record<string, unknown> | null;
  source: ConfigSource | null;
  draft: string;
  dirty: boolean;
  rendered: Record<string, string>;
  diff: string;
  validation: string;
  serverSettingsDraft: ServerSettingsDraft;
  authMethodsDraft: AuthMethodsDraft;
  webSettingsDraft: WebSettingsDraft;
  generalSettingsDraft: GeneralSettingsDraft;
  onServerSettingsDraftChange: (value: ServerSettingsDraft) => void;
  onAuthMethodsDraftChange: (value: AuthMethodsDraft) => void;
  onWebSettingsDraftChange: (value: WebSettingsDraft) => void;
  onGeneralSettingsDraftChange: (value: GeneralSettingsDraft) => void;
  onSaveServerSettings: () => void;
  onSaveAuthMethodsSettings: () => void;
  onTestOtpEmail: () => void;
  onTestOtpTelegram: () => void;
  onSaveWebSettings: () => void;
  onSaveGeneralSettings: () => void;
  busy: string | null;
  onDraftChange: (value: string) => void;
  onReloadSource: () => void;
  onRender: () => void;
  onValidate: () => void;
  onDiff: () => void;
  onSave: () => void;
  onWrite: () => void;
  onNotice: (kind: "ok" | "warning" | "error", text: string) => void;
}) {
  return (
    <div className="view-stack">
      {section === "server" && (
      <section className="panel config-section-panel">
        <div className="panel-header config-section-header">
          <div>
            <h2>VPN server</h2>
            <p className="muted-line">Listener, client network and ocserv behavior.</p>
          </div>
          <label className="switch" title="Whether ocserv itself runs in this container">
            <input checked={serverSettingsDraft.enabled} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, enabled: event.target.checked })} type="checkbox" />
            <span>Enabled</span>
          </label>
        </div>

        {!serverSettingsDraft.enabled && <p className="config-disabled-note">Enable the VPN server to edit its dependent settings.</p>}
        {serverSettingsDraft.enabled && (
          <SettingsTabs ariaLabel="VPN server settings">
            <details className="settings-details">
              <summary>Listener &amp; identity</summary>
              <div className="settings-grid settings-details-body">
                <label><span>Listen address</span><input value={serverSettingsDraft.listen} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, listen: event.target.value })} /></label>
                <label><span>Port</span><input type="number" min={1} max={65535} value={serverSettingsDraft.port} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, port: Math.max(1, Number(event.target.value) || 443) })} /></label>
                <label className="switch"><input checked={serverSettingsDraft.udpEnabled} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, udpEnabled: event.target.checked })} type="checkbox" /><span>Enable UDP transport</span></label>
                <label><span>TUN device</span><input value={serverSettingsDraft.device} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, device: event.target.value })} /></label>
                <label><span>Common name</span><input value={serverSettingsDraft.cn} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, cn: event.target.value })} /></label>
                <label><span>Authentication realm</span><input value={serverSettingsDraft.realm} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, realm: event.target.value })} /></label>
              </div>
            </details>

            <details className="settings-details">
              <summary>Client network</summary>
              <div className="settings-grid settings-details-body">
                <label><span>IPv4 network</span><input value={serverSettingsDraft.ipv4Network} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, ipv4Network: event.target.value })} /></label>
                <label><span>DNS servers (one per line)</span><textarea rows={3} value={serverSettingsDraft.dns} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, dns: event.target.value })} /></label>
                <label><span>Search domains <KorclientHint text="Also used as the server-wide split-DNS list. A Korvus client resolves these through its own dnsmasq; stock OpenConnect clients receive DNS suffix scoping." /></span><textarea rows={3} value={serverSettingsDraft.searchDomains} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, searchDomains: event.target.value })} /></label>
                <label><span>Routes <KorclientHint text="A Korvus client applies these through nftables policy routing. Stock OpenConnect clients receive plain pushed routes." /></span><textarea rows={3} value={serverSettingsDraft.routes} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, routes: event.target.value })} /></label>
                <label><span>Excluded routes</span><textarea rows={3} value={serverSettingsDraft.noRoutes} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, noRoutes: event.target.value })} /></label>
              </div>
            </details>

            <details className="settings-details">
              <summary>Limits &amp; compatibility</summary>
              <div className="settings-grid settings-details-body">
                <label><span>Maximum clients</span><input type="number" min={1} value={serverSettingsDraft.maxClients} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, maxClients: Math.max(1, Number(event.target.value) || 128) })} /></label>
                <label><span>Maximum sessions per user</span><input type="number" min={1} value={serverSettingsDraft.maxSameClients} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, maxSameClients: Math.max(1, Number(event.target.value) || 2) })} /></label>
                <label><span>Keepalive (seconds)</span><input type="number" min={0} value={serverSettingsDraft.keepalive} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, keepalive: Math.max(0, Number(event.target.value) || 32400) })} /></label>
                <label title="0-1: errors only. 2: connect/disconnect events. 3+: verbose debug."><span>Debug level (0-9)</span><input type="number" min={0} max={9} value={serverSettingsDraft.debugLevel} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, debugLevel: Math.min(9, Math.max(0, Number(event.target.value) || 0)) })} /></label>
                <label className="switch"><input checked={serverSettingsDraft.compression} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, compression: event.target.checked })} type="checkbox" /><span>Enable compression</span></label>
                <label className="switch"><input checked={serverSettingsDraft.ciscoClientCompat} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, ciscoClientCompat: event.target.checked })} type="checkbox" /><span>Cisco client compatibility</span></label>
              </div>
            </details>

            <details className="settings-details">
              <summary>Timing, rekeying &amp; ban policy</summary>
              <div className="settings-grid settings-details-body">
                <label><span>DPD interval (seconds)</span><input type="number" min={0} value={serverSettingsDraft.dpd} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, dpd: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Mobile DPD interval (seconds)</span><input type="number" min={0} value={serverSettingsDraft.mobileDpd} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, mobileDpd: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Rate limit (ms)</span><input type="number" min={0} value={serverSettingsDraft.rateLimitMs} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, rateLimitMs: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Server stats reset time (seconds)</span><input type="number" min={0} value={serverSettingsDraft.serverStatsResetTime} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, serverStatsResetTime: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Switch-to-TCP timeout (seconds)</span><input type="number" min={0} value={serverSettingsDraft.switchToTcpTimeout} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, switchToTcpTimeout: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Auth timeout (seconds)</span><input type="number" min={0} value={serverSettingsDraft.authTimeout} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, authTimeout: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Cookie timeout (seconds)</span><input type="number" min={0} value={serverSettingsDraft.cookieTimeout} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, cookieTimeout: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Rekey time (seconds)</span><input type="number" min={0} value={serverSettingsDraft.rekeyTime} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, rekeyTime: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Rekey method</span>
                  <select value={serverSettingsDraft.rekeyMethod} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, rekeyMethod: event.target.value === "new-tunnel" ? "new-tunnel" : "ssl" })}>
                    <option value="ssl">ssl</option>
                    <option value="new-tunnel">new-tunnel</option>
                  </select>
                </label>
                <label><span>Ban time (seconds)</span><input type="number" min={0} value={serverSettingsDraft.banTime} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, banTime: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Max ban score</span><input type="number" min={0} value={serverSettingsDraft.maxBanScore} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, maxBanScore: Math.max(0, Number(event.target.value) || 0) })} /></label>
                <label><span>Ban reset time (seconds)</span><input type="number" min={0} value={serverSettingsDraft.banResetTime} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, banResetTime: Math.max(0, Number(event.target.value) || 0) })} /></label>
              </div>
            </details>

            <details className="settings-details">
              <summary>Advanced flags &amp; TLS</summary>
              <div className="settings-grid settings-details-body">
                <label className="switch"><input checked={serverSettingsDraft.isolateWorkers} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, isolateWorkers: event.target.checked })} type="checkbox" /><span>Isolate worker processes</span></label>
                <label className="switch"><input checked={serverSettingsDraft.tryMtuDiscovery} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, tryMtuDiscovery: event.target.checked })} type="checkbox" /><span>Try MTU discovery</span></label>
                <label className="switch"><input checked={serverSettingsDraft.predictableIps} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, predictableIps: event.target.checked })} type="checkbox" /><span>Predictable client IPs</span></label>
                <label className="switch"><input checked={serverSettingsDraft.denyRoaming} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, denyRoaming: event.target.checked })} type="checkbox" /><span>Deny roaming</span></label>
                <label className="switch"><input checked={serverSettingsDraft.pingLeases} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, pingLeases: event.target.checked })} type="checkbox" /><span>Ping leases before reuse</span></label>
                <label className="switch"><input checked={serverSettingsDraft.dtlsLegacy} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, dtlsLegacy: event.target.checked })} type="checkbox" /><span>DTLS legacy compatibility</span></label>
                <label className="switch"><input checked={serverSettingsDraft.clientBypassProtocol} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, clientBypassProtocol: event.target.checked })} type="checkbox" /><span>Client bypass protocol</span></label>
                <label title="Certificate field ocserv reads the username from. Changing this requires re-issuing user certificates with a matching field."><span>Cert user OID</span><input value={serverSettingsDraft.certUserOid} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, certUserOid: event.target.value })} /></label>
                <label><span>TLS priorities</span><input placeholder="NORMAL:%SERVER_PRECEDENCE:..." value={serverSettingsDraft.tlsPriorities} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, tlsPriorities: event.target.value })} /></label>
              </div>
            </details>

            <details className="settings-details">
              <summary>Hooks &amp; camouflage</summary>
              <div className="settings-grid settings-details-body">
                <label><span>Connect script</span><input value={serverSettingsDraft.connectScript} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, connectScript: event.target.value })} /></label>
                <label><span>Disconnect script</span><input value={serverSettingsDraft.disconnectScript} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, disconnectScript: event.target.value })} /></label>
                <label className="switch"><input checked={serverSettingsDraft.camouflageEnabled} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, camouflageEnabled: event.target.checked })} type="checkbox" /><span>Enable HTTP camouflage</span></label>
                <fieldset className="settings-grid nested-fieldset" disabled={!serverSettingsDraft.camouflageEnabled}>
                  <label><span>Camouflage secret</span><input value={serverSettingsDraft.camouflageSecret} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, camouflageSecret: event.target.value })} /></label>
                  <label><span>Camouflage realm</span><input value={serverSettingsDraft.camouflageRealm} onChange={(event) => onServerSettingsDraftChange({ ...serverSettingsDraft, camouflageRealm: event.target.value })} /></label>
                </fieldset>
              </div>
            </details>
          </SettingsTabs>
        )}

        <div className="panel-footer config-save-footer">
          <ActionButton label="Save" icon={Save} primary busy={busy === "server-config-settings"} onClick={onSaveServerSettings} />
        </div>
      </section>
      )}

      {section === "auth" && (
      <section className="panel auth-settings-panel">
        <div className="panel-header">
          <h2>Authentication methods</h2>
        </div>

        <div className="settings-grid auth-method-switches">
          <label className="switch">
            <input checked={authMethodsDraft.passwordEnabled} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, passwordEnabled: event.target.checked })} type="checkbox" />
            <span>Password auth</span>
          </label>
          <label className="switch">
            <input checked={authMethodsDraft.certificateEnabled} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, certificateEnabled: event.target.checked })} type="checkbox" />
            <span>Certificate auth</span>
          </label>
          <label className="switch">
            <input checked={authMethodsDraft.otpEnabled} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpEnabled: event.target.checked })} type="checkbox" />
            <span>OTP</span>
          </label>
        </div>
        <p className="field-help">
          Enabled methods are all required at once: with both password and certificate on, clients must
          present a certificate and a password. Changing the methods restarts ocserv, which disconnects the
          active VPN sessions.
        </p>

        {authMethodsDraft.otpEnabled && (
          <div className="collapsible-settings-list">
            <section className="settings-tab-panel otp-configuration-body">
              <div className="settings-grid">
                <div className="field-heading">
                  <strong>OTP configuration</strong>
                  <span className="muted-line">OTP secret management is enabled. Runtime enforcement is configured below.</span>
                </div>
              </div>
              <div className="settings-details-body otp-configuration-body">
                <div className="settings-grid">
                  <label className="switch" title="Use ocserv's built-in oath auth backend for OTP">
                    <input checked={authMethodsDraft.otpOcservOathAuth} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpOcservOathAuth: event.target.checked })} type="checkbox" />
                    <span>Require OTP during VPN login (ocserv OATH backend)</span>
                  </label>
                  <label>
                    <span>OTP issuer</span>
                    <input value={authMethodsDraft.otpIssuer} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpIssuer: event.target.value })} />
                  </label>
                </div>

                <SettingsTabs ariaLabel="OTP delivery channels">
                <details className="settings-details nested-settings-details">
                  <summary>Email delivery</summary>
                  <div className="settings-details-body">
                    <label className="switch">
                      <input checked={authMethodsDraft.otpSendByEmail} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSendByEmail: event.target.checked })} type="checkbox" />
                      <span>Enable email delivery</span>
                    </label>
                    <fieldset disabled={!authMethodsDraft.otpSendByEmail}>
                      <div className="settings-grid otp-delivery-grid">
                        <label><span>SMTP host</span><input value={authMethodsDraft.otpSmtpHost} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSmtpHost: event.target.value })} /></label>
                        <label><span>SMTP port</span><input min={1} max={65535} type="number" value={authMethodsDraft.otpSmtpPort} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSmtpPort: Number(event.target.value) })} /></label>
                        <label><span>SMTP username</span><input value={authMethodsDraft.otpSmtpUsername} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSmtpUsername: event.target.value })} /></label>
                        <label><span>SMTP password</span><input type="password" placeholder="Blank preserves saved secret" value={authMethodsDraft.otpSmtpPassword} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSmtpPassword: event.target.value })} /></label>
                        <label><span>From address</span><input type="email" value={authMethodsDraft.otpSmtpFrom} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSmtpFrom: event.target.value })} /></label>
                        <label className="switch"><input checked={authMethodsDraft.otpSmtpStarttls} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSmtpStarttls: event.target.checked })} type="checkbox" /><span>Use STARTTLS</span></label>
                        <label><span>Test recipient</span><input type="email" value={authMethodsDraft.otpSmtpTestRecipient} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSmtpTestRecipient: event.target.value })} /></label>
                      </div>
                    </fieldset>
                    <div className="settings-actions">
                      <ActionButton label="Test email" icon={Send} busy={busy === "auth-methods-test-email"} disabled={!authMethodsDraft.otpSendByEmail || !authMethodsDraft.otpSmtpHost.trim() || authMethodsDraft.otpSmtpPort < 1 || authMethodsDraft.otpSmtpPort > 65535 || !authMethodsDraft.otpSmtpFrom.trim() || !authMethodsDraft.otpSmtpTestRecipient.trim()} onClick={onTestOtpEmail} />
                    </div>
                  </div>
                </details>

                <details className="settings-details nested-settings-details">
                  <summary>Telegram delivery</summary>
                  <div className="settings-details-body">
                    <label className="switch">
                      <input checked={authMethodsDraft.otpSendByTelegram} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpSendByTelegram: event.target.checked })} type="checkbox" />
                      <span>Enable Telegram delivery</span>
                    </label>
                    <fieldset disabled={!authMethodsDraft.otpSendByTelegram}>
                      <div className="settings-grid otp-delivery-grid">
                        <label><span>Telegram bot token</span><input type="password" placeholder="Blank preserves saved secret" value={authMethodsDraft.otpTelegramBotToken} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpTelegramBotToken: event.target.value })} /></label>
                        <label><span>Telegram chat ID</span><input value={authMethodsDraft.otpTelegramChatId} onChange={(event) => onAuthMethodsDraftChange({ ...authMethodsDraft, otpTelegramChatId: event.target.value })} /></label>
                      </div>
                    </fieldset>
                    <div className="settings-actions">
                      <ActionButton label="Test Telegram" icon={Send} busy={busy === "auth-methods-test-telegram"} disabled={!authMethodsDraft.otpSendByTelegram || !authMethodsDraft.otpTelegramBotToken || !authMethodsDraft.otpTelegramChatId.trim()} onClick={onTestOtpTelegram} />
                    </div>
                  </div>
                </details>
                </SettingsTabs>
              </div>
            </section>
          </div>
        )}

        <div className="panel-footer">
          <ActionButton label="Save" icon={Save} primary busy={busy === "auth-methods-settings"} onClick={onSaveAuthMethodsSettings} />
        </div>
      </section>
      )}

      {section === "web" && (
      <>
      <section className="panel config-section-panel">
        <div className="panel-header config-section-header">
          <div>
            <h2>Web / API panel</h2>
            <p className="muted-line">Admin panel listener, sessions and browser terminal.</p>
          </div>
          <label className="switch">
            <input checked={webSettingsDraft.enabled} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, enabled: event.target.checked })} type="checkbox" />
            <span>Enabled</span>
          </label>
        </div>

        {!webSettingsDraft.enabled && <p className="config-disabled-note">Enable the Web / API panel to edit its dependent settings.</p>}
        {webSettingsDraft.enabled && (
          <SettingsTabs ariaLabel="Web and API settings">
            <details className="settings-details">
              <summary>Listener &amp; transport security</summary>
              <div className="settings-grid settings-details-body">
                <label><span>Listen address</span><input value={webSettingsDraft.listen} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, listen: event.target.value })} /></label>
                <label><span>Port</span><input type="number" min={1} max={65535} value={webSettingsDraft.port} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, port: Math.max(1, Number(event.target.value) || 8443) })} /></label>
                <label className="switch"><input checked={webSettingsDraft.tls} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, tls: event.target.checked })} type="checkbox" /><span>Enable TLS</span></label>
                <label className="switch" title="Only for use behind a trusted TLS-terminating reverse proxy"><input checked={webSettingsDraft.allowInsecureHttp} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, allowInsecureHttp: event.target.checked })} type="checkbox" /><span>Allow insecure HTTP</span></label>
                <label><span>Trusted proxies (one per line)</span><textarea rows={3} value={webSettingsDraft.trustedProxies} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, trustedProxies: event.target.value })} /></label>
              </div>
            </details>

            <details className="settings-details">
              <summary>Administrator &amp; sessions</summary>
              <div className="settings-grid settings-details-body">
                <label><span>Admin username</span><input value={webSettingsDraft.adminUser} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, adminUser: event.target.value })} /></label>
                <label><span>Session lifetime (seconds)</span><input type="number" min={300} value={webSettingsDraft.sessionLifetime} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, sessionLifetime: Math.max(300, Number(event.target.value) || 43200) })} /></label>
                <label className="switch"><input checked={webSettingsDraft.sessionCookieSecure} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, sessionCookieSecure: event.target.checked })} type="checkbox" /><span>Secure session cookie</span></label>
              </div>
            </details>

            <details className="settings-details">
              <summary>Browser terminal</summary>
              <div className="settings-details-body">
                <label className="switch"><input checked={webSettingsDraft.terminalEnabled} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, terminalEnabled: event.target.checked })} type="checkbox" /><span>Enable browser terminal</span></label>
                <fieldset className="settings-grid nested-fieldset" disabled={!webSettingsDraft.terminalEnabled}>
                  <label><span>Idle timeout (seconds)</span><input type="number" min={60} value={webSettingsDraft.terminalIdleTimeout} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, terminalIdleTimeout: Math.max(60, Number(event.target.value) || 900) })} /></label>
                  <label><span>Maximum sessions</span><input type="number" min={1} value={webSettingsDraft.terminalMaxSessions} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, terminalMaxSessions: Math.max(1, Number(event.target.value) || 2) })} /></label>
                </fieldset>
              </div>
            </details>

            <details className="settings-details">
              <summary>Client routing sync</summary>
              <div className="settings-details-body">
                <label className="switch" title="Serves GET /api/client/routing -- polled by upstream profiles' sync_url (kornode-as-client or Korvus Client) for mid-session route/split-DNS refresh. No admin auth (VPN clients authenticate by session source IP); off by default so enabling the admin panel alone never exposes it.">
                  <input checked={webSettingsDraft.clientSyncEnabled} onChange={(event) => onWebSettingsDraftChange({ ...webSettingsDraft, clientSyncEnabled: event.target.checked })} type="checkbox" />
                  <span>Serve client routing sync</span>
                </label>
              </div>
            </details>
          </SettingsTabs>
        )}

        <div className="panel-footer config-save-footer">
          <ActionButton label="Save" icon={Save} primary busy={busy === "web-config-settings"} onClick={onSaveWebSettings} />
        </div>
      </section>
      <AdminTotpPanel onNotice={onNotice} />
      </>
      )}

      {section === "system" && (
      <section className="panel">
        <div className="panel-header">
          <h2>General</h2>
        </div>
        <div className="settings-grid">
          <label>
            <span>Timezone</span>
            <input
              value={generalSettingsDraft.timezone}
              onChange={(event) =>
                onGeneralSettingsDraftChange({
                  ...generalSettingsDraft,
                  timezone: event.target.value
                })
              }
            />
          </label>
          <label>
            <span>Log level</span>
            <select
              value={generalSettingsDraft.logLevel}
              onChange={(event) =>
                onGeneralSettingsDraftChange({
                  ...generalSettingsDraft,
                  logLevel: event.target.value as GeneralSettingsDraft["logLevel"]
                })
              }
            >
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="error">Error</option>
            </select>
          </label>
          <label>
            <span>Project name</span>
            <input
              value={generalSettingsDraft.projectName}
              onChange={(event) =>
                onGeneralSettingsDraftChange({
                  ...generalSettingsDraft,
                  projectName: event.target.value
                })
              }
            />
          </label>
          <label className="switch" title="Enable the korctl CLI inside the container">
            <input
              checked={generalSettingsDraft.cliEnabled}
              onChange={(event) =>
                onGeneralSettingsDraftChange({
                  ...generalSettingsDraft,
                  cliEnabled: event.target.checked
                })
              }
              type="checkbox"
            />
            <span>CLI enabled</span>
          </label>
        </div>
        <div className="panel-footer">
          <ActionButton
            label="Save"
            icon={Save}
            primary
            busy={busy === "general-settings"}
            onClick={onSaveGeneralSettings}
          />
        </div>
      </section>
      )}

      {section === "advanced" && (
      <SettingsTabs ariaLabel="Advanced configuration">
      <details>
        <summary>Persistent YAML</summary>
        <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Persistent YAML</h2>
            <p className="muted-line">
              {source?.path ?? "/etc/kornode/config.yaml"} &mdash; only fields explicitly stored on
              disk; inherited values are shown under Effective config
            </p>
          </div>
          <div className="toolbar">
            {source && !source.exists && <Pill kind="muted">Not created</Pill>}
            {dirty && <Pill kind="warning">Unsaved</Pill>}
          </div>
        </div>
        <textarea
          className="config-editor"
          value={draft}
          onChange={(event) => onDraftChange(event.target.value)}
          placeholder="# No persistent YAML yet. Add settings here to create the file."
          spellCheck={false}
        />
        {source && !source.exists && !dirty && (
          <p className="muted-line">
            The active configuration currently comes from environment variables and application
            defaults. Saving this editor creates the YAML file without copying inherited values.
          </p>
        )}
        {validation && (
          <details className="rendered-file" open>
            <summary>Validation</summary>
            <pre>{validation}</pre>
          </details>
        )}
        <div className="panel-footer">
          <ActionButton label="Reload" icon={RefreshCw} onClick={onReloadSource} />
          <ActionButton
            label="Validate"
            icon={CheckCircle2}
            busy={busy === "config-validate"}
            onClick={onValidate}
          />
          <ActionButton
            label="Save"
            icon={Save}
            primary
            busy={busy === "config-save"}
            onClick={onSave}
          />
        </div>
      </section>
      </details>
      <details>
        <summary>Rendered files</summary>
        <section className="panel">
        <div className="panel-header">
          <h2>Rendered files</h2>
        </div>
        {diff && (
          <details className="rendered-file" open>
            <summary>Diff</summary>
            <pre>{diff || "No changes."}</pre>
          </details>
        )}
        {Object.entries(rendered).length === 0 ? (
          <EmptyState text="No rendered files" />
        ) : (
          Object.entries(rendered).map(([path, content]) => (
            <details className="rendered-file" key={path}>
              <summary>{path}</summary>
              <pre>{content}</pre>
            </details>
          ))
        )}
        <div className="panel-footer">
          <ActionButton label="Refresh" icon={RefreshCw} onClick={onRender} />
          <ActionButton
            label="Diff"
            icon={FileDiff}
            busy={busy === "config-diff"}
            onClick={onDiff}
          />
          <ActionButton
            label="Render configs"
            icon={Save}
            primary
            title="Write generated Korvus Node, supervisor, dnsmasq and nftables files from YAML"
            busy={busy === "write-config"}
            onClick={onWrite}
          />
        </div>
      </section>
      </details>
      <details>
        <summary>Effective config</summary>
        <section className="panel">
          <h2>Effective config</h2>
          <p className="muted-line">
            Read-only result after applying defaults, .env, environment, persistent YAML and CLI
            overrides.
          </p>
          <pre>{JSON.stringify(config ?? {}, null, 2)}</pre>
        </section>
      </details>
      </SettingsTabs>
      )}
    </div>
  );
}
