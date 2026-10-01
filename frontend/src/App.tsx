import { LogOut, Menu, Moon, RefreshCw, Sun } from "lucide-react";
import { Suspense, lazy, useEffect, useMemo, useState } from "react";
import { usePanelCore } from "./app/core";
import { useCertificates } from "./app/hooks/useCertificates";
import { useConfigEditor } from "./app/hooks/useConfigEditor";
import { useDashboard } from "./app/hooks/useDashboard";
import { useGroups } from "./app/hooks/useGroups";
import { useIdentity } from "./app/hooks/useIdentity";
import { useInternalDns } from "./app/hooks/useInternalDns";
import { useLogin } from "./app/hooks/useLogin";
import { useLogs } from "./app/hooks/useLogs";
import { useRouting } from "./app/hooks/useRouting";
import { useSessions } from "./app/hooks/useSessions";
import { useSettings } from "./app/hooks/useSettings";
import { useTheme } from "./app/hooks/useTheme";
import { useUpstream } from "./app/hooks/useUpstream";
import { useUsers } from "./app/hooks/useUsers";
import { tabs } from "./app/state";
import type { ConfigSection, Tab } from "./app/types";
import { NoticeToast } from "./components/NoticeToast";
import { IconButton, RavenMark } from "./components/ui";
import { readBoolean, readRecord } from "./lib/read";
import { DashboardView } from "./views/DashboardView";
import { DiagnosticsView } from "./views/DiagnosticsView";
import { IdentityView } from "./views/IdentityView";
import { InternalDnsView } from "./views/InternalDnsView";
import { LoginScreen } from "./views/LoginScreen";
import { LogsView } from "./views/LogsView";
import { SessionsView } from "./views/SessionsView";
import { CertificatesView } from "./views/certificates/CertificatesView";
import { ConfigSubnav } from "./views/config/ConfigSubnav";
import { ConfigView } from "./views/config/ConfigView";
import { GroupMembersDialog } from "./views/groups/GroupMembersDialog";
import { GroupsView } from "./views/groups/GroupsView";
import { UserConfigDialog } from "./views/groups/UserConfigDialog";
import { ClientProfileDialog } from "./views/clients/ClientProfileDialog";
import { ClientsSettingsDialog } from "./views/clients/ClientsSettingsDialog";
import { ClientsView } from "./views/clients/ClientsView";
import { UpstreamRelayDialog } from "./views/upstream/UpstreamRelayDialog";
import { UpstreamView } from "./views/upstream/UpstreamView";
import { P12Base64Dialog } from "./views/users/P12Base64Dialog";
import { RevokedCertsDialog } from "./views/users/RevokedCertsDialog";
import { CertificateContentDialog } from "./views/certificates/CertificateContentDialog";
import { UserGroupsDialog } from "./views/users/UserGroupsDialog";
import { UsersView } from "./views/users/UsersView";

const TerminalView = lazy(() =>
  import("./TerminalView").then((module) => ({ default: module.TerminalView }))
);

// Root component: composes the shared panel core with one hook per panel
// area (app/hooks/) and wires their state and actions into the views.
export function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [configSection, setConfigSection] = useState<ConfigSection>("server");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const { theme, toggleTheme } = useTheme();
  const core = usePanelCore();
  const {
    authInfo,
    authToken,
    busy,
    clearCommand,
    commandOutputs,
    dryRun,
    loadAll,
    loading,
    logout,
    notice,
    setDryRun,
    setNotice,
    setNoticePaused,
    state
  } = core;
  const login = useLogin(core);
  const sessions = useSessions(core, tab);
  const dashboard = useDashboard(core, tab, sessions.updateSessions);
  const users = useUsers(core);
  const groups = useGroups(core);
  const settings = useSettings(core);
  const routing = useRouting(core);
  const internalDns = useInternalDns(core, routing.routingDraft, settings.serverSettingsDraft);
  const identity = useIdentity(core);
  const upstream = useUpstream(core, tab, configSection, routing.saveRoutingSettings);
  const certificates = useCertificates(core);
  const configEditor = useConfigEditor(core);
  const logs = useLogs(core, tab);

  useEffect(() => {
    if (tab !== "diagnostics" || !authToken || !authInfo) {
      return;
    }
    void loadAll(authToken, { includeExtras: true });
  }, [tab]);

  const terminalEnabled = readBoolean(readRecord(state.config?.web).terminal_enabled, false);
  const availableTabs = useMemo(
    () => tabs.filter((item) => item.id !== "terminal" || terminalEnabled),
    [terminalEnabled]
  );

  useEffect(() => {
    if (tab === "terminal" && !terminalEnabled) {
      setTab("dashboard");
    }
  }, [tab, terminalEnabled]);

  if (!authToken || !authInfo) {
    return (
      <LoginScreen
        form={login.loginForm}
        busy={busy === "login"}
        notice={notice}
        theme={theme}
        totpRequired={login.totpRequired}
        onChange={login.setLoginForm}
        onSubmit={login.submit}
        onToggleTheme={toggleTheme}
      />
    );
  }

  const activeTab = availableTabs.find((item) => item.id === tab) ?? availableTabs[0];
  const selectTab = (target: Tab) => {
    setTab(target);
    setMobileNavOpen(false);
  };

  return (
    <main className={`app-shell${mobileNavOpen ? " nav-open" : ""}`}>
      <aside className="sidebar">
        <div className="brand">
          <RavenMark />
          <strong>Korvus Node</strong>
        </div>
        <nav aria-label="Primary">
          {availableTabs.map((item) => {
            const Icon = item.icon;
            return (
              <button
                className={tab === item.id ? "active" : ""}
                key={item.id}
                onClick={() => selectTab(item.id)}
                title={item.label}
                type="button"
              >
                <Icon size={18} aria-hidden="true" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <RavenMark />
          <div>
            <strong>r4ven.me</strong>
            <a href="https://r4ven.me" rel="noreferrer" target="_blank">
              Website
            </a>
            <a href="https://github.com/r4ven-me" rel="noreferrer" target="_blank">
              GitHub
            </a>
            <a href="https://t.me/r4ven_me" rel="noreferrer" target="_blank">
              Telegram
            </a>
            <small>
              Korvus Node {state.health?.version ?? ""}
              <br />
              Vibecoded by Ivan Cherniy
            </small>
          </div>
        </div>
      </aside>
      <button
        className="nav-backdrop"
        onClick={() => setMobileNavOpen(false)}
        type="button"
        aria-label="Close menu"
      />
      <section className="workspace">
        <header className="topbar">
          <div className="topbar-title">
            <IconButton
              label="Menu"
              icon={Menu}
              onClick={() => setMobileNavOpen((current) => !current)}
              extraClassName="mobile-menu-button"
            />
            <div>
            <h1>{activeTab.label}</h1>
            <p>{state.health ? `API ${state.health.version}` : "API"}</p>
            </div>
          </div>
          <div className="topbar-actions">
            <label className="switch" title="Preview commands without applying dangerous runtime changes">
              <input
                checked={dryRun}
                onChange={(event) => setDryRun(event.target.checked)}
                type="checkbox"
              />
              <span>Dry-run</span>
            </label>
            <span className="status ok">Connected as {authInfo.username}</span>
            <IconButton
              label="Reload panel data"
              icon={RefreshCw}
              busy={loading}
              onClick={() =>
                void loadAll(authToken, { includeExtras: tab === "diagnostics" })
              }
            />
            <IconButton
              label={theme === "dark" ? "Light theme" : "Dark theme"}
              icon={theme === "dark" ? Sun : Moon}
              onClick={toggleTheme}
            />
            <IconButton label="Log out" icon={LogOut} onClick={logout} />
          </div>
        </header>

        {tab === "dashboard" && (
          <DashboardView
            state={state}
            diagnosticScore={dashboard.diagnosticScore}
            busy={busy}
            interfaceName={dashboard.interfaceName}
            interfaceHistory={dashboard.interfaceHistory}
            commandOutput={commandOutputs.dashboard ?? null}
            onClearCommand={() => clearCommand("dashboard")}
            onStartServer={dashboard.startServer}
            onStopServer={dashboard.stopServer}
            onReloadServer={dashboard.reloadServer}
            onRestartServer={dashboard.restartServer}
            onWriteConfig={dashboard.writeConfig}
            onApplyNft={dashboard.applyNft}
          />
        )}

        {tab === "users" && (
          <UsersView
            users={state.users}
            otpRecords={state.otpRecords}
            busy={busy}
            newUser={users.newUser}
            passwordDrafts={users.passwordDrafts}
            p12Drafts={users.p12Drafts}
            commandOutput={commandOutputs.users ?? null}
            onClearCommand={() => clearCommand("users")}
            onNewUserChange={users.setNewUser}
            onPasswordDraftChange={users.setPasswordDraft}
            onP12DraftChange={users.setP12Draft}
            onCreate={users.createUser}
            onChangePassword={users.changePassword}
            onEnable={users.setEnabled}
            onDelete={users.deleteUser}
            onOtp={users.setOtpEnabled}
            onOtpQr={users.showOtpQr}
            onCert={users.issueCertificate}
            onRevokeCert={users.revokeCertificate}
            onP12={users.createP12}
            onDownloadP12={users.downloadP12}
            onDownloadCert={users.downloadCert}
            onDownloadKey={users.downloadKey}
            onViewP12Base64={users.viewP12Base64}
            onOpenConfig={users.openConfig}
            onOpenGroups={users.openGroups}
          />
        )}

        {tab === "groups" && (
          <GroupsView
            groups={state.groups}
            users={state.users}
            name={groups.newGroupName}
            busy={busy}
            commandOutput={commandOutputs.groups ?? null}
            onClearCommand={() => clearCommand("groups")}
            onNameChange={groups.setNewGroupName}
            onCreate={groups.createGroup}
            onOpenConfig={groups.openConfig}
            onDeleteConfig={groups.deleteConfig}
            onDeleteGroup={groups.deleteGroup}
            onOpenMembers={groups.openMembers}
          />
        )}

        {tab === "sessions" && (
          <SessionsView
            sessions={state.sessions}
            sessionRates={sessions.sessionRates}
            busy={busy}
            commandOutput={commandOutputs.sessions ?? null}
            onClearCommand={() => clearCommand("sessions")}
            onKick={sessions.kick}
          />
        )}

        {tab === "config" && (
          <ConfigSubnav active={configSection} onSelect={setConfigSection} />
        )}

        {tab === "config" && configSection === "internal_dns" && (
          <InternalDnsView
            status={state.internalDns}
            draft={internalDns.internalDnsDraft}
            dnsServerDraft={routing.routingDraft}
            serverDraft={settings.serverSettingsDraft}
            resolverRequired={
              (routing.routingDraft.mode === "split" && routing.routingDraft.tunnelDns) ||
              state.upstreamProfiles.some(
                (profile) => profile.enabled && (profile.domains?.length ?? 0) > 0
              )
            }
            busy={busy}
            commandOutput={commandOutputs.internal_dns ?? null}
            onClearCommand={() => clearCommand("internal_dns")}
            onDraftChange={internalDns.setInternalDnsDraft}
            onDnsServerDraftChange={routing.setRoutingDraft}
            onServerDraftChange={settings.setServerSettingsDraft}
            onSave={() => void internalDns.save()}
            onPreviewUrl={(url) => void internalDns.refreshBlocklist(url, true)}
            onRefreshUrl={(url) => void internalDns.refreshBlocklist(url, false)}
          />
        )}

        {tab === "config" && configSection === "identity" && (
          <IdentityView
            identity={state.identity}
            oidcDraft={identity.oidcDraft}
            providerDraft={identity.oidcProviderDraft}
            groupDraft={identity.groupPolicyDraft}
            identitySettingsDraft={identity.identitySettingsDraft}
            busy={busy}
            commandOutput={commandOutputs.identity ?? null}
            onClearCommand={() => clearCommand("identity")}
            onOidcDraftChange={identity.setOidcDraft}
            onProviderDraftChange={identity.setOidcProviderDraft}
            onGroupDraftChange={identity.setGroupPolicyDraft}
            onIdentitySettingsDraftChange={identity.setIdentitySettingsDraft}
            onSaveIdentitySettings={() => void identity.saveIdentitySettings()}
            onSaveOidcSettings={() => void identity.saveOidcSettings()}
            onSaveProvider={identity.saveProvider}
            onSaveGroup={identity.saveGroup}
            onDeleteProvider={identity.deleteProvider}
            onDeleteGroup={identity.deleteGroup}
          />
        )}

        {tab === "config" && configSection === "clients" && (
          <div className="view-stack">
            <ClientsView
              status={state.upstream}
              profiles={state.upstreamProfiles}
              busy={busy}
              commandOutput={commandOutputs.upstream ?? null}
              onClearCommand={() => clearCommand("upstream")}
              onSetEnabled={(enabled) => void upstream.saveSettings(enabled)}
              onSetProfileEnabled={(profile, enabled) =>
                void upstream.setProfileEnabled(profile, enabled)
              }
              onSwitch={upstream.switchProfile}
              onDeleteProfile={(profile) => void upstream.deleteProfile(profile)}
              onCreateProfile={upstream.createProfile}
              onEditProfile={upstream.editProfile}
              onConnectProfile={upstream.connectProfile}
              onDisconnectProfile={upstream.disconnectProfile}
              onSyncProfile={(profile) => void upstream.syncProfile(profile)}
              onOpenSettings={upstream.openSettings}
            />
          </div>
        )}
        {tab === "config" && configSection === "upstream" && (
          <div className="view-stack">
            <UpstreamView
              status={state.upstream}
              profiles={state.upstreamProfiles}
              serverEnabled={readBoolean(readRecord(state.config?.server).enabled, true)}
              routingDraft={routing.routingDraft}
              routes={state.routes}
              domains={state.domains}
              routesStatus={state.routesStatus}
              domainsStatus={state.domainsStatus}
              busy={busy}
              commandOutput={commandOutputs.routing ?? null}
              onClearCommand={() => clearCommand("routing")}
              onRoutingDraftChange={routing.setRoutingDraft}
              onSaveSettings={() => void routing.saveRoutingSettings()}
              onSaveRoutes={routing.saveRoutes}
              onSaveDomains={routing.saveDomains}
              onPreviewRoutesUrl={(url) => routing.refreshRoutesUrl(url, true)}
              onRefreshRoutesUrl={(url) => routing.refreshRoutesUrl(url, false)}
              onPreviewDomainsUrl={(url) => routing.refreshDomainsUrl(url, true)}
              onRefreshDomainsUrl={(url) => routing.refreshDomainsUrl(url, false)}
              onEditRelay={upstream.editRelay}
              onOpenClients={() => setConfigSection("clients")}
            />
          </div>
        )}
        {upstream.relayDraft && (
          <UpstreamRelayDialog
            draft={upstream.relayDraft}
            busy={busy}
            routesStatus={upstream.relayRoutesStatus}
            domainsStatus={upstream.relayDomainsStatus}
            onDraftChange={upstream.setRelayDraft}
            onClose={upstream.closeRelay}
            onSave={(event) => void upstream.saveRelay(event)}
            onPreviewRoutesUrl={upstream.previewRelayRoutesUrl}
            onRefreshRoutesUrl={upstream.refreshRelayRoutesUrl}
            onPreviewDomainsUrl={upstream.previewRelayDomainsUrl}
            onRefreshDomainsUrl={upstream.refreshRelayDomainsUrl}
          />
        )}
        {upstream.profileModalOpen && (
          <ClientProfileDialog
            key={upstream.profileDialogKey}
            draft={upstream.upstreamDraft}
            isEdit={upstream.editingProfile}
            busy={busy}
            serverRouting={
              state.upstream?.connections.find(
                (connection) => connection.profile === upstream.upstreamDraft.name
              )?.server_routing
            }
            onDraftChange={upstream.setUpstreamDraft}
            onClose={upstream.closeProfileDialog}
            onSave={upstream.saveProfile}
            onFetchPin={() => void upstream.fetchDraftServerPin()}
          />
        )}
        {upstream.settingsModalOpen && (
          <ClientsSettingsDialog
            upstreamInterface={upstream.upstreamInterface}
            checkInterval={upstream.checkInterval}
            checkThreshold={upstream.checkThreshold}
            checkSettleSeconds={upstream.checkSettleSeconds}
            failover={upstream.failover}
            connectOnBoot={upstream.connectOnBoot}
            checkHost={upstream.checkHost}
            hasActiveProfile={Boolean(state.upstream?.active_profile)}
            upstreamEnabled={Boolean(state.upstream?.enabled)}
            hostRoutes={state.hostRoutes}
            hostDomains={state.hostDomains}
            hostRoutesStatus={state.hostRoutesStatus}
            hostDomainsStatus={state.hostDomainsStatus}
            routingDraft={routing.routingDraft}
            busy={busy}
            onInterfaceChange={upstream.setUpstreamInterface}
            onCheckIntervalChange={upstream.setCheckInterval}
            onCheckThresholdChange={upstream.setCheckThreshold}
            onCheckSettleSecondsChange={upstream.setCheckSettleSeconds}
            onFailoverChange={upstream.setFailover}
            onConnectOnBootChange={upstream.setConnectOnBoot}
            onCheckHostChange={upstream.setCheckHost}
            onRoutingDraftChange={routing.setRoutingDraft}
            onSaveHostRoutes={routing.saveHostRoutes}
            onSaveHostDomains={routing.saveHostDomains}
            onPreviewHostRoutesUrl={(url) => routing.refreshHostRoutesUrl(url, true)}
            onRefreshHostRoutesUrl={(url) => routing.refreshHostRoutesUrl(url, false)}
            onPreviewHostDomainsUrl={(url) => routing.refreshHostDomainsUrl(url, true)}
            onRefreshHostDomainsUrl={(url) => routing.refreshHostDomainsUrl(url, false)}
            onClose={upstream.closeSettings}
            onSave={upstream.submitSettings}
          />
        )}

        {tab === "config" && configSection === "certificates" && (
          <CertificatesView
            status={state.certificateStatus}
            externalFiles={certificates.externalCertFiles}
            caFiles={certificates.caFiles}
            caRevokeDraft={certificates.caRevokeDraft}
            certificateSettingsDraft={certificates.certificateSettingsDraft}
            letsEncryptDraft={certificates.letsEncryptDraft}
            busy={busy}
            dryRun={dryRun}
            commandOutput={commandOutputs.certificates ?? null}
            onClearCommand={() => clearCommand("certificates")}
            onExternalFilesChange={certificates.setExternalCertFiles}
            onCaFilesChange={certificates.setCaFiles}
            onCaRevokeDraftChange={certificates.setCaRevokeDraft}
            onCertificateSettingsDraftChange={certificates.setCertificateSettingsDraft}
            onSaveCertificateSettings={() => void certificates.saveSettings()}
            onLetsEncryptDraftChange={certificates.setLetsEncryptDraft}
            onUploadExternal={certificates.uploadExternal}
            onIssueLetsEncrypt={certificates.issueLetsEncrypt}
            onRenewLetsEncrypt={() => void certificates.renewLetsEncrypt()}
            onSaveLetsEncryptSettings={() => void certificates.saveLetsEncryptSettings()}
            onSetLetsEncryptEnabled={(enabled) => void certificates.setLetsEncryptEnabled(enabled)}
            onRegenerateCa={certificates.regenerateCa}
            onUploadCa={certificates.uploadCa}
            onRevokeCaCert={certificates.revokeCaCert}
            onShowRevokedCerts={certificates.showRevokedCerts}
            serverPin={certificates.serverPin}
            onShowServerPin={() => void certificates.showServerPin()}
            onShowAuthorityCertificateContent={() =>
              void certificates.showAuthorityCertificateContent()
            }
            onShowServerCertificateContent={() => void certificates.showServerCertificateContent()}
            onShowLetsEncryptCertificateContent={() =>
              void certificates.showLetsEncryptCertificateContent()
            }
          />
        )}

        {tab === "config" && (
          <ConfigView
            section={configSection}
            config={state.config}
            source={state.configSource}
            draft={configEditor.configDraft}
            dirty={configEditor.configDirty}
            rendered={state.renderedConfig}
            diff={configEditor.configDiff}
            validation={configEditor.configValidation}
            serverSettingsDraft={settings.serverSettingsDraft}
            authMethodsDraft={settings.authMethodsDraft}
            webSettingsDraft={settings.webSettingsDraft}
            generalSettingsDraft={settings.generalSettingsDraft}
            onServerSettingsDraftChange={settings.setServerSettingsDraft}
            onAuthMethodsDraftChange={settings.setAuthMethodsDraft}
            onWebSettingsDraftChange={settings.setWebSettingsDraft}
            onGeneralSettingsDraftChange={settings.setGeneralSettingsDraft}
            onSaveServerSettings={() => void settings.saveServer()}
            onSaveAuthMethodsSettings={() => void settings.saveAuthMethods()}
            onTestOtpEmail={settings.testEmail}
            onTestOtpTelegram={settings.testTelegram}
            onSaveWebSettings={() => void settings.saveWeb()}
            onSaveGeneralSettings={() => void settings.saveGeneral()}
            busy={busy}
            onDraftChange={configEditor.editDraft}
            onReloadSource={configEditor.reloadSource}
            onRender={() => void loadAll(authToken)}
            onValidate={configEditor.validate}
            onDiff={configEditor.diff}
            onSave={configEditor.save}
            onWrite={dashboard.writeConfig}
            onNotice={(kind, text) => setNotice({ kind, text })}
          />
        )}

        {tab === "diagnostics" && <DiagnosticsView diagnostics={state.diagnostics} />}

        {tab === "logs" && (
          <LogsView
            files={state.logFiles}
            request={logs.logRequest}
            live={logs.liveLog}
            logTail={logs.logTail}
            busy={busy}
            rotation={logs.logRotationDraft}
            onRequestChange={logs.setLogRequest}
            onLiveChange={logs.setLiveLog}
            onFetch={logs.fetchLog}
            onRotationChange={logs.setLogRotationDraft}
            onSaveRotation={logs.saveRotation}
            onRotateNow={() => void logs.rotateNow()}
          />
        )}

        {terminalEnabled && (
          <Suspense fallback={<section className="panel">Loading terminal...</section>}>
            <div className={tab === "terminal" ? "tab-pane" : "tab-pane tab-pane-hidden"}>
              <TerminalView
                authToken={authToken}
                theme={theme}
                onNotice={(kind, text) => setNotice({ kind, text })}
              />
            </div>
          </Suspense>
        )}
      </section>
      {users.userConfigModal && (
        <UserConfigDialog
          busy={busy}
          state={users.userConfigModal}
          onChange={(draft) =>
            users.setUserConfigModal((current) => (current ? { ...current, draft } : current))
          }
          onClose={() => users.setUserConfigModal(null)}
          onDelete={users.deleteConfig}
          onSave={users.saveConfig}
        />
      )}
      {users.p12Base64Modal && (
        <P12Base64Dialog
          state={users.p12Base64Modal}
          onClose={() => users.setP12Base64Modal(null)}
        />
      )}
      {certificates.revokedCertsModal && (
        <RevokedCertsDialog
          state={certificates.revokedCertsModal}
          onClose={certificates.closeRevokedCerts}
        />
      )}
      {certificates.certificateContentModal && (
        <CertificateContentDialog
          state={certificates.certificateContentModal}
          onClose={certificates.closeCertificateContent}
        />
      )}
      {users.userGroupsModal && (
        <UserGroupsDialog
          availableGroups={state.groups}
          busy={busy}
          state={users.userGroupsModal}
          onChange={(nextGroups) =>
            users.setUserGroupsModal((current) =>
              current ? { ...current, groups: nextGroups } : current
            )
          }
          onClose={() => users.setUserGroupsModal(null)}
          onCreateGroup={() => {
            users.setUserGroupsModal(null);
            setTab("groups");
          }}
          onSave={users.saveGroups}
        />
      )}
      {groups.groupConfigModal && (
        <UserConfigDialog
          busy={busy}
          state={{ username: groups.groupConfigModal.name, draft: groups.groupConfigModal.draft }}
          title={`${groups.groupConfigModal.name} group config`}
          saveBusyKey={`group-config-save-${groups.groupConfigModal.name}`}
          deleteBusyKey={`group-config-delete-${groups.groupConfigModal.name}`}
          onChange={(draft) =>
            groups.setGroupConfigModal((current) => (current ? { ...current, draft } : current))
          }
          onClose={() => groups.setGroupConfigModal(null)}
          onDelete={groups.deleteDialogConfig}
          onSave={groups.saveDialogConfig}
        />
      )}
      {groups.groupMembersModal && (
        <GroupMembersDialog
          busy={busy}
          state={groups.groupMembersModal}
          users={state.users}
          onChange={(members) =>
            groups.setGroupMembersModal((current) =>
              current ? { ...current, users: members } : current
            )
          }
          onClose={() => groups.setGroupMembersModal(null)}
          onSave={groups.saveMembers}
        />
      )}
      {notice && (
        <NoticeToast
          notice={notice}
          onClose={() => setNotice(null)}
          onPauseChange={setNoticePaused}
        />
      )}
    </main>
  );
}
