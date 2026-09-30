import { useState } from "react";
import {
  saveAuthMethodsSettings,
  saveGeneralSettings,
  saveServerSettings,
  saveWebSettings,
  testOtpEmail,
  testOtpTelegram
} from "../../api";
import { syntheticCommand } from "../../lib/commands";
import {
  type AuthMethodsDraft,
  type GeneralSettingsDraft,
  type ServerSettingsDraft,
  type WebSettingsDraft,
  authMethodsPayload,
  readAuthMethodsDraft,
  readGeneralSettingsDraft,
  readServerSettingsDraft,
  readWebSettingsDraft,
  splitLines
} from "../../lib/drafts";
import type { PanelCore } from "../core";

// The structured Config sub-sections: VPN server, authentication methods,
// Web / API panel and System (general).
export function useSettings(core: PanelCore) {
  const { recordCommand, runAction } = core;
  const [serverSettingsDraft, setServerSettingsDraft] = useState<ServerSettingsDraft>(() =>
    readServerSettingsDraft({})
  );
  const [authMethodsDraft, setAuthMethodsDraft] = useState<AuthMethodsDraft>(() =>
    readAuthMethodsDraft({})
  );
  const [webSettingsDraft, setWebSettingsDraft] = useState<WebSettingsDraft>(() =>
    readWebSettingsDraft({})
  );
  const [generalSettingsDraft, setGeneralSettingsDraft] = useState<GeneralSettingsDraft>(() =>
    readGeneralSettingsDraft({})
  );

  core.registerHydrator("settings", ({ config }) => {
    if (!config) {
      return;
    }
    setServerSettingsDraft(readServerSettingsDraft(config));
    setAuthMethodsDraft(readAuthMethodsDraft(config));
    setWebSettingsDraft(readWebSettingsDraft(config));
    setGeneralSettingsDraft(readGeneralSettingsDraft(config));
  });

  const saveServer = async () => {
    const result = await runAction("server-config-settings", "Server settings saved", (token) =>
      saveServerSettings(token, {
        enabled: serverSettingsDraft.enabled,
        listen: serverSettingsDraft.listen,
        port: serverSettingsDraft.port,
        udp_enabled: serverSettingsDraft.udpEnabled,
        device: serverSettingsDraft.device,
        cn: serverSettingsDraft.cn,
        realm: serverSettingsDraft.realm,
        ipv4_network: serverSettingsDraft.ipv4Network,
        dns: splitLines(serverSettingsDraft.dns),
        search_domains: splitLines(serverSettingsDraft.searchDomains),
        routes: splitLines(serverSettingsDraft.routes),
        no_routes: splitLines(serverSettingsDraft.noRoutes),
        max_clients: serverSettingsDraft.maxClients,
        max_same_clients: serverSettingsDraft.maxSameClients,
        keepalive: serverSettingsDraft.keepalive,
        dpd: serverSettingsDraft.dpd,
        mobile_dpd: serverSettingsDraft.mobileDpd,
        compression: serverSettingsDraft.compression,
        cisco_client_compat: serverSettingsDraft.ciscoClientCompat,
        isolate_workers: serverSettingsDraft.isolateWorkers,
        try_mtu_discovery: serverSettingsDraft.tryMtuDiscovery,
        predictable_ips: serverSettingsDraft.predictableIps,
        deny_roaming: serverSettingsDraft.denyRoaming,
        ping_leases: serverSettingsDraft.pingLeases,
        dtls_legacy: serverSettingsDraft.dtlsLegacy,
        client_bypass_protocol: serverSettingsDraft.clientBypassProtocol,
        rate_limit_ms: serverSettingsDraft.rateLimitMs,
        server_stats_reset_time: serverSettingsDraft.serverStatsResetTime,
        switch_to_tcp_timeout: serverSettingsDraft.switchToTcpTimeout,
        auth_timeout: serverSettingsDraft.authTimeout,
        cookie_timeout: serverSettingsDraft.cookieTimeout,
        ban_time: serverSettingsDraft.banTime,
        max_ban_score: serverSettingsDraft.maxBanScore,
        ban_reset_time: serverSettingsDraft.banResetTime,
        rekey_time: serverSettingsDraft.rekeyTime,
        rekey_method: serverSettingsDraft.rekeyMethod,
        cert_user_oid: serverSettingsDraft.certUserOid,
        tls_priorities: serverSettingsDraft.tlsPriorities || null,
        camouflage: {
          enabled: serverSettingsDraft.camouflageEnabled,
          secret: serverSettingsDraft.camouflageSecret || null,
          realm: serverSettingsDraft.camouflageRealm
        },
        connect_script: serverSettingsDraft.connectScript || null,
        disconnect_script: serverSettingsDraft.disconnectScript || null,
        debug_level: serverSettingsDraft.debugLevel
      })
    );
    if (result !== null) {
      const saved = syntheticCommand(["korctl", "server", "settings"], "saved");
      recordCommand("config", result.reload ? [saved, result.reload] : saved);
    }
  };

  const saveAuthMethods = async () => {
    const result = await runAction(
      "auth-methods-settings",
      "Authentication method settings saved",
      (token) => saveAuthMethodsSettings(token, authMethodsPayload(authMethodsDraft))
    );
    if (result !== null) {
      const saved = syntheticCommand(["korctl", "server", "auth-settings"], "saved");
      recordCommand("config", result.reload ? [saved, result.reload] : saved);
    }
  };

  const testEmail = () =>
    void runAction(
      "auth-methods-test-email",
      "Test email sent",
      (token) => testOtpEmail(token, authMethodsPayload(authMethodsDraft)),
      { reload: false }
    );

  const testTelegram = () =>
    void runAction(
      "auth-methods-test-telegram",
      "Test Telegram message sent",
      (token) => testOtpTelegram(token, authMethodsPayload(authMethodsDraft)),
      { reload: false }
    );

  const saveWeb = async () => {
    const result = await runAction("web-config-settings", "Web panel settings saved", (token) =>
      saveWebSettings(token, {
        enabled: webSettingsDraft.enabled,
        listen: webSettingsDraft.listen,
        port: webSettingsDraft.port,
        tls: webSettingsDraft.tls,
        allow_insecure_http: webSettingsDraft.allowInsecureHttp,
        trusted_proxies: splitLines(webSettingsDraft.trustedProxies),
        admin_user: webSettingsDraft.adminUser,
        terminal_enabled: webSettingsDraft.terminalEnabled,
        terminal_idle_timeout: webSettingsDraft.terminalIdleTimeout,
        terminal_max_sessions: webSettingsDraft.terminalMaxSessions,
        client_sync_enabled: webSettingsDraft.clientSyncEnabled,
        session_lifetime: webSettingsDraft.sessionLifetime,
        session_cookie_secure: webSettingsDraft.sessionCookieSecure
      })
    );
    if (result !== null) {
      recordCommand("config", syntheticCommand(["korctl", "web-config", "settings"], "saved"));
    }
  };

  const saveGeneral = async () => {
    const result = await runAction("general-settings", "General settings saved", (token) =>
      saveGeneralSettings(token, {
        timezone: generalSettingsDraft.timezone,
        log_level: generalSettingsDraft.logLevel,
        project_name: generalSettingsDraft.projectName,
        cli_enabled: generalSettingsDraft.cliEnabled
      })
    );
    if (result !== null) {
      recordCommand(
        "config",
        syntheticCommand(["korctl", "config", "general-settings"], "saved")
      );
    }
  };

  return {
    serverSettingsDraft,
    setServerSettingsDraft,
    authMethodsDraft,
    setAuthMethodsDraft,
    webSettingsDraft,
    setWebSettingsDraft,
    generalSettingsDraft,
    setGeneralSettingsDraft,
    saveServer,
    saveAuthMethods,
    testEmail,
    testTelegram,
    saveWeb,
    saveGeneral
  };
}
