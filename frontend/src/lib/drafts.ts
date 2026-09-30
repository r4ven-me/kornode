import type { OidcDraft } from "../app/types";
import type { IdentityStatus } from "../api";
import { readBoolean, readNumber, readRecord, readString, readStringArray } from "./read";

export function splitLines(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

export function readRoutingDraft(config: Record<string, unknown>): {
  clientTraffic: boolean;
  mode: string;
  tunnelDns: boolean;
  hostTraffic: boolean;
  hostMode: string;
  hostDns: string;
  mainInterface: string;
  fwmark: string;
  tableId: number;
  nftPrefix: string;
  routesFilesText: string;
  routesUrlsText: string;
  domainsFilesText: string;
  domainsUrlsText: string;
  hostRoutesFilesText: string;
  hostRoutesUrlsText: string;
  hostDomainsFilesText: string;
  hostDomainsUrlsText: string;
} {
  const routing = readRecord(config.routing);
  const split = readRecord(routing.split);
  const hostSplit = readRecord(routing.host_split);
  return {
    clientTraffic: readBoolean(routing.client_traffic, true),
    mode: readString(routing.mode, "full"),
    tunnelDns: readBoolean(split.tunnel_dns, false),
    hostTraffic: readBoolean(routing.host_traffic, false),
    hostMode: readString(routing.host_mode, "full"),
    hostDns: readString(routing.host_dns, "off"),
    mainInterface: readString(routing.main_interface, "auto"),
    fwmark: readString(routing.fwmark, "0x0c01"),
    tableId: readNumber(routing.table_id, 1201),
    nftPrefix: readString(routing.nft_prefix, "kornode"),
    routesFilesText: readStringArray(split.routes_files).join("\n"),
    routesUrlsText: readStringArray(split.routes_urls).join("\n"),
    domainsFilesText: readStringArray(split.domains_files).join("\n"),
    domainsUrlsText: readStringArray(split.domains_urls).join("\n"),
    hostRoutesFilesText: readStringArray(hostSplit.routes_files).join("\n"),
    hostRoutesUrlsText: readStringArray(hostSplit.routes_urls).join("\n"),
    hostDomainsFilesText: readStringArray(hostSplit.domains_files).join("\n"),
    hostDomainsUrlsText: readStringArray(hostSplit.domains_urls).join("\n")
  };
}

export function readOidcDraft(identity: IdentityStatus): OidcDraft {
  return {
    enabled: identity.auth.enabled,
    connector: identity.auth.connector,
    pamService: identity.auth.pam.service,
    pamGidMin: identity.auth.pam.gid_min === null ? "" : String(identity.auth.pam.gid_min),
    radiusConfigFile: identity.auth.radius.config_file,
    radiusGroupconfig: identity.auth.radius.groupconfig,
    radiusNasIdentifier: identity.auth.radius.nas_identifier ?? "",
    radiusGroupSeparator: identity.auth.radius.group_separator,
  };
}

export type ServerSettingsDraft = {
  enabled: boolean;
  listen: string;
  port: number;
  udpEnabled: boolean;
  device: string;
  cn: string;
  realm: string;
  ipv4Network: string;
  dns: string;
  searchDomains: string;
  routes: string;
  noRoutes: string;
  maxClients: number;
  maxSameClients: number;
  keepalive: number;
  dpd: number;
  mobileDpd: number;
  compression: boolean;
  ciscoClientCompat: boolean;
  isolateWorkers: boolean;
  tryMtuDiscovery: boolean;
  predictableIps: boolean;
  denyRoaming: boolean;
  pingLeases: boolean;
  dtlsLegacy: boolean;
  clientBypassProtocol: boolean;
  rateLimitMs: number;
  serverStatsResetTime: number;
  switchToTcpTimeout: number;
  authTimeout: number;
  cookieTimeout: number;
  banTime: number;
  maxBanScore: number;
  banResetTime: number;
  rekeyTime: number;
  rekeyMethod: "ssl" | "new-tunnel";
  certUserOid: string;
  tlsPriorities: string;
  camouflageEnabled: boolean;
  camouflageSecret: string;
  camouflageRealm: string;
  connectScript: string;
  disconnectScript: string;
  debugLevel: number;
};

export function readServerSettingsDraft(config: Record<string, unknown>): ServerSettingsDraft {
  const server = readRecord(config.server);
  const camouflage = readRecord(server.camouflage);
  return {
    enabled: readBoolean(server.enabled, true),
    listen: readString(server.listen, "0.0.0.0"),
    port: readNumber(server.port, 443),
    udpEnabled: readBoolean(server.udp_enabled, true),
    device: readString(server.device, "vpns"),
    cn: readString(server.cn, "vpn.example.com"),
    realm: readString(server.realm, "Korvus VPN Server"),
    ipv4Network: readString(server.ipv4_network, "10.10.10.0/24"),
    dns: readStringArray(server.dns).join("\n"),
    searchDomains: readStringArray(server.search_domains).join("\n"),
    routes: readStringArray(server.routes).join("\n"),
    noRoutes: readStringArray(server.no_routes).join("\n"),
    maxClients: readNumber(server.max_clients, 128),
    maxSameClients: readNumber(server.max_same_clients, 2),
    keepalive: readNumber(server.keepalive, 32400),
    dpd: readNumber(server.dpd, 90),
    mobileDpd: readNumber(server.mobile_dpd, 1800),
    compression: readBoolean(server.compression, false),
    ciscoClientCompat: readBoolean(server.cisco_client_compat, true),
    isolateWorkers: readBoolean(server.isolate_workers, true),
    tryMtuDiscovery: readBoolean(server.try_mtu_discovery, true),
    predictableIps: readBoolean(server.predictable_ips, true),
    denyRoaming: readBoolean(server.deny_roaming, false),
    pingLeases: readBoolean(server.ping_leases, false),
    dtlsLegacy: readBoolean(server.dtls_legacy, true),
    clientBypassProtocol: readBoolean(server.client_bypass_protocol, false),
    rateLimitMs: readNumber(server.rate_limit_ms, 200),
    serverStatsResetTime: readNumber(server.server_stats_reset_time, 604800),
    switchToTcpTimeout: readNumber(server.switch_to_tcp_timeout, 25),
    authTimeout: readNumber(server.auth_timeout, 240),
    cookieTimeout: readNumber(server.cookie_timeout, 600),
    banTime: readNumber(server.ban_time, 300),
    maxBanScore: readNumber(server.max_ban_score, 80),
    banResetTime: readNumber(server.ban_reset_time, 1200),
    rekeyTime: readNumber(server.rekey_time, 172800),
    rekeyMethod: readString(server.rekey_method, "ssl") === "new-tunnel" ? "new-tunnel" : "ssl",
    certUserOid: readString(server.cert_user_oid, "2.5.4.3"),
    tlsPriorities: readString(server.tls_priorities, ""),
    camouflageEnabled: readBoolean(camouflage.enabled, false),
    camouflageSecret: readString(camouflage.secret, ""),
    camouflageRealm: readString(camouflage.realm, "Hidden service"),
    connectScript: readString(server.connect_script, ""),
    disconnectScript: readString(server.disconnect_script, ""),
    debugLevel: readNumber(server.debug_level, 1)
  };
}

export type AuthMethodsDraft = {
  passwordEnabled: boolean;
  certificateEnabled: boolean;
  otpEnabled: boolean;
  otpOcservOathAuth: boolean;
  otpIssuer: string;
  otpSendByEmail: boolean;
  otpSendByTelegram: boolean;
  otpSmtpHost: string;
  otpSmtpPort: number;
  otpSmtpUsername: string;
  otpSmtpPassword: string;
  otpSmtpFrom: string;
  otpSmtpStarttls: boolean;
  otpSmtpTestRecipient: string;
  otpTelegramBotToken: string;
  otpTelegramChatId: string;
};

export function readAuthMethodsDraft(config: Record<string, unknown>): AuthMethodsDraft {
  const auth = readRecord(config.auth);
  const password = readRecord(auth.password);
  const certificate = readRecord(auth.certificate);
  const otp = readRecord(auth.otp);
  return {
    passwordEnabled: readBoolean(password.enabled, true),
    certificateEnabled: readBoolean(certificate.enabled, false),
    otpEnabled: readBoolean(otp.enabled, false),
    otpOcservOathAuth: readBoolean(otp.ocserv_oath_auth, false),
    otpIssuer: readString(otp.issuer, "Korvus Node"),
    otpSendByEmail: readBoolean(otp.send_by_email, false),
    otpSendByTelegram: readBoolean(otp.send_by_telegram, false),
    otpSmtpHost: readString(otp.smtp_host, ""),
    otpSmtpPort: readNumber(otp.smtp_port, 587),
    otpSmtpUsername: readString(otp.smtp_username, ""),
    otpSmtpPassword: "",
    otpSmtpFrom: readString(otp.smtp_from, ""),
    otpSmtpStarttls: readBoolean(otp.smtp_starttls, true),
    otpSmtpTestRecipient: readString(otp.smtp_test_recipient, ""),
    otpTelegramBotToken: "",
    otpTelegramChatId: readString(otp.telegram_chat_id, "")
  };
}

export function authMethodsPayload(draft: AuthMethodsDraft) {
  return {
    password_enabled: draft.passwordEnabled,
    certificate_enabled: draft.certificateEnabled,
    otp_enabled: draft.otpEnabled,
    otp_ocserv_oath_auth: draft.otpOcservOathAuth,
    otp_issuer: draft.otpIssuer,
    otp_send_by_email: draft.otpSendByEmail,
    otp_send_by_telegram: draft.otpSendByTelegram,
    otp_smtp_host: draft.otpSmtpHost.trim() || null,
    otp_smtp_port: draft.otpSmtpPort,
    otp_smtp_username: draft.otpSmtpUsername.trim() || null,
    otp_smtp_password: draft.otpSmtpPassword || null,
    otp_smtp_from: draft.otpSmtpFrom.trim() || null,
    otp_smtp_starttls: draft.otpSmtpStarttls,
    otp_smtp_test_recipient: draft.otpSmtpTestRecipient.trim() || null,
    otp_telegram_bot_token: draft.otpTelegramBotToken || null,
    otp_telegram_chat_id: draft.otpTelegramChatId.trim() || null
  };
}

export type WebSettingsDraft = {
  enabled: boolean;
  listen: string;
  port: number;
  tls: boolean;
  allowInsecureHttp: boolean;
  trustedProxies: string;
  adminUser: string;
  terminalEnabled: boolean;
  terminalIdleTimeout: number;
  terminalMaxSessions: number;
  clientSyncEnabled: boolean;
  sessionLifetime: number;
  sessionCookieSecure: boolean;
};

export function readWebSettingsDraft(config: Record<string, unknown>): WebSettingsDraft {
  const web = readRecord(config.web);
  return {
    enabled: readBoolean(web.enabled, false),
    listen: readString(web.listen, "127.0.0.1"),
    port: readNumber(web.port, 8443),
    tls: readBoolean(web.tls, true),
    allowInsecureHttp: readBoolean(web.allow_insecure_http, false),
    trustedProxies: readStringArray(web.trusted_proxies).join("\n"),
    adminUser: readString(web.admin_user, "admin"),
    terminalEnabled: readBoolean(web.terminal_enabled, false),
    terminalIdleTimeout: readNumber(web.terminal_idle_timeout, 900),
    terminalMaxSessions: readNumber(web.terminal_max_sessions, 2),
    clientSyncEnabled: readBoolean(web.client_sync_enabled, false),
    sessionLifetime: readNumber(web.session_lifetime, 43200),
    sessionCookieSecure: readBoolean(web.session_cookie_secure, true)
  };
}

export type GeneralSettingsDraft = {
  timezone: string;
  logLevel: "debug" | "info" | "warning" | "error";
  projectName: string;
  cliEnabled: boolean;
};

export function readGeneralSettingsDraft(config: Record<string, unknown>): GeneralSettingsDraft {
  const system = readRecord(config.system);
  const cli = readRecord(config.cli);
  const logLevel = system.log_level;
  return {
    timezone: readString(system.timezone, "UTC"),
    logLevel:
      logLevel === "debug" || logLevel === "warning" || logLevel === "error" ? logLevel : "info",
    projectName: readString(system.project_name, "kornode"),
    cliEnabled: readBoolean(cli.enabled, true)
  };
}
