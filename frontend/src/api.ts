export type Health = {
  status: string;
  version: string;
};

export type AuthInfo = {
  authenticated: boolean;
  username: string;
  csrf_token: string | null;
};

export type CommandResult = {
  argv: string[];
  returncode: number;
  stdout: string;
  stderr: string;
  dry_run: boolean;
};

export type UserRecord = {
  username: string;
  disabled: boolean;
  certificate_exists: boolean;
  p12_exists: boolean;
  groups: string[] | null;
};

export type UserConfig = {
  dns: string[];
  nbns: string[];
  split_dns: string[];
  routes: string[];
  no_routes: string[];
  iroutes: string[];
  ipv4_network: string | null;
  ipv4_netmask: string | null;
  ipv6_network: string | null;
  ipv6_subnet_prefix: number | null;
  explicit_ipv4: string | null;
  explicit_ipv6: string | null;
  rx_data_per_sec: number | null;
  tx_data_per_sec: number | null;
  net_priority: string | null;
  deny_roaming: boolean | null;
  no_udp: boolean | null;
  keepalive: number | null;
  dpd: number | null;
  mobile_dpd: number | null;
  max_same_clients: number | null;
  tunnel_all_dns: boolean | null;
  restrict_user_to_routes: boolean | null;
  stats_report_time: number | null;
  mtu: number | null;
  idle_timeout: number | null;
  mobile_idle_timeout: number | null;
  restrict_user_to_ports: string | null;
  session_timeout: number | null;
  hostname: string | null;
};

export type OtpRecord = {
  username: string;
  enabled: boolean;
};

export type SessionRecord = {
  username: string;
  vpn_ip: string | null;
  real_ip: string | null;
  device: string | null;
  rx: string | null;
  tx: string | null;
  rx_rate: string | null;
  tx_rate: string | null;
  duration_seconds: number | null;
};

export type UpstreamProfile = {
  name: string;
  // "openconnect" (default): kornode dials out itself. "external_interface":
  // this profile only points at a device that already exists on the host
  // (e.g. an externally-managed WireGuard interface) -- kornode never
  // creates/brings up/tears it down, only applies routing on top of it.
  kind: "openconnect" | "external_interface";
  server?: string | null;
  port: string;
  interface?: string | null;
  auth_type: "password" | "cert" | "p12";
  trusted_cert?: boolean;
  username?: string | null;
  cert_file?: string | null;
  key_file?: string | null;
  server_cert_pin?: string | null;
  check_host?: string | null;
  route_clients_enabled?: boolean;
  routes?: string[];
  domains?: string[];
  routes_files?: string[];
  routes_urls?: string[];
  domains_files?: string[];
  domains_urls?: string[];
  route_host_enabled?: boolean;
  host_routes?: string[];
  host_domains?: string[];
  accept_server_routes?: boolean;
  sync_url?: string | null;
  sync_interval?: number;
  sync_verify_tls?: boolean;
  routing_offset?: number | null;
  enabled: boolean;
};

export type UpstreamProfileDraft = {
  name: string;
  kind: "openconnect" | "external_interface";
  server: string;
  port: string;
  interface: string;
  auth_type: "password" | "cert" | "p12";
  trusted_cert: boolean;
  username: string;
  password: string;
  cert_file: string;
  cert_file_base64: string;
  key_file: string;
  key_file_base64: string;
  cert_pass: string;
  server_cert_pin: string;
  check_host: string;
  camouflage_secret: string;
  // Route these specific CIDRs/domains through this profile specifically,
  // regardless of which profile is active/default. Newline/comma-separated
  // in the form, same convention as GroupPolicyDraft's routes/dns.
  route_clients_enabled: boolean;
  routes: string;
  domains: string;
  routesFilesText: string;
  routesUrlsText: string;
  domainsFilesText: string;
  domainsUrlsText: string;
  // Same idea, for the HOST's own traffic through this specific profile --
  // independent toggle and lists.
  route_host_enabled: boolean;
  host_routes: string;
  host_domains: string;
  // Server-driven host routing: add the routes/split-DNS domains the
  // upstream server pushes (and, with a sync URL, keeps updating) to the
  // host lists above.
  accept_server_routes: boolean;
  sync_url: string;
  sync_interval: string;
  sync_verify_tls: boolean;
  // Explicit fwmark/table_id offset override; blank derives it from the
  // profile's position in upstream.profiles.
  routing_offset: string;
  enabled: boolean;
};

// What the upstream server pushed to one profile (handshake or sync).
export type ServerRouting = {
  accept: boolean;
  active: boolean;
  routes: string[];
  domains: string[];
  dns: string[];
  source: string;
  version: string;
  updated_at: number;
  synced_at: number;
  sync_error: string;
  warnings: string[];
};

export type UpstreamConnection = {
  profile: string;
  interface: string;
  connected: boolean;
  local_ip: string | null;
  remote: string | null;
  connected_since: string | null;
  connected_for_seconds: number | null;
  server_routing?: ServerRouting;
};

export type UpstreamStatus = {
  enabled: boolean;
  active_profile: string | null;
  interface: string;
  connected: boolean;
  local_ip: string | null;
  remote: string | null;
  connections: UpstreamConnection[];
};

export type OidcAuthSettings = {
  enabled: boolean;
  connector: "pam" | "radius";
  pam: { service: string; gid_min: number | null };
  radius: {
    config_file: string;
    groupconfig: boolean;
    nas_identifier: string | null;
    group_separator: "semicolon" | "comma";
  };
};

export type OidcProvider = {
  name: string;
  issuer_url: string;
  client_id: string;
  scopes: string[];
  username_claim: string;
  groups_claim: string;
  allowed_groups: string[];
};

export type OidcProviderDraft = OidcProvider & {
  client_secret: string;
};

export type GroupPolicy = {
  name: string;
  display_name: string | null;
  routes: string[];
  no_routes: string[];
  dns: string[];
  split_dns: string[];
  tunnel_all_dns: boolean | null;
  max_same_clients: number | null;
  session_timeout: number | null;
  idle_timeout: number | null;
  no_udp: boolean | null;
};

export type GroupPolicyDraft = {
  name: string;
  display_name: string;
  routes: string;
  no_routes: string;
  dns: string;
  split_dns: string;
  tunnel_all_dns: boolean;
  max_same_clients: string;
  session_timeout: string;
  idle_timeout: string;
  no_udp: boolean;
};

export type GroupConfigRecord = {
  name: string;
  config_exists: boolean;
  has_settings: boolean;
};

export type IdentityStatus = {
  auth: OidcAuthSettings;
  oidc_providers: OidcProvider[];
  group_policies: GroupPolicy[];
  config_per_group_dir: string | null;
  select_group_by_url: boolean;
  default_select_group: string | null;
  default_group_config: string | null;
};

export type ProcessStatus = {
  name: string;
  state: string;
  description: string;
};

export type CertificatePathStatus = {
  server_cert: string;
  server_key: string;
  ca_cert: string;
  server_cert_exists: boolean;
  server_key_exists: boolean;
  ca_cert_exists: boolean;
};

export type CertificateAuthorityStatus = {
  ca_cert: string;
  ca_key: string;
  ca_cert_exists: boolean;
  ca_key_exists: boolean;
};

export type CertificateStatus = {
  mode: string;
  ca_name: string;
  active: CertificatePathStatus;
  authority: CertificateAuthorityStatus;
  external: CertificatePathStatus;
  letsencrypt: {
    enabled: boolean;
    email: string | null;
    domains: string[];
    renew_reload: boolean;
    auto_renew_enabled: boolean;
    auto_renew_interval: number;
    auto_renew_interval_unit: IntervalUnit;
    http01_address: string | null;
    http01_port: number;
    paths: CertificatePathStatus | null;
  };
  certbot_available: boolean;
};

export type DiagnosticResult = Record<string, CommandResult>;

export type SoftwareVersion = {
  name: string;
  version: string;
  command: string[] | null;
  status: "ok" | "warning" | "missing";
};

export type LogTail = {
  name: string;
  lines: number;
  content: string;
};

export type LogFile = {
  name: string;
  size: number;
};

export type IntervalUnit = "hours" | "days" | "weeks" | "months";

export type LogRotationSettings = {
  enabled: boolean;
  max_size_mb: number;
  max_age: number;
  max_age_unit: IntervalUnit;
  keep_files: number;
};

export type ConfigSource = {
  path: string;
  exists: boolean;
  content: string;
};

export type ConfigSourceSaveResult = {
  path: string;
  written: string[];
  config: Record<string, unknown>;
  content: string;
  valid: boolean;
};

export type TerminalSettings = {
  cwd: string;
  rows: number;
  cols: number;
};

export type TerminalSession = {
  token: string;
  cwd: string;
  rows: number;
  cols: number;
};

let csrfToken: string | null = null;

export function setCsrfToken(value: string | null): void {
  csrfToken = value;
}

async function requestJson<T>(
  path: string,
  _token: string | null,
  init: RequestInit = {}
): Promise<T> {
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();
  if (csrfToken && ["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    headers.set("X-Kornode-CSRF", csrfToken);
  }
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...init, credentials: "same-origin", headers });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const payload = (await response.json()) as { detail?: unknown };
      if (payload.detail) {
        detail = formatApiDetail(payload.detail);
      }
    } catch {
      // Keep status text for non-JSON responses.
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

async function requestBlob(path: string, _token: string, init: RequestInit = {}): Promise<Blob> {
  const headers = new Headers(init.headers);
  const response = await fetch(path, { ...init, credentials: "same-origin", headers });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const payload = (await response.json()) as { detail?: unknown };
      if (payload.detail) {
        detail = formatApiDetail(payload.detail);
      }
    } catch {
      // Keep status text for non-JSON responses.
    }
    throw new Error(detail);
  }
  return response.blob();
}

function body(payload: unknown): string {
  return JSON.stringify(payload);
}

function dryRunBody(dryRun: boolean): string {
  return body({ dry_run: dryRun });
}

function formatApiDetail(detail: unknown): string {
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => formatApiDetailItem(item))
      .filter((item) => item.length > 0);
    return messages.length > 0 ? messages.join("; ") : "invalid request";
  }
  if (detail && typeof detail === "object") {
    return formatApiDetailItem(detail);
  }
  return "invalid request";
}

function formatApiDetailItem(item: unknown): string {
  if (typeof item === "string") {
    return item;
  }
  if (!item || typeof item !== "object") {
    return "";
  }
  const record = item as Record<string, unknown>;
  const message = typeof record.msg === "string" ? record.msg : "invalid value";
  const location = Array.isArray(record.loc)
    ? record.loc
        .map((part) => String(part))
        .filter((part) => part !== "body")
        .join(".")
    : "";
  return location ? `${location}: ${message}` : message;
}

export function fetchHealth(): Promise<Health> {
  return requestJson<Health>("/healthz", null);
}

export function login(
  username: string,
  password: string,
  totpCode?: string
): Promise<AuthInfo> {
  return requestJson<AuthInfo>("/api/auth/login", null, {
    method: "POST",
    body: body({ username, password, totp_code: totpCode || undefined })
  });
}

export type TotpStatus = {
  enabled: boolean;
};

export type TotpSetup = {
  secret: string;
  otpauth_uri: string;
  qr_svg: string | null;
};

export function fetchTotpStatus(token: string): Promise<TotpStatus> {
  return requestJson<TotpStatus>("/api/auth/totp/status", token);
}

export function setupTotp(token: string): Promise<TotpSetup> {
  return requestJson<TotpSetup>("/api/auth/totp/setup", token, { method: "POST" });
}

export function confirmTotp(
  token: string,
  secret: string,
  code: string
): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/auth/totp/confirm", token, {
    method: "POST",
    body: body({ secret, code })
  });
}

export function disableTotp(token: string): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/auth/totp/disable", token, { method: "POST" });
}

export function fetchAuthInfo(): Promise<AuthInfo> {
  return requestJson<AuthInfo>("/api/auth/me", null);
}

export function logout(): Promise<{ authenticated: boolean }> {
  return requestJson<{ authenticated: boolean }>("/api/auth/logout", null, {
    method: "POST"
  });
}

export function fetchConfig(token: string): Promise<Record<string, unknown>> {
  return requestJson<Record<string, unknown>>("/api/config", token);
}

export function fetchConfigSource(token: string): Promise<ConfigSource> {
  return requestJson<ConfigSource>("/api/config/source", token);
}

export function validateConfigSource(
  token: string,
  content: string
): Promise<Record<string, unknown>> {
  return requestJson<Record<string, unknown>>("/api/config/source/validate", token, {
    method: "POST",
    body: body({ content })
  });
}

export function saveConfigSource(
  token: string,
  content: string,
  writeRendered: boolean
): Promise<ConfigSourceSaveResult> {
  return requestJson<ConfigSourceSaveResult>("/api/config/source", token, {
    method: "POST",
    body: body({ content, write_rendered: writeRendered })
  });
}

export function fetchConfigDiff(token: string): Promise<{ diff: string }> {
  return requestJson<{ diff: string }>("/api/config/diff", token);
}

export function fetchRenderedConfig(token: string): Promise<Record<string, string>> {
  return requestJson<Record<string, string>>("/api/config/render", token);
}

export function writeRenderedConfig(token: string): Promise<{ written: string[] }> {
  return requestJson<{ written: string[] }>("/api/config/render", token, { method: "POST" });
}

export function saveGeneralSettings(
  token: string,
  payload: {
    timezone: string;
    log_level: "debug" | "info" | "warning" | "error";
    project_name: string;
    cli_enabled: boolean;
  }
): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/config/general-settings", token, {
    method: "POST",
    body: body(payload)
  });
}

export function saveWebSettings(
  token: string,
  payload: {
    enabled: boolean;
    listen: string;
    port: number;
    tls: boolean;
    allow_insecure_http: boolean;
    trusted_proxies: string[];
    admin_user: string;
    terminal_enabled: boolean;
    terminal_idle_timeout: number;
    terminal_max_sessions: number;
    client_sync_enabled: boolean;
    session_lifetime: number;
    session_cookie_secure: boolean;
  }
): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/web-config/settings", token, {
    method: "POST",
    body: body(payload)
  });
}

export function fetchUsers(token: string): Promise<UserRecord[]> {
  return requestJson<UserRecord[]>("/api/users", token);
}

export function createUser(
  token: string,
  username: string,
  password: string,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/users", token, {
    method: "POST",
    body: body({ username, password, dry_run: dryRun })
  });
}

export function deleteUser(token: string, username: string): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/users/${encodeURIComponent(username)}`, token, {
    method: "DELETE"
  });
}

export function changePassword(
  token: string,
  username: string,
  password: string,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/users/${encodeURIComponent(username)}/password`, token, {
    method: "POST",
    body: body({ password, dry_run: dryRun })
  });
}

export function setUserEnabled(
  token: string,
  username: string,
  enabled: boolean,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>(
    `/api/users/${encodeURIComponent(username)}/${enabled ? "enable" : "disable"}`,
    token,
    { method: "POST", body: dryRunBody(dryRun) }
  );
}

export function fetchUserConfig(token: string, username: string): Promise<UserConfig> {
  return requestJson<UserConfig>(`/api/users/${encodeURIComponent(username)}/config`, token);
}

export function saveUserConfig(
  token: string,
  username: string,
  config: UserConfig
): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/users/${encodeURIComponent(username)}/config`, token, {
    method: "PUT",
    body: body(config)
  });
}

export function deleteUserConfig(token: string, username: string): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/users/${encodeURIComponent(username)}/config`, token, {
    method: "DELETE"
  });
}

export function saveUserGroups(
  token: string,
  username: string,
  groups: string[]
): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/users/${encodeURIComponent(username)}/groups`, token, {
    method: "PUT",
    body: body({ groups })
  });
}

export function fetchGroups(token: string): Promise<GroupConfigRecord[]> {
  return requestJson<GroupConfigRecord[]>("/api/groups", token);
}

export function fetchGroupConfig(token: string, name: string): Promise<UserConfig> {
  return requestJson<UserConfig>(`/api/groups/${encodeURIComponent(name)}/config`, token);
}

export function saveGroupConfig(
  token: string,
  name: string,
  config: UserConfig
): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/groups/${encodeURIComponent(name)}/config`, token, {
    method: "PUT",
    body: body(config)
  });
}

export function deleteGroupConfig(token: string, name: string): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/groups/${encodeURIComponent(name)}/config`, token, {
    method: "DELETE"
  });
}

export function deleteGroup(token: string, name: string): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/groups/${encodeURIComponent(name)}`, token, {
    method: "DELETE"
  });
}

export function fetchOtpRecords(token: string): Promise<OtpRecord[]> {
  return requestJson<OtpRecord[]>("/api/users/otp", token);
}

export function setOtp(token: string, username: string, enabled: boolean): Promise<unknown> {
  return requestJson<unknown>(`/api/users/${encodeURIComponent(username)}/otp`, token, {
    method: enabled ? "POST" : "DELETE"
  });
}

export function fetchOtpQr(token: string, username: string): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/users/${encodeURIComponent(username)}/otp/qr`, token);
}

export function createCertificate(
  token: string,
  username: string,
  dryRun: boolean
): Promise<{ results: CommandResult[] }> {
  return requestJson<{ results: CommandResult[] }>(
    `/api/users/${encodeURIComponent(username)}/cert`,
    token,
    { method: "POST", body: dryRunBody(dryRun) }
  );
}

export function revokeCertificate(
  token: string,
  username: string,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/users/${encodeURIComponent(username)}/cert`, token, {
    method: "DELETE",
    body: dryRunBody(dryRun)
  });
}

export function createP12(
  token: string,
  username: string,
  passphrase: string | null,
  appleCompatible: boolean,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/users/${encodeURIComponent(username)}/p12`, token, {
    method: "POST",
    body: body({
      passphrase: passphrase || null,
      apple_compatible: appleCompatible,
      dry_run: dryRun
    })
  });
}

export function fetchP12(token: string, username: string): Promise<Blob> {
  return requestBlob(`/api/users/${encodeURIComponent(username)}/p12`, token);
}

export function fetchUserCert(token: string, username: string): Promise<Blob> {
  return requestBlob(`/api/users/${encodeURIComponent(username)}/cert`, token);
}

export function fetchUserKey(token: string, username: string): Promise<Blob> {
  return requestBlob(`/api/users/${encodeURIComponent(username)}/key`, token);
}

export function fetchSessions(token: string): Promise<SessionRecord[]> {
  return requestJson<SessionRecord[]>("/api/sessions", token);
}

export function kickSession(
  token: string,
  username: string,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>(`/api/sessions/${encodeURIComponent(username)}/kick`, token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function fetchRoutes(token: string): Promise<string[]> {
  return requestJson<string[]>("/api/routing/routes", token);
}

export function setRoutes(token: string, items: string[]): Promise<string[]> {
  return requestJson<string[]>("/api/routing/routes", token, {
    method: "PUT",
    body: body({ items })
  });
}

export function fetchDomains(token: string): Promise<string[]> {
  return requestJson<string[]>("/api/routing/domains", token);
}

export function setDomains(token: string, items: string[]): Promise<string[]> {
  return requestJson<string[]>("/api/routing/domains", token, {
    method: "PUT",
    body: body({ items })
  });
}

export function fetchHostRoutes(token: string): Promise<string[]> {
  return requestJson<string[]>("/api/routing/host-routes", token);
}

export function setHostRoutes(token: string, items: string[]): Promise<string[]> {
  return requestJson<string[]>("/api/routing/host-routes", token, {
    method: "PUT",
    body: body({ items })
  });
}

export function fetchHostDomains(token: string): Promise<string[]> {
  return requestJson<string[]>("/api/routing/host-domains", token);
}

export function setHostDomains(token: string, items: string[]): Promise<string[]> {
  return requestJson<string[]>("/api/routing/host-domains", token, {
    method: "PUT",
    body: body({ items })
  });
}

export type RoutingListFileStatus = {
  path: string;
  exists: boolean;
  count: number;
};

export type RoutingListUrlStatus = {
  url: string;
  count: number;
  meta: {
    url?: string;
    fetched_at?: number;
    valid?: number;
    skipped?: number;
  } | null;
};

export type RoutingListStatus = {
  files: RoutingListFileStatus[];
  urls: RoutingListUrlStatus[];
};

export type RoutingListRefreshResult = {
  status: string;
  url: string;
  total_lines: number;
  valid: number;
  skipped: number;
  sample: string[];
  saved: boolean;
  written: string[];
};

export function fetchRoutesStatus(token: string): Promise<RoutingListStatus> {
  return requestJson<RoutingListStatus>("/api/routing/routes/status", token);
}

export function fetchDomainsStatus(token: string): Promise<RoutingListStatus> {
  return requestJson<RoutingListStatus>("/api/routing/domains/status", token);
}

export function refreshRoutesUrl(
  token: string,
  url: string,
  preview: boolean
): Promise<RoutingListRefreshResult> {
  return requestJson<RoutingListRefreshResult>("/api/routing/routes/refresh", token, {
    method: "POST",
    body: body({ url, preview })
  });
}

export function refreshDomainsUrl(
  token: string,
  url: string,
  preview: boolean
): Promise<RoutingListRefreshResult> {
  return requestJson<RoutingListRefreshResult>("/api/routing/domains/refresh", token, {
    method: "POST",
    body: body({ url, preview })
  });
}

export function fetchHostRoutesStatus(token: string): Promise<RoutingListStatus> {
  return requestJson<RoutingListStatus>("/api/routing/host-routes/status", token);
}

export function fetchHostDomainsStatus(token: string): Promise<RoutingListStatus> {
  return requestJson<RoutingListStatus>("/api/routing/host-domains/status", token);
}

export function refreshHostRoutesUrl(
  token: string,
  url: string,
  preview: boolean
): Promise<RoutingListRefreshResult> {
  return requestJson<RoutingListRefreshResult>("/api/routing/host-routes/refresh", token, {
    method: "POST",
    body: body({ url, preview })
  });
}

export function refreshHostDomainsUrl(
  token: string,
  url: string,
  preview: boolean
): Promise<RoutingListRefreshResult> {
  return requestJson<RoutingListRefreshResult>("/api/routing/host-domains/refresh", token, {
    method: "POST",
    body: body({ url, preview })
  });
}

export function fetchProfileRoutesSourcesStatus(
  token: string,
  name: string
): Promise<RoutingListStatus> {
  return requestJson<RoutingListStatus>(
    `/api/upstream/profiles/${encodeURIComponent(name)}/routes-sources/status`,
    token
  );
}

export function fetchProfileDomainsSourcesStatus(
  token: string,
  name: string
): Promise<RoutingListStatus> {
  return requestJson<RoutingListStatus>(
    `/api/upstream/profiles/${encodeURIComponent(name)}/domains-sources/status`,
    token
  );
}

export function refreshProfileRoutesUrl(
  token: string,
  name: string,
  url: string,
  preview: boolean
): Promise<RoutingListRefreshResult> {
  return requestJson<RoutingListRefreshResult>(
    `/api/upstream/profiles/${encodeURIComponent(name)}/routes-sources/refresh`,
    token,
    { method: "POST", body: body({ url, preview }) }
  );
}

export function refreshProfileDomainsUrl(
  token: string,
  name: string,
  url: string,
  preview: boolean
): Promise<RoutingListRefreshResult> {
  return requestJson<RoutingListRefreshResult>(
    `/api/upstream/profiles/${encodeURIComponent(name)}/domains-sources/refresh`,
    token,
    { method: "POST", body: body({ url, preview }) }
  );
}

export function saveRoutingSettings(
  token: string,
  payload: {
    client_traffic: boolean;
    mode: string;
    tunnel_dns: boolean;
    host_traffic: boolean;
    host_mode: string;
    host_dns: string;
    main_interface: string;
    fwmark: string;
    table_id: number;
    nft_prefix: string;
    routes_files: string[];
    routes_urls: string[];
    domains_files: string[];
    domains_urls: string[];
    host_routes_files: string[];
    host_routes_urls: string[];
    host_domains_files: string[];
    host_domains_urls: string[];
  }
): Promise<{ status: string; host_dns?: { mode: string; changed: boolean; detail: string } }> {
  return requestJson<{
    status: string;
    host_dns?: { mode: string; changed: boolean; detail: string };
  }>("/api/routing/settings", token, {
    method: "POST",
    body: body(payload)
  });
}

export function reloadRouting(token: string, dryRun: boolean): Promise<CommandResult[]> {
  return requestJson<CommandResult[]>("/api/routing/reload", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function fetchNft(token: string): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/routing/nft", token);
}

export function applyNft(token: string, dryRun: boolean): Promise<CommandResult[]> {
  return requestJson<CommandResult[]>("/api/routing/nft/apply", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function cleanupNft(token: string, dryRun: boolean): Promise<CommandResult[]> {
  return requestJson<CommandResult[]>("/api/routing/nft/cleanup", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export type InternalDnsBlocklistFileStatus = {
  path: string;
  exists: boolean;
  count: number;
};

export type InternalDnsBlocklistUrlStatus = {
  url: string;
  count: number;
  meta: {
    url?: string;
    fetched_at?: number;
    valid?: number;
    skipped?: number;
  } | null;
};

export type InternalDnsStatus = {
  enabled: boolean;
  blocklist_enabled?: boolean;
  local_records_enabled?: boolean;
  listen: string;
  port: number;
  client_dns: string[];
  server_dns?: string[];
  search_domains?: string[];
  tunnel_dns?: boolean;
  default_upstreams: string[];
  forward_upstreams: string[];
  forward_domains: string[];
  blocklist_domains: string[];
  blocklist_files: InternalDnsBlocklistFileStatus[];
  blocklist_urls: InternalDnsBlocklistUrlStatus[];
  total: number;
  cache_size: number;
  log_queries: boolean;
  local_records: string[];
};

export type InternalDnsSettingsRequest = {
  resolver_enabled: boolean;
  listen: string;
  port: number;
  blocklist_enabled: boolean;
  local_records_enabled: boolean;
  server_dns: string[];
  search_domains: string[];
  tunnel_dns: boolean;
  default_upstreams: string[];
  forward_upstreams: string[];
  forward_domains: string[];
  blocklist_domains: string[];
  blocklist_files: string[];
  blocklist_urls: string[];
  cache_size: number;
  log_queries: boolean;
  local_records: string[];
};

export type InternalDnsRefreshResult = {
  status: string;
  url: string;
  total_lines: number;
  valid: number;
  skipped: number;
  sample: string[];
  saved: boolean;
  written: string[];
};

export function fetchInternalDnsStatus(token: string): Promise<InternalDnsStatus> {
  return requestJson<InternalDnsStatus>("/api/internal-dns/status", token);
}

export function saveInternalDnsSettings(
  token: string,
  payload: InternalDnsSettingsRequest
): Promise<{
  status: string;
  reconnect_required: boolean;
  commands: CommandResult[];
  internal_dns: InternalDnsStatus;
}> {
  return requestJson<{
    status: string;
    reconnect_required: boolean;
    commands: CommandResult[];
    internal_dns: InternalDnsStatus;
  }>(
    "/api/internal-dns/settings",
    token,
    {
      method: "POST",
      body: body(payload)
    }
  );
}

export function applyInternalDns(token: string): Promise<CommandResult[]> {
  return requestJson<CommandResult[]>("/api/internal-dns/apply", token, {
    method: "POST"
  });
}

export function refreshInternalDnsBlocklist(
  token: string,
  url: string,
  preview: boolean
): Promise<InternalDnsRefreshResult> {
  return requestJson<InternalDnsRefreshResult>("/api/internal-dns/blocklist/refresh", token, {
    method: "POST",
    body: body({ url, preview })
  });
}

export function fetchUpstreamStatus(token: string): Promise<UpstreamStatus> {
  return requestJson<UpstreamStatus>("/api/upstream/status", token);
}

export function fetchIdentity(token: string): Promise<IdentityStatus> {
  return requestJson<IdentityStatus>("/api/identity", token);
}

export function saveOidcSettings(
  token: string,
  payload: {
    enabled: boolean;
    connector: "pam" | "radius";
    pam_service: string;
    pam_gid_min: number | null;
    radius_config_file: string;
    radius_groupconfig: boolean;
    radius_nas_identifier: string | null;
    radius_group_separator: "semicolon" | "comma";
  }
): Promise<{ status: string; identity: IdentityStatus; reload: CommandResult | null }> {
  return requestJson<{ status: string; identity: IdentityStatus; reload: CommandResult | null }>(
    "/api/identity/oidc/settings",
    token,
    {
      method: "POST",
      body: body(payload)
    }
  );
}

export function saveIdentitySettings(
  token: string,
  payload: {
    select_group_by_url: boolean;
    default_select_group: string | null;
    default_group_config: string | null;
  }
): Promise<{ status: string; identity: IdentityStatus }> {
  return requestJson<{ status: string; identity: IdentityStatus }>("/api/identity/settings", token, {
    method: "POST",
    body: body(payload)
  });
}

export function saveOidcProvider(
  token: string,
  payload: OidcProviderDraft
): Promise<{ status: string; identity: IdentityStatus }> {
  return requestJson<{ status: string; identity: IdentityStatus }>("/api/identity/oidc/providers", token, {
    method: "POST",
    body: body({
      ...payload,
      client_secret: payload.client_secret || null
    })
  });
}

export function deleteOidcProvider(
  token: string,
  name: string
): Promise<{ status: string; identity: IdentityStatus }> {
  return requestJson<{ status: string; identity: IdentityStatus }>(
    `/api/identity/oidc/providers/${encodeURIComponent(name)}`,
    token,
    { method: "DELETE" }
  );
}

export function saveGroupPolicy(
  token: string,
  payload: GroupPolicyDraft
): Promise<{ status: string; identity: IdentityStatus }> {
  return requestJson<{ status: string; identity: IdentityStatus }>("/api/identity/groups", token, {
    method: "POST",
    body: body({
      name: payload.name,
      display_name: payload.display_name || null,
      routes: payload.routes.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      no_routes: payload.no_routes.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      dns: payload.dns.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      split_dns: payload.split_dns.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      tunnel_all_dns: payload.tunnel_all_dns,
      max_same_clients: payload.max_same_clients ? Number(payload.max_same_clients) : null,
      session_timeout: payload.session_timeout ? Number(payload.session_timeout) : null,
      idle_timeout: payload.idle_timeout ? Number(payload.idle_timeout) : null,
      no_udp: payload.no_udp
    })
  });
}

export function deleteGroupPolicy(
  token: string,
  name: string
): Promise<{ status: string; identity: IdentityStatus }> {
  return requestJson<{ status: string; identity: IdentityStatus }>(
    `/api/identity/groups/${encodeURIComponent(name)}`,
    token,
    { method: "DELETE" }
  );
}

export function fetchUpstreamProfiles(token: string): Promise<UpstreamProfile[]> {
  return requestJson<UpstreamProfile[]>("/api/upstream", token);
}

export function fetchUpstreamServerPin(
  token: string,
  server: string,
  port: number
): Promise<CertificatePin> {
  return requestJson<CertificatePin>("/api/upstream/fetch-pin", token, {
    method: "POST",
    body: body({ server, port })
  });
}

export function switchUpstream(token: string, profile: string): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/upstream/switch", token, {
    method: "POST",
    body: body({ profile })
  });
}

export function saveUpstreamSettings(
  token: string,
  payload: {
    enabled: boolean;
    interface: string;
    active_profile: string | null;
    check_interval: number;
    check_threshold: number;
    check_settle_seconds: number;
    failover: boolean;
    connect_on_boot: boolean;
  }
): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/upstream/settings", token, {
    method: "POST",
    body: body(payload)
  });
}

export function saveUpstreamProfile(
  token: string,
  payload: UpstreamProfileDraft
): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/upstream/profiles", token, {
    method: "POST",
    body: body({
      ...payload,
      username: payload.username || null,
      password: payload.password || null,
      cert_file: payload.cert_file || null,
      cert_file_base64: payload.cert_file_base64 || null,
      key_file: payload.key_file || null,
      key_file_base64: payload.key_file_base64 || null,
      cert_pass: payload.cert_pass || null,
      server_cert_pin: payload.server_cert_pin || null,
      check_host: payload.check_host || null,
      camouflage_secret: payload.camouflage_secret || null,
      routes: payload.routes.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      domains: payload.domains.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      routes_files: payload.routesFilesText.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      routes_urls: payload.routesUrlsText.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      domains_files: payload.domainsFilesText.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      domains_urls: payload.domainsUrlsText.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      host_routes: payload.host_routes.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
      host_domains: payload.host_domains
        .split(/[\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean),
      sync_url: payload.sync_url.trim() || null,
      sync_interval: Number(payload.sync_interval) || 60,
      routing_offset: payload.routing_offset.trim() ? Number(payload.routing_offset) : null
    })
  });
}

export function syncUpstreamProfile(
  token: string,
  name: string
): Promise<{ status: string; server_routing: ServerRouting }> {
  return requestJson<{ status: string; server_routing: ServerRouting }>(
    `/api/upstream/profiles/${encodeURIComponent(name)}/sync`,
    token,
    { method: "POST" }
  );
}

export function setUpstreamProfileEnabled(
  token: string,
  name: string,
  enabled: boolean
): Promise<{ status: string }> {
  return requestJson<{ status: string }>(
    `/api/upstream/profiles/${encodeURIComponent(name)}/enabled`,
    token,
    { method: "POST", body: body({ enabled }) }
  );
}

export function deleteUpstreamProfile(
  token: string,
  name: string
): Promise<{ status: string }> {
  return requestJson<{ status: string }>(
    `/api/upstream/profiles/${encodeURIComponent(name)}`,
    token,
    { method: "DELETE" }
  );
}

export function connectUpstream(token: string, dryRun: boolean): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/upstream/connect", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function disconnectUpstream(token: string, dryRun: boolean): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/upstream/disconnect", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function connectUpstreamProfile(
  token: string,
  name: string,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>(
    `/api/upstream/profiles/${encodeURIComponent(name)}/connect`,
    token,
    { method: "POST", body: dryRunBody(dryRun) }
  );
}

export function disconnectUpstreamProfile(
  token: string,
  name: string,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>(
    `/api/upstream/profiles/${encodeURIComponent(name)}/disconnect`,
    token,
    { method: "POST", body: dryRunBody(dryRun) }
  );
}

export type ServerSettings = {
  enabled: boolean;
  listen: string;
  port: number;
  udp_enabled: boolean;
  device: string;
  cn: string;
  realm: string;
  ipv4_network: string;
  dns: string[];
  search_domains: string[];
  routes: string[];
  no_routes: string[];
  max_clients: number;
  max_same_clients: number;
  keepalive: number;
  dpd: number;
  mobile_dpd: number;
  compression: boolean;
  cisco_client_compat: boolean;
  isolate_workers: boolean;
  try_mtu_discovery: boolean;
  predictable_ips: boolean;
  deny_roaming: boolean;
  ping_leases: boolean;
  dtls_legacy: boolean;
  client_bypass_protocol: boolean;
  rate_limit_ms: number;
  server_stats_reset_time: number;
  switch_to_tcp_timeout: number;
  auth_timeout: number;
  cookie_timeout: number;
  ban_time: number;
  max_ban_score: number;
  ban_reset_time: number;
  rekey_time: number;
  rekey_method: "ssl" | "new-tunnel";
  cert_user_oid: string;
  tls_priorities: string | null;
  camouflage: { enabled: boolean; secret: string | null; realm: string };
  connect_script: string | null;
  disconnect_script: string | null;
  debug_level: number;
};

export function saveServerSettings(
  token: string,
  payload: ServerSettings
): Promise<{ status: string; server: ServerSettings; reload: CommandResult | null }> {
  return requestJson<{ status: string; server: ServerSettings; reload: CommandResult | null }>(
    "/api/server/settings",
    token,
    {
      method: "POST",
      body: body(payload)
    }
  );
}

export type AuthMethodsSettingsPayload = {
  password_enabled: boolean;
  certificate_enabled: boolean;
  otp_enabled: boolean;
  otp_ocserv_oath_auth: boolean;
  otp_issuer: string;
  otp_send_by_email: boolean;
  otp_send_by_telegram: boolean;
  otp_smtp_host: string | null;
  otp_smtp_port: number;
  otp_smtp_username: string | null;
  otp_smtp_password: string | null;
  otp_smtp_from: string | null;
  otp_smtp_starttls: boolean;
  otp_smtp_test_recipient: string | null;
  otp_telegram_bot_token: string | null;
  otp_telegram_chat_id: string | null;
};

export function saveAuthMethodsSettings(
  token: string,
  payload: AuthMethodsSettingsPayload
): Promise<{ status: string; reload: CommandResult | null }> {
  return requestJson<{ status: string; reload: CommandResult | null }>("/api/server/auth-settings", token, {
    method: "POST",
    body: body(payload)
  });
}

export function testOtpEmail(
  token: string,
  payload: AuthMethodsSettingsPayload
): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/server/auth-settings/test-email", token, {
    method: "POST",
    body: body(payload)
  });
}

export function testOtpTelegram(
  token: string,
  payload: AuthMethodsSettingsPayload
): Promise<{ status: string }> {
  return requestJson<{ status: string }>("/api/server/auth-settings/test-telegram", token, {
    method: "POST",
    body: body(payload)
  });
}

export function fetchServerStatus(token: string): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/server/status", token);
}

export function fetchServerProcesses(token: string): Promise<ProcessStatus[]> {
  return requestJson<ProcessStatus[]>("/api/server/processes", token);
}

export function controlServerProcess(
  token: string,
  action: "start" | "stop" | "restart" | "status",
  process: string,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/server/process", token, {
    method: "POST",
    body: body({ action, process, dry_run: dryRun })
  });
}

export function startServer(token: string, dryRun: boolean): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/server/start", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function stopServer(token: string, dryRun: boolean): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/server/stop", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function reloadServer(token: string, dryRun: boolean): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/server/reload", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function restartServer(token: string, dryRun: boolean): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/server/restart", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function fetchDiagnostics(token: string): Promise<DiagnosticResult> {
  return requestJson<DiagnosticResult>("/api/diagnostics", token);
}

export function fetchSoftwareVersions(token: string): Promise<SoftwareVersion[]> {
  return requestJson<SoftwareVersion[]>("/api/diagnostics/software", token);
}

export interface InterfaceStats {
  interface: string | null;
  rx_bytes: number | null;
  tx_bytes: number | null;
}

export function fetchInterfaceStats(token: string): Promise<InterfaceStats> {
  return requestJson<InterfaceStats>("/api/diagnostics/interface-stats", token);
}

export function fetchLogFiles(token: string): Promise<LogFile[]> {
  return requestJson<LogFile[]>("/api/logs/files", token);
}

export function fetchLog(token: string, name: string, lines: number): Promise<LogTail> {
  const params = new URLSearchParams({ name, lines: String(lines) });
  return requestJson<LogTail>(`/api/logs?${params}`, token);
}

export function fetchLogRotationSettings(token: string): Promise<LogRotationSettings> {
  return requestJson<LogRotationSettings>("/api/logs/rotation", token);
}

export function saveLogRotationSettings(
  token: string,
  payload: LogRotationSettings
): Promise<{ status: string; settings: LogRotationSettings }> {
  return requestJson<{ status: string; settings: LogRotationSettings }>(
    "/api/logs/rotation",
    token,
    { method: "POST", body: body(payload) }
  );
}

export function runLogRotation(
  token: string
): Promise<{ status: string; rotated: string[] }> {
  return requestJson<{ status: string; rotated: string[] }>("/api/logs/rotation/run", token, {
    method: "POST",
    body: body({})
  });
}

export function fetchCertificateStatus(token: string): Promise<CertificateStatus> {
  return requestJson<CertificateStatus>("/api/certificates", token);
}

// Pin in the format openconnect's --servercert accepts (see
// backend/kornode/services/cert_pin.py).
export type CertificatePin = {
  pin: string;
  sha256: string;
  path?: string;
};

export function fetchServerCertificatePin(token: string): Promise<CertificatePin> {
  return requestJson<CertificatePin>("/api/certificates/server-pin", token);
}

export function uploadExternalCertificates(
  token: string,
  files: { serverCert: File; serverKey: File; caCert: File },
  reload: boolean
): Promise<{ status: string; reload: CommandResult | null }> {
  const form = new FormData();
  form.set("server_cert", files.serverCert);
  form.set("server_key", files.serverKey);
  form.set("ca_cert", files.caCert);
  form.set("reload", reload ? "true" : "false");
  return requestJson<{ status: string; reload: CommandResult | null }>(
    "/api/certificates/external",
    token,
    { method: "POST", body: form }
  );
}

export function regenerateCa(token: string, dryRun: boolean): Promise<{ results: CommandResult[] }> {
  return requestJson<{ results: CommandResult[] }>("/api/certificates/ca/regenerate", token, {
    method: "POST",
    body: dryRunBody(dryRun)
  });
}

export function uploadCa(
  token: string,
  files: { caCert: File; caKey: File }
): Promise<CommandResult> {
  const form = new FormData();
  form.append("ca_cert", files.caCert);
  form.append("ca_key", files.caKey);
  return requestJson<CommandResult>("/api/certificates/ca/upload", token, {
    method: "POST",
    body: form
  });
}

export function revokeCaCertificateB64(
  token: string,
  certificateB64: string,
  dryRun: boolean
): Promise<CommandResult> {
  return requestJson<CommandResult>("/api/certificates/ca/revoke", token, {
    method: "POST",
    body: body({ certificate_b64: certificateB64, dry_run: dryRun })
  });
}

export function revokeCaCertificateFile(
  token: string,
  certificate: File,
  dryRun: boolean
): Promise<CommandResult> {
  const form = new FormData();
  form.append("certificate", certificate);
  form.append("dry_run", String(dryRun));
  return requestJson<CommandResult>("/api/certificates/ca/revoke-file", token, {
    method: "POST",
    body: form
  });
}

export interface RevokedCertificate {
  subject: string;
  serial: string;
  not_before: string;
  not_after: string;
}

export function fetchRevokedCertificates(token: string): Promise<{ certificates: RevokedCertificate[] }> {
  return requestJson<{ certificates: RevokedCertificate[] }>("/api/certificates/ca/revoked", token);
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serial: string;
  not_before: string;
  not_after: string;
  sans: string[];
}

export interface CertificateInfoResponse {
  path: string;
  certificate: CertificateInfo | null;
}

export function fetchAuthorityCertificateInfo(token: string): Promise<CertificateInfoResponse> {
  return requestJson<CertificateInfoResponse>("/api/certificates/ca/info", token);
}

export function fetchServerCertificateInfo(token: string): Promise<CertificateInfoResponse> {
  return requestJson<CertificateInfoResponse>("/api/certificates/server/info", token);
}

export function fetchLetsEncryptCertificateInfo(token: string): Promise<CertificateInfoResponse> {
  return requestJson<CertificateInfoResponse>("/api/certificates/letsencrypt/info", token);
}

export function issueLetsEncryptCertificate(
  token: string,
  payload: {
    email: string;
    domains: string[];
    staging: boolean;
    reload: boolean;
    auto_renew_enabled: boolean;
    auto_renew_interval: number;
    auto_renew_interval_unit: IntervalUnit;
    dry_run: boolean;
  }
): Promise<{ result: CommandResult; reload: CommandResult | null }> {
  return requestJson<{ result: CommandResult; reload: CommandResult | null }>(
    "/api/certificates/letsencrypt/issue",
    token,
    { method: "POST", body: body(payload) }
  );
}

export function saveLetsEncryptSettings(
  token: string,
  payload: {
    enabled: boolean;
    email: string | null;
    domains: string[];
    renew_reload: boolean;
    auto_renew_enabled: boolean;
    auto_renew_interval: number;
    auto_renew_interval_unit: IntervalUnit;
    http01_address: string | null;
    http01_port: number;
  }
): Promise<{ status: string; config: Record<string, unknown> }> {
  return requestJson<{ status: string; config: Record<string, unknown> }>(
    "/api/certificates/letsencrypt/settings",
    token,
    { method: "POST", body: body(payload) }
  );
}

export function saveCertificateSettings(
  token: string,
  payload: { mode: "auto" | "external"; ca_name: string }
): Promise<{ status: string; config: Record<string, unknown> }> {
  return requestJson<{ status: string; config: Record<string, unknown> }>(
    "/api/certificates/settings",
    token,
    { method: "POST", body: body(payload) }
  );
}

export function renewLetsEncryptCertificate(
  token: string,
  reload: boolean,
  dryRun: boolean
): Promise<{ result: CommandResult; reload: CommandResult | null }> {
  return requestJson<{ result: CommandResult; reload: CommandResult | null }>(
    "/api/certificates/letsencrypt/renew",
    token,
    { method: "POST", body: body({ reload, dry_run: dryRun }) }
  );
}

export function createTerminalSession(
  token: string,
  settings: TerminalSettings
): Promise<TerminalSession> {
  return requestJson<TerminalSession>("/api/terminal/sessions", token, {
    method: "POST",
    body: body(settings)
  });
}
