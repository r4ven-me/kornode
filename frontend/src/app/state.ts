import { Activity, FileSliders, type LucideIcon, Network, ScrollText, Server, ShieldCheck, Terminal, Users } from "lucide-react";
import { listText } from "../lib/userConfig";
import type { UpstreamProfile, UpstreamProfileDraft, UserConfig } from "../api";
import type { AppState, Tab } from "./types";

export const themeStorageKey = "kornode.theme";

export const emptyState: AppState = {
  health: null,
  serverStatus: null,
  serverProcesses: [],
  users: [],
  groups: [],
  otpRecords: [],
  sessions: [],
  routes: [],
  domains: [],
  routesStatus: null,
  domainsStatus: null,
  hostRoutes: [],
  hostDomains: [],
  hostRoutesStatus: null,
  hostDomainsStatus: null,
  upstream: null,
  upstreamProfiles: [],
  identity: null,
  internalDns: null,
  config: null,
  configSource: null,
  renderedConfig: {},
  diagnostics: null,
  logFiles: [],
  certificateStatus: null,
  softwareVersions: []
};

export const emptyUserConfig: UserConfig = {
  dns: [],
  nbns: [],
  split_dns: [],
  routes: [],
  no_routes: [],
  iroutes: [],
  ipv4_network: null,
  ipv4_netmask: null,
  ipv6_network: null,
  ipv6_subnet_prefix: null,
  explicit_ipv4: null,
  explicit_ipv6: null,
  rx_data_per_sec: null,
  tx_data_per_sec: null,
  net_priority: null,
  deny_roaming: null,
  no_udp: null,
  keepalive: null,
  dpd: null,
  mobile_dpd: null,
  max_same_clients: null,
  tunnel_all_dns: null,
  restrict_user_to_routes: null,
  stats_report_time: null,
  mtu: null,
  idle_timeout: null,
  mobile_idle_timeout: null,
  restrict_user_to_ports: null,
  session_timeout: null,
  hostname: null
};

export const emptyUpstreamProfileDraft: UpstreamProfileDraft = {
  name: "",
  kind: "openconnect",
  server: "",
  port: "443",
  interface: "",
  auth_type: "password",
  trusted_cert: false,
  username: "",
  password: "",
  cert_file: "",
  cert_file_base64: "",
  key_file: "",
  key_file_base64: "",
  cert_pass: "",
  server_cert_pin: "",
  check_host: "",
  camouflage_secret: "",
  route_clients_enabled: false,
  routes: "",
  domains: "",
  routesFilesText: "",
  routesUrlsText: "",
  domainsFilesText: "",
  domainsUrlsText: "",
  route_host_enabled: false,
  host_routes: "",
  host_domains: "",
  accept_server_routes: false,
  sync_url: "",
  sync_interval: "60",
  sync_verify_tls: false,
  routing_offset: "",
  enable: false,
  enabled: false
};

export function upstreamProfileToDraft(
  profile: UpstreamProfile,
  upstreamEnabled: boolean
): UpstreamProfileDraft {
  return {
    name: profile.name,
    kind: profile.kind,
    server: profile.server ?? "",
    port: profile.port,
    interface: profile.interface ?? "",
    auth_type: profile.auth_type,
    trusted_cert: profile.trusted_cert ?? false,
    username: profile.username ?? "",
    password: "",
    cert_file: profile.cert_file ?? "",
    cert_file_base64: "",
    key_file: profile.key_file ?? "",
    key_file_base64: "",
    cert_pass: "",
    server_cert_pin: profile.server_cert_pin ?? "",
    check_host: profile.check_host ?? "",
    // write-only, never sent back by the API (same as password/cert_pass);
    // leaving it blank on save keeps whatever secret is already stored.
    camouflage_secret: "",
    route_clients_enabled: profile.route_clients_enabled ?? true,
    routes: listText(profile.routes ?? []),
    domains: listText(profile.domains ?? []),
    routesFilesText: listText(profile.routes_files ?? []),
    routesUrlsText: listText(profile.routes_urls ?? []),
    domainsFilesText: listText(profile.domains_files ?? []),
    domainsUrlsText: listText(profile.domains_urls ?? []),
    route_host_enabled: profile.route_host_enabled ?? false,
    host_routes: listText(profile.host_routes ?? []),
    host_domains: listText(profile.host_domains ?? []),
    accept_server_routes: profile.accept_server_routes ?? false,
    sync_url: profile.sync_url ?? "",
    sync_interval: String(profile.sync_interval ?? 60),
    sync_verify_tls: profile.sync_verify_tls ?? false,
    routing_offset: profile.routing_offset != null ? String(profile.routing_offset) : "",
    // Reflects the ACTUAL current upstream.enabled, not a hardcoded true --
    // editing a profile while upstream is deliberately disabled must not
    // silently re-enable it just because this checkbox defaulted on.
    enable: upstreamEnabled,
    enabled: profile.enabled
  };
}

export const tabs: Array<{ id: Tab; label: string; icon: LucideIcon }> = [
  { id: "dashboard", label: "Dashboard", icon: Activity },
  { id: "config", label: "Config", icon: FileSliders },
  { id: "users", label: "Users", icon: Users },
  { id: "groups", label: "Groups", icon: ShieldCheck },
  { id: "sessions", label: "Sessions", icon: Server },
  { id: "diagnostics", label: "Diagnostics", icon: Network },
  { id: "logs", label: "Logs", icon: ScrollText },
  { id: "terminal", label: "Terminal", icon: Terminal }
];
