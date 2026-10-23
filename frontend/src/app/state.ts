import { Activity, FileSliders, type LucideIcon, Network, PlugZap, Route, ScrollText, Server, ShieldCheck, Stethoscope, Terminal, Users } from "lucide-react";
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
  upstream: null,
  upstreamProfiles: [],
  identity: null,
  internalDns: null,
  config: null,
  configSource: null,
  renderedConfig: {},
  diagnostics: null,
  doctor: null,
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
  enabled: false
};

export function upstreamProfileToDraft(profile: UpstreamProfile): UpstreamProfileDraft {
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
    enabled: profile.enabled
  };
}

/** Sidebar groups, in the order an operator meets them: who connects, where traffic goes, then upkeep. */
export type TabGroup = "overview" | "access" | "routing" | "system";

export const tabGroups: Array<{ id: TabGroup; label: string | null }> = [
  { id: "overview", label: null },
  { id: "access", label: "Access" },
  { id: "routing", label: "Routing" },
  { id: "system", label: "System" }
];

export const tabs: Array<{ id: Tab; label: string; icon: LucideIcon; group: TabGroup; description: string }> = [
  { id: "dashboard", label: "Dashboard", icon: Activity, group: "overview", description: "Server state, software versions and interface load" },
  { id: "users", label: "Users", icon: Users, group: "access", description: "VPN accounts: passwords, certificates, one-time codes" },
  { id: "groups", label: "Groups", icon: ShieldCheck, group: "access", description: "Shared ocserv settings for a set of users" },
  { id: "sessions", label: "Sessions", icon: PlugZap, group: "access", description: "Who is connected right now" },
  { id: "network", label: "Network", icon: Route, group: "routing", description: "Where client traffic goes: egress rules and attached networks" },
  { id: "agents", label: "Agents", icon: Server, group: "routing", description: "Other servers joined to this hub" },
  { id: "fabric", label: "Fabric", icon: Network, group: "routing", description: "Addressing and DNS of the network between the hub and agents" },
  { id: "config", label: "Config", icon: FileSliders, group: "system", description: "Server, certificates, authentication, upstreams and backups" },
  { id: "diagnostics", label: "Diagnostics", icon: Stethoscope, group: "system", description: "Probe commands and the doctor's health checks" },
  { id: "logs", label: "Logs", icon: ScrollText, group: "system", description: "Log files and their rotation" },
  { id: "terminal", label: "Terminal", icon: Terminal, group: "system", description: "Shell on the server" }
];
