import type { CertificateInfo, CertificateStatus, CommandResult, ConfigSource, DiagnosticResult, GroupConfigRecord, Health, IdentityStatus, InternalDnsStatus, LogFile, OtpRecord, ProcessStatus, RevokedCertificate, RoutingListStatus, SessionRecord, SoftwareVersion, UpstreamProfile, UpstreamStatus, UserConfig, UserRecord } from "../api";

export type Tab =
  | "dashboard"
  | "users"
  | "groups"
  | "sessions"
  | "config"
  | "diagnostics"
  | "logs"
  | "terminal";

export type ConfigSection =
  | "system"
  | "server"
  | "auth"
  | "certificates"
  | "identity"
  | "internal_dns"
  | "clients"
  | "upstream"
  | "web"
  | "advanced";

// "routing" is no longer its own nav section (its settings live inside the
// "clients" and "upstream" sections, see the config section render block)
// but is kept as a distinct command-output/busy key so its nftables/route
// actions don't clobber upstream's own last-command panel.
export type CommandOutputKey = Tab | ConfigSection | "routing";

export const configSections: Array<{ id: ConfigSection; label: string }> = [
  { id: "system", label: "System" },
  { id: "server", label: "Server" },
  { id: "certificates", label: "Certificates" },
  { id: "auth", label: "Authentication" },
  { id: "identity", label: "Identity · Experimental" },
  { id: "clients", label: "Clients" },
  { id: "upstream", label: "Upstream" },
  { id: "internal_dns", label: "DNS" },
  { id: "web", label: "Web / API" },
  { id: "advanced", label: "Advanced" }
];

export type Theme = "light" | "dark";

export type Notice = {
  kind: "ok" | "warning" | "error";
  text: string;
} | null;

export type P12Draft = {
  passphrase: string;
  appleCompatible: boolean;
};

export type OidcDraft = {
  enabled: boolean;
  connector: "pam" | "radius";
  pamService: string;
  pamGidMin: string;
  radiusConfigFile: string;
  radiusGroupconfig: boolean;
  radiusNasIdentifier: string;
  radiusGroupSeparator: "semicolon" | "comma";
};

export type CommandOutput = CommandResult | CommandResult[] | null;

export type SessionRates = Record<string, { download: string | null; upload: string | null }>;

export type SessionSample = {
  rxBytes: number | null;
  txBytes: number | null;
  timestamp: number;
};

export type InterfaceSample = {
  rxBytes: number;
  txBytes: number;
  timestamp: number;
};

export type InterfaceRatePoint = {
  rx: number;
  tx: number;
};

export const INTERFACE_HISTORY_CAP = 180;

export type UserConfigModalState = {
  username: string;
  draft: UserConfig;
} | null;

export type GroupConfigModalState = {
  name: string;
  draft: UserConfig;
} | null;

export type UserGroupsModalState = {
  username: string;
  groups: string[];
} | null;

export type GroupMembersModalState = {
  name: string;
  users: string[];
} | null;

export type P12Base64ModalState = {
  username: string;
  base64: string;
} | null;

export type RevokedCertsModalState = {
  loading: boolean;
  certificates: RevokedCertificate[];
} | null;

export type CertificateContentModalState = {
  title: string;
  loading: boolean;
  path: string;
  certificate: CertificateInfo | null;
} | null;

export type AppState = {
  health: Health | null;
  serverStatus: CommandResult | null;
  serverProcesses: ProcessStatus[];
  users: UserRecord[];
  groups: GroupConfigRecord[];
  otpRecords: OtpRecord[];
  sessions: SessionRecord[];
  routes: string[];
  domains: string[];
  routesStatus: RoutingListStatus | null;
  domainsStatus: RoutingListStatus | null;
  hostRoutes: string[];
  hostDomains: string[];
  hostRoutesStatus: RoutingListStatus | null;
  hostDomainsStatus: RoutingListStatus | null;
  upstream: UpstreamStatus | null;
  upstreamProfiles: UpstreamProfile[];
  identity: IdentityStatus | null;
  internalDns: InternalDnsStatus | null;
  config: Record<string, unknown> | null;
  configSource: ConfigSource | null;
  renderedConfig: Record<string, string>;
  diagnostics: DiagnosticResult | null;
  logFiles: LogFile[];
  certificateStatus: CertificateStatus | null;
  softwareVersions: SoftwareVersion[];
};
