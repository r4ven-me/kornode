import { requestBlob, requestJson } from "./api";

export type JsonObject = Record<string, unknown>;
export type Agent = {
  id: number; name: string; description: string; roles: string[];
  state: "pending" | "active" | "revoked"; online: boolean;
  desired_version: number; applied_version: number; last_seen: string | null;
  cert_not_after: string | null;
  transport: { transport?: string; dpd?: number; keepalive?: number; camouflage_set?: boolean };
};
export type Prefix = { prefix: string; kind: string; export: boolean };
export type Source = { name: string; interface: string; cidr: string; export: boolean; allow_outside_pool?: boolean; description?: string };
export type Rule = { id?: string | null; from: string[]; to: unknown; via: string; kill_switch?: boolean; description?: string };
export type Policy = { sources?: Source[]; sets?: JsonObject; egress?: Rule[] };
export type Upstream = {
  name: string; interface: string; server: string; port: number; enabled?: boolean;
  transport?: string; auth_type: "password" | "cert"; username?: string;
  cert_pem?: string; server_cert_pin?: string; check_host?: string;
  dns?: string[]; credentials_set?: boolean;
};
export type AccessUser = { username: string; groups: string[]; enabled: boolean; password_set: boolean };
export type AccessListener = { configured: boolean; role?: boolean; hostname?: string; port?: number; udp?: boolean; certificate?: { not_after: string | null; pin: string | null } };
export type BundleVersion = { version: number; key_id: string; created_at: string; reason: string };
export type AgentCommand = { id: string; type: string; state: string; created_at: string; args: JsonObject; result: (JsonObject & { artefact_available?: boolean }) | null };
export type ControlStatus = { enabled: boolean; agents: number; active?: number; signing_key_id: string | null; rotation: { phase: string; promotes_at: string; warning: string } | null };
export type Detail = {
  agent: Agent; prefixes: Prefix[]; policy: Policy; upstreams: Upstream[];
  users: AccessUser[]; bundles: BundleVersion[]; reports: JsonObject[]; commands: AgentCommand[];
  access: AccessListener;
};

export function agentPath(name: string, suffix = ""): string {
  return `/api/agents/${encodeURIComponent(name)}${suffix}`;
}
export const agentGet = <T>(path: string, token: string | null) => requestJson<T>(path, token);
export const agentWrite = (path: string, method: string, body: unknown, token: string | null) =>
  requestJson<JsonObject>(path, token, { method, body: body === undefined ? undefined : JSON.stringify(body) });

export async function loadAgent(name: string, token: string | null): Promise<Detail> {
  const path = agentPath(name);
  const [agent, prefixes, policy, upstreams, users, bundles, reports, commands, access] = await Promise.all([
    agentGet<Agent>(path, token), agentGet<{ prefixes: Prefix[] }>(path + "/prefixes", token),
    agentGet<{ policy: Policy }>(path + "/policy", token), agentGet<{ upstreams: Upstream[] }>(path + "/upstreams", token),
    agentGet<{ users: AccessUser[] }>(path + "/users", token), agentGet<{ bundles: BundleVersion[] }>(path + "/bundles", token),
    agentGet<{ reports: JsonObject[] }>(path + "/reports", token), agentGet<{ commands: AgentCommand[] }>(path + "/commands", token),
    agentGet<AccessListener>(path + "/access", token)
  ]);
  return { agent, prefixes: prefixes.prefixes, policy: policy.policy, upstreams: upstreams.upstreams,
    users: users.users, bundles: bundles.bundles, reports: reports.reports, commands: commands.commands, access };
}

export async function downloadAgentArtifact(name: string, id: string, token: string | null) {
  const blob = await requestBlob(agentPath(name, `/commands/${encodeURIComponent(id)}/artifact`), token ?? "");
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = `agent-${name}-diagnostic.tar.gz`; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export type Mutate = (suffix: string, method: string, body?: unknown, confirmation?: string) => Promise<boolean>;
