import type { P12Draft } from "../app/types";
import type { UserConfig } from "../api";

export function p12DraftFor(drafts: Record<string, P12Draft>, username: string): P12Draft {
  return drafts[username] ?? { passphrase: "", appleCompatible: false };
}

export type UserConfigListKey = "dns" | "nbns" | "split_dns" | "routes" | "no_routes" | "iroutes";
export type UserConfigStringKey =
  | "ipv4_network"
  | "ipv4_netmask"
  | "ipv6_network"
  | "explicit_ipv4"
  | "explicit_ipv6"
  | "net_priority"
  | "restrict_user_to_ports"
  | "hostname";
export type UserConfigNumberKey =
  | "ipv6_subnet_prefix"
  | "rx_data_per_sec"
  | "tx_data_per_sec"
  | "keepalive"
  | "dpd"
  | "mobile_dpd"
  | "max_same_clients"
  | "stats_report_time"
  | "mtu"
  | "idle_timeout"
  | "mobile_idle_timeout"
  | "session_timeout";
export type UserConfigBoolKey =
  | "deny_roaming"
  | "no_udp"
  | "tunnel_all_dns"
  | "restrict_user_to_routes";

export function normalizeUserConfigDraft(draft: UserConfig): UserConfig {
  return {
    ...draft,
    dns: cleanList(draft.dns),
    nbns: cleanList(draft.nbns),
    split_dns: cleanList(draft.split_dns),
    routes: cleanList(draft.routes),
    no_routes: cleanList(draft.no_routes),
    iroutes: cleanList(draft.iroutes),
    ipv4_network: cleanOptional(draft.ipv4_network),
    ipv4_netmask: cleanOptional(draft.ipv4_netmask),
    ipv6_network: cleanOptional(draft.ipv6_network),
    explicit_ipv4: cleanOptional(draft.explicit_ipv4),
    explicit_ipv6: cleanOptional(draft.explicit_ipv6),
    net_priority: cleanOptional(draft.net_priority),
    restrict_user_to_ports: cleanOptional(draft.restrict_user_to_ports),
    hostname: cleanOptional(draft.hostname)
  };
}

export function cleanList(value: string[]): string[] {
  return value.map((item) => item.trim()).filter(Boolean);
}

export function cleanOptional(value: string | null): string | null {
  const trimmed = value?.trim() ?? "";
  return trimmed ? trimmed : null;
}

export function listText(value: string[]): string {
  return value.join("\n");
}

export function nullableNumber(value: string): number | null {
  if (value.trim() === "") {
    return null;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function nullableBoolean(value: string): boolean | null {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  return null;
}
