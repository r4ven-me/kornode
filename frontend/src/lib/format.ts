import type { SessionRecord } from "../api";

export function formatBytes(value: number): string {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let size = value;
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {
    size /= 1000;
    unit += 1;
  }
  if (unit === 0) {
    return `${Math.round(size)} ${units[unit]}`;
  }
  return `${size >= 10 ? size.toFixed(1) : size.toFixed(2)} ${units[unit]}`;
}

export function formatTraffic(value: string | null): string {
  if (!value) {
    return "-";
  }
  const cleaned = value
    .replace(/\b(?:RX|TX)\s*[:=]\s*/gi, "")
    .replace(/\s+/g, " ")
    .trim();
  const parenthesized = cleaned.match(/\(([^)]+)\)/);
  if (parenthesized) {
    return normalizeByteUnit(parenthesized[1]);
  }
  const bytes = cleaned.match(/^\d+(?:\.\d+)?$/);
  if (bytes) {
    return formatBytes(Number(bytes[0]));
  }
  return normalizeByteUnit(cleaned);
}

export function sessionKey(session: SessionRecord): string {
  return `${session.username}:${session.vpn_ip ?? ""}:${session.real_ip ?? ""}`;
}

export function parseTrafficBytes(value: string | null): number | null {
  if (!value) {
    return null;
  }
  const cleaned = value
    .replace(/\b(?:RX|TX)\s*[:=]\s*/gi, "")
    .replace(/\([^)]*\)/g, "")
    .replace(/\s+/g, " ")
    .trim();
  const match = cleaned.match(/^(\d+(?:\.\d+)?)\s*([kmgtp]?i?b|bytes?)?$/i);
  if (!match) {
    return null;
  }
  const amount = Number(match[1]);
  const unit = (match[2] ?? "bytes").toLowerCase();
  const multipliers: Record<string, number> = {
    b: 1,
    byte: 1,
    bytes: 1,
    kb: 1000,
    mb: 1000 ** 2,
    gb: 1000 ** 3,
    tb: 1000 ** 4,
    pb: 1000 ** 5,
    kib: 1024,
    mib: 1024 ** 2,
    gib: 1024 ** 3,
    tib: 1024 ** 4,
    pib: 1024 ** 5
  };
  return amount * (multipliers[unit] ?? 1);
}

export function rateFromDelta(
  previous: number | null,
  current: number | null,
  elapsedSeconds: number
): string | null {
  if (previous === null || current === null) {
    return null;
  }
  const delta = Math.max(current - previous, 0);
  return `${formatBytes(delta / elapsedSeconds)}/s`;
}

export function normalizeByteUnit(value: string): string {
  return value
    .replace(/\bKiB\b/g, "KB")
    .replace(/\bMiB\b/g, "MB")
    .replace(/\bGiB\b/g, "GB")
    .replace(/\bTiB\b/g, "TB")
    .trim();
}

export function formatTrafficRate(value: string): string {
  const normalized = normalizeByteUnit(value.replace(/\s+/g, " ").trim());
  if (/\b(?:B|KB|MB|GB|TB|PB)\/s\b/i.test(normalized)) {
    return normalized;
  }
  return normalized
    .replace(/\bbytes\/sec\b/i, "B/s")
    .replace(/\bbytes per second\b/i, "B/s")
    .replace(/\bsec\b/i, "s");
}

export function formatDuration(seconds: number | null): string {
  if (typeof seconds !== "number" || Number.isNaN(seconds) || seconds < 0) {
    return "-";
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
}
