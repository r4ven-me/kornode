import type { AppState } from "../app/types";
import type { CommandResult } from "../api";

export function serverRuntimeState(result: CommandResult | null): "running" | "stopped" | "unknown" {
  if (!result) {
    return "unknown";
  }
  const text = `${result.stdout}\n${result.stderr}`.toLowerCase();
  if (/\bocserv\s+running\b/.test(text)) {
    return "running";
  }
  if (/\bocserv\s+(stopped|exited|fatal|backoff|unknown)\b/.test(text)) {
    return "stopped";
  }
  return "unknown";
}

export function dashboardProcessCount(state: AppState): { running: number; total: number } {
  if (state.serverProcesses.length > 0) {
    return {
      running: state.serverProcesses.filter((process) => process.state === "RUNNING").length,
      total: state.serverProcesses.length
    };
  }
  return serverStatusProcessCount(state.serverStatus);
}

export function serverStatusProcessCount(result: CommandResult | null): { running: number; total: number } {
  const processLines = (result?.stdout ?? "")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => /\b(?:RUNNING|STOPPED|FATAL|BACKOFF|STARTING)\b/.test(line));
  return {
    running: processLines.filter((line) => /\bRUNNING\b/.test(line)).length,
    total: processLines.length
  };
}
