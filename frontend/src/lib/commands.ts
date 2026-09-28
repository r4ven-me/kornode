import type { CommandResult } from "../api";

// A CommandResult for panel actions that don't run a real command server-side,
// so they still show up in the "last command" panel as the equivalent korctl call.
export function syntheticCommand(argv: string[], stdout = ""): CommandResult {
  return {
    argv,
    returncode: 0,
    stdout,
    stderr: "",
    dry_run: false
  };
}

export type UrlRefreshResult = {
  url: string;
  valid: number;
  skipped: number;
  sample: string[];
};

export function urlRefreshSample(result: UrlRefreshResult): string {
  return result.sample.length ? `sample:\n  ${result.sample.join("\n  ")}` : "sample: (empty)";
}
