import type { CommandResult } from "../api";

export function diagnosticKind(result: CommandResult): "ok" | "warning" | "error" {
  if (result.returncode !== 0) {
    return "error";
  }
  const text = `${result.stdout} ${result.stderr}`.toLowerCase();
  if (text.includes("not installed yet") || text.includes("not ready")) {
    return "warning";
  }
  return "ok";
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "operation failed";
}

export function isAuthError(text: string): boolean {
  return (
    text.includes("authentication required") ||
    text.includes("invalid credentials") ||
    text.includes("admin password is not configured") ||
    text.includes("401")
  );
}
