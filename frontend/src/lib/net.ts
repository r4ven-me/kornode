import type { NetPlanOp, NetStatus } from "../api";

export function netPlanLines(ops: NetPlanOp[]): string[] {
  return ops.length > 0 ? ops.map((op) => op.text) : ["kernel matches the compiled policy"];
}

export function netDriftCount(status: NetStatus | null): number {
  if (!status?.drift) {
    return 0;
  }
  return Object.values(status.drift).reduce((total, value) => total + Number(value || 0), 0);
}
