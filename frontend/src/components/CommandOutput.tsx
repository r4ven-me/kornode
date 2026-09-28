import { X } from "lucide-react";
import type { CommandOutput } from "../app/types";
import type { CommandResult } from "../api";
import { EmptyState, IconButton } from "./ui";

export function LastCommandPanel({
  title,
  result,
  onClose
}: {
  title: string;
  result: CommandOutput;
  onClose: () => void;
}) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>{title}</h2>
        <IconButton label="Close command output" icon={X} onClick={onClose} />
      </div>
      <CommandBlock result={result} />
    </section>
  );
}

export function CommandBlock({ result, onClose }: { result: CommandOutput; onClose?: () => void }) {
  if (!result) {
    return <EmptyState text="No command output" />;
  }
  const results = Array.isArray(result) ? result : [result];
  const svgResults = results.filter((item) => isSvgOutput(item.stdout));
  return (
    <div className="command-list">
      {onClose && (
        <div className="command-actions">
          <IconButton label="Close command output" icon={X} onClick={onClose} />
        </div>
      )}
      {svgResults.map((item, index) => (
        <div
          className="qr-preview"
          dangerouslySetInnerHTML={{ __html: item.stdout }}
          key={`svg-${index}`}
        />
      ))}
      <pre>{results.map(formatCommandResult).join("\n\n")}</pre>
    </div>
  );
}

export function isSvgOutput(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.startsWith("<svg") || trimmed.startsWith("<?xml");
}

export function formatCommandResult(item: CommandResult): string {
  const stdout = isSvgOutput(item.stdout) ? "[svg output rendered above]" : item.stdout || "";
  if (!stdout && !item.stderr && item.returncode === 0) {
    return `$ ${item.argv.join(" ")}
returncode: 0
dry_run: ${item.dry_run}
output: command completed successfully`;
  }
  return `$ ${item.argv.join(" ")}
returncode: ${item.returncode}
dry_run: ${item.dry_run}

stdout:
${stdout}

stderr:
${item.stderr || ""}`;
}
