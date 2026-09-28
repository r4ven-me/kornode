import { Table } from "../components/Table";
import { Pill } from "../components/ui";
import { diagnosticKind } from "../lib/errors";
import type { DiagnosticResult } from "../api";

export function DiagnosticsView({ diagnostics }: { diagnostics: DiagnosticResult | null }) {
  return (
    <section className="panel">
      <Table columns={["Probe", "Status", "Stdout", "Stderr"]} empty="No diagnostics">
        {Object.entries(diagnostics ?? {}).map(([name, result]) => (
          <tr key={name}>
            <td colSpan={4}>
              <details className="diagnostic-probe">
                <summary>
                  <strong>{name}</strong>
                  <Pill kind={diagnosticKind(result)}>{result.returncode}</Pill>
                </summary>
                <div className="diagnostic-probe-output">
                  <div><span>Command</span><code>{result.argv.join(" ")}</code></div>
                  <div><span>Stdout</span><pre>{result.stdout || "—"}</pre></div>
                  <div><span>Stderr</span><pre>{result.stderr || "—"}</pre></div>
                </div>
              </details>
            </td>
          </tr>
        ))}
      </Table>
    </section>
  );
}
