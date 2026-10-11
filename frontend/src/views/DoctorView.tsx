import { Table } from "../components/Table";
import { Pill } from "../components/ui";
import type { DoctorResult } from "../api";

export function DoctorView({ doctor }: { doctor: DoctorResult | null }) {
  return (
    <section className="panel" data-capability="doctor">
      <h3>Doctor</h3>
      <Table columns={["Check", "Status", "Details"]} empty="No doctor results">
        {Object.entries(doctor ?? {}).map(([name, check]) => (
          <tr key={name}>
            <td colSpan={3}>
              <details className="diagnostic-probe">
                <summary>
                  <strong>{name}</strong>
                  <Pill kind={check.ok ? "ok" : "error"}>{check.ok ? "ok" : "fail"}</Pill>
                </summary>
                <div className="diagnostic-probe-output">
                  <div><span>Stdout</span><pre>{check.stdout || "—"}</pre></div>
                  <div><span>Stderr</span><pre>{check.stderr || "—"}</pre></div>
                </div>
              </details>
            </td>
          </tr>
        ))}
      </Table>
    </section>
  );
}
