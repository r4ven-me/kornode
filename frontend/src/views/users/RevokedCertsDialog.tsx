import { X } from "lucide-react";
import type { RevokedCertsModalState } from "../../app/types";
import { IconButton } from "../../components/ui";

export function RevokedCertsDialog({
  state,
  onClose
}: {
  state: RevokedCertsModalState;
  onClose: () => void;
}) {
  if (!state) {
    return null;
  }
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel revoked-certs-dialog" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>Revoked certificates</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        {state.loading ? (
          <p className="muted-line">Loading…</p>
        ) : state.certificates.length === 0 ? (
          <p className="muted-line">No certificates have been revoked.</p>
        ) : (
          <div className="table-wrap">
            <table className="revoked-certs-table">
              <thead>
                <tr>
                  <th>Subject</th>
                  <th>Serial</th>
                  <th>Not before</th>
                  <th>Not after</th>
                </tr>
              </thead>
              <tbody>
                {state.certificates.map((cert, index) => (
                  <tr key={`${cert.serial}-${index}`}>
                    <td>{cert.subject || "—"}</td>
                    <td>{cert.serial || "—"}</td>
                    <td>{cert.not_before || "—"}</td>
                    <td>{cert.not_after || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
