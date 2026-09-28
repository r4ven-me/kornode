import { X } from "lucide-react";
import type { CertificateContentModalState } from "../../app/types";
import { IconButton } from "../../components/ui";

export function CertificateContentDialog({
  state,
  onClose
}: {
  state: CertificateContentModalState;
  onClose: () => void;
}) {
  if (!state) {
    return null;
  }
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel certificate-content-dialog" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>{state.title}</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        {state.loading ? (
          <p className="muted-line">Loading…</p>
        ) : !state.certificate ? (
          <p className="muted-line">No certificate found at {state.path || "the expected path"}.</p>
        ) : (
          <dl className="detail-list">
            <dt>Path</dt>
            <dd>{state.path}</dd>
            <dt>Subject</dt>
            <dd>{state.certificate.subject || "—"}</dd>
            <dt>Issuer</dt>
            <dd>{state.certificate.issuer || "—"}</dd>
            <dt>Serial</dt>
            <dd>{state.certificate.serial || "—"}</dd>
            <dt>Not before</dt>
            <dd>{state.certificate.not_before || "—"}</dd>
            <dt>Not after</dt>
            <dd>{state.certificate.not_after || "—"}</dd>
            <dt>Subject alternative names</dt>
            <dd>
              {state.certificate.sans.length > 0 ? (
                <ul>
                  {state.certificate.sans.map((san, index) => (
                    <li key={`${san}-${index}`}>{san}</li>
                  ))}
                </ul>
              ) : (
                "—"
              )}
            </dd>
          </dl>
        )}
      </section>
    </div>
  );
}
