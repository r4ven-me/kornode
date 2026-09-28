import { Save, X } from "lucide-react";
import type { FormEvent } from "react";
import { IconButton } from "../../components/ui";
import type { UpstreamProfileDraft } from "../../api";

// One client's own relay lists: VPN users' destinations that always go
// through this specific client (UpstreamProfileConfig.route_clients_enabled/
// routes/domains), edited from the Upstream section. Saved through the same
// profile endpoint as the Clients dialog; the draft carries the rest of the
// client unchanged (secrets stay write-only and are kept server-side).
export function UpstreamRelayDialog({
  draft,
  busy,
  onDraftChange,
  onClose,
  onSave
}: {
  draft: UpstreamProfileDraft;
  busy: string | null;
  onDraftChange: (value: UpstreamProfileDraft) => void;
  onClose: () => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>{`Relay through ${draft.name}`}</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        <form className="settings-grid" onSubmit={onSave}>
          <label
            className="switch field-full-width"
            title="Route these specific CIDRs/domains of VPN users through this client, regardless of which client is the default."
          >
            <input
              checked={draft.route_clients_enabled}
              onChange={(event) =>
                onDraftChange({ ...draft, route_clients_enabled: event.target.checked })
              }
              type="checkbox"
            />
            <span>Relay VPN users&rsquo; traffic through this client</span>
          </label>
          {draft.route_clients_enabled && (
            <>
              <label>
                <span>Relay routes</span>
                <textarea
                  value={draft.routes}
                  onChange={(event) => onDraftChange({ ...draft, routes: event.target.value })}
                  placeholder={"10.20.0.0/16\n203.0.113.5"}
                  rows={4}
                />
              </label>
              <label>
                <span>Relay domains</span>
                <textarea
                  value={draft.domains}
                  onChange={(event) => onDraftChange({ ...draft, domains: event.target.value })}
                  placeholder={"internal.example\ncorp.example.com"}
                  rows={4}
                />
              </label>
            </>
          )}
          <div className="modal-actions">
            <button className="primary-button" disabled={busy === "upstream-relay"} type="submit">
              <Save size={18} aria-hidden="true" />
              <span>Save relay lists</span>
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
