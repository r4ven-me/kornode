import { Save, X } from "lucide-react";
import type { FormEvent } from "react";
import { IconButton } from "../../components/ui";
import type { RoutingListStatus, UpstreamProfileDraft } from "../../api";
import { RoutingListSourcesPanel } from "./RoutingListSourcesPanel";

// One profile's own relay lists: VPN users' destinations that always go
// through this specific profile (UpstreamProfileConfig.route_clients_enabled/
// routes/domains), edited from the Routing tab. Saved through the same
// profile endpoint as the Profiles tab's edit dialog; the draft carries the
// rest of the profile unchanged (secrets stay write-only and are kept
// server-side).
export function UpstreamRelayDialog({
  draft,
  busy,
  routesStatus,
  domainsStatus,
  onDraftChange,
  onClose,
  onSave,
  onPreviewRoutesUrl,
  onRefreshRoutesUrl,
  onPreviewDomainsUrl,
  onRefreshDomainsUrl
}: {
  draft: UpstreamProfileDraft;
  busy: string | null;
  routesStatus: RoutingListStatus | null;
  domainsStatus: RoutingListStatus | null;
  onDraftChange: (value: UpstreamProfileDraft) => void;
  onClose: () => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
  onPreviewRoutesUrl: (url: string) => void;
  onRefreshRoutesUrl: (url: string) => void;
  onPreviewDomainsUrl: (url: string) => void;
  onRefreshDomainsUrl: (url: string) => void;
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
            title="Route these specific CIDRs/domains of VPN users through this profile, regardless of which profile is the default."
          >
            <input
              checked={draft.route_clients_enabled}
              onChange={(event) =>
                onDraftChange({ ...draft, route_clients_enabled: event.target.checked })
              }
              type="checkbox"
            />
            <span>Relay VPN users&rsquo; traffic through this profile</span>
          </label>
          {draft.route_clients_enabled && (
            <div className="settings-grid field-full-width">
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
              <div className="field-full-width">
                <RoutingListSourcesPanel
                  title="Relay route sources"
                  filesLabel="Route files"
                  filesPlaceholder={"/etc/kornode/relay-routes.txt"}
                  urlsLabel="Route URLs"
                  urlsPlaceholder={"https://example.com/relay-routes.txt"}
                  disabled={!draft.route_clients_enabled}
                  disabledHint="Inert until relaying VPN users' traffic through this profile is on"
                  filesText={draft.routesFilesText}
                  urlsText={draft.routesUrlsText}
                  status={routesStatus}
                  busy={busy}
                  busyKeyPrefix="relay-routes"
                  onFilesTextChange={(value) => onDraftChange({ ...draft, routesFilesText: value })}
                  onUrlsTextChange={(value) => onDraftChange({ ...draft, routesUrlsText: value })}
                  onPreviewUrl={onPreviewRoutesUrl}
                  onRefreshUrl={onRefreshRoutesUrl}
                />
              </div>
              <div className="field-full-width">
                <RoutingListSourcesPanel
                  title="Relay domain sources"
                  filesLabel="Domain files"
                  filesPlaceholder={"/etc/kornode/relay-domains.txt"}
                  urlsLabel="Domain URLs"
                  urlsPlaceholder={"https://example.com/relay-domains.txt"}
                  disabled={!draft.route_clients_enabled}
                  disabledHint="Inert until relaying VPN users' traffic through this profile is on"
                  filesText={draft.domainsFilesText}
                  urlsText={draft.domainsUrlsText}
                  status={domainsStatus}
                  busy={busy}
                  busyKeyPrefix="relay-domains"
                  onFilesTextChange={(value) => onDraftChange({ ...draft, domainsFilesText: value })}
                  onUrlsTextChange={(value) => onDraftChange({ ...draft, domainsUrlsText: value })}
                  onPreviewUrl={onPreviewDomainsUrl}
                  onRefreshUrl={onRefreshDomainsUrl}
                />
              </div>
            </div>
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
