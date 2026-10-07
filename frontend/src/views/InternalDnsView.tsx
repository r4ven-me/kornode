import { Download, Eye, Save } from "lucide-react";
import { LastCommandPanel } from "../components/CommandOutput";
import { SettingsTabs } from "../components/SettingsTabs";
import { ActionButton, Pill } from "../components/ui";
import type { ServerSettingsDraft } from "../lib/drafts";
import type { CommandResult, InternalDnsStatus } from "../api";

export type InternalDnsDraft = {
  listen: string;
  port: number;
  blocklistEnabled: boolean;
  localRecordsEnabled: boolean;
  upstreamsText: string;
  forwardUpstreamsText: string;
  forwardDomainsText: string;
  domainsText: string;
  filesText: string;
  urlsText: string;
  cacheSize: number;
  logQueries: boolean;
  localRecordsText: string;
};

export function InternalDnsView({
  status,
  draft,
  serverDraft,
  busy,
  commandOutput,
  onClearCommand,
  onDraftChange,
  onServerDraftChange,
  onSave,
  onPreviewUrl,
  onRefreshUrl
}: {
  status: InternalDnsStatus | null;
  draft: InternalDnsDraft;
  serverDraft: ServerSettingsDraft;
  busy: string | null;
  commandOutput: CommandResult | CommandResult[] | null;
  onClearCommand: () => void;
  onDraftChange: (value: InternalDnsDraft) => void;
  onServerDraftChange: (value: ServerSettingsDraft) => void;
  onSave: () => void;
  onPreviewUrl: (url: string) => void;
  onRefreshUrl: (url: string) => void;
}) {
  // The built-in resolver is mandatory, not opt-in, whenever the VPN server
  // is enabled -- there is no switch for it here any more, just a status
  // line. Defaults to active while status hasn't loaded yet (server.enabled
  // itself defaults true).
  const resolverActive = status ? status.resolver_active : true;
  return (
    <div className="view-stack dns-view">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>DNS</h2>
            <p className="muted-line">One draft controls the DNS path used by VPN clients.</p>
          </div>
          <Pill kind={resolverActive ? "ok" : "muted"}>
            {resolverActive ? "Built-in resolver" : "Direct server DNS"}
          </Pill>
        </div>

        <div className="dns-chain" aria-label="DNS request path">
          <div className="dns-chain-node">VPN client</div>
          <span className="dns-chain-arrow">→</span>
          {!resolverActive ? (
            <div className="dns-chain-node">Direct server DNS</div>
          ) : (
            <>
              <div className="dns-chain-node accent">Built-in resolver</div>
              <span className="dns-chain-arrow">→</span>
              <div className={`dns-chain-node ${draft.localRecordsEnabled ? "active" : "inactive"}`}>
                Local records
              </div>
              <span className="dns-chain-arrow">→</span>
              <div className={`dns-chain-node ${draft.blocklistEnabled ? "active" : "inactive"}`}>
                Blocklist
              </div>
              <span className="dns-chain-arrow">→</span>
              <div className="dns-chain-node">Upstream DNS rules / upstream servers</div>
            </>
          )}
        </div>

        <p className="muted-line">
          {resolverActive
            ? "Active automatically because the VPN server is enabled -- VPN clients always use it, no opt-out."
            : "Inactive: the VPN server is disabled, so there are no VPN clients to serve it to."}
        </p>

        <div className="settings-grid dns-switches">
          <label className="switch">
            <input
              checked={draft.localRecordsEnabled}
              disabled={!resolverActive}
              onChange={(event) =>
                onDraftChange({ ...draft, localRecordsEnabled: event.target.checked })
              }
              type="checkbox"
            />
            <span>Enable local records</span>
          </label>
          <label className="switch">
            <input
              checked={draft.blocklistEnabled}
              disabled={!resolverActive}
              onChange={(event) =>
                onDraftChange({ ...draft, blocklistEnabled: event.target.checked })
              }
              type="checkbox"
            />
            <span>Enable blocklist</span>
          </label>
        </div>
      </section>

      <SettingsTabs ariaLabel="DNS settings">
        <details>
          <summary>Upstream</summary>
          <div className="settings-grid internal-dns-grid">
            <label className="blocklist-domains">
              <span>Upstream DNS servers</span>
              <textarea
                rows={3}
                value={draft.upstreamsText}
                onChange={(event) => onDraftChange({ ...draft, upstreamsText: event.target.value })}
              />
            </label>
            <label className="blocklist-domains">
              <span>Server DNS servers</span>
              <textarea
                aria-label="DNS servers (same as Server)"
                rows={3}
                value={serverDraft.dns}
                onChange={(event) => onServerDraftChange({ ...serverDraft, dns: event.target.value })}
              />
            </label>
            <label className="blocklist-domains">
              <span>Search domains</span>
              <textarea
                rows={3}
                value={serverDraft.searchDomains}
                onChange={(event) =>
                  onServerDraftChange({ ...serverDraft, searchDomains: event.target.value })
                }
              />
            </label>
          </div>
          <p className="muted-line dns-shared-note">
            Upstream DNS servers is what the built-in resolver forwards unmatched queries to --
            independent of Server DNS servers below. Server DNS servers (shared with Config →
            Server) only still matters when the VPN server itself is disabled: with no VPN
            clients to push the built-in resolver to, this is what a client-only/middle-server
            deployment uses instead.
          </p>
        </details>

        <details>
          <summary>Resolver</summary>
          <div className="settings-grid">
            <label><span>Listen address</span><input disabled={!resolverActive} value={draft.listen} onChange={(event) => onDraftChange({ ...draft, listen: event.target.value })} /></label>
            <label><span>Port</span><input disabled={!resolverActive} min={1} max={65535} type="number" value={draft.port} onChange={(event) => onDraftChange({ ...draft, port: Math.max(1, Number(event.target.value) || 53) })} /></label>
            <label><span>Cache size</span><input disabled={!resolverActive} type="number" min={0} max={10000} value={draft.cacheSize} onChange={(event) => onDraftChange({ ...draft, cacheSize: Math.max(0, Number(event.target.value) || 0) })} /></label>
            <label className="switch"><input checked={draft.logQueries} disabled={!resolverActive} onChange={(event) => onDraftChange({ ...draft, logQueries: event.target.checked })} type="checkbox" /><span>Log queries</span></label>
          </div>
        </details>

        <details>
          <summary>Local records</summary>
          <textarea
            aria-label="Local records"
            className="bulk-list-textarea"
            disabled={!resolverActive || !draft.localRecordsEnabled}
            rows={8}
            placeholder={"nas.corp.local 10.11.11.5\nprinter.corp.local 10.11.11.6"}
            value={draft.localRecordsText}
            onChange={(event) => onDraftChange({ ...draft, localRecordsText: event.target.value })}
          />
          {!draft.localRecordsEnabled && <p className="config-disabled-note">Enable local records above to edit this list.</p>}
        </details>

        <details>
          <summary>Blocklist</summary>
          <div className="panel-header"><h2>Blocklist sources</h2>{status && <Pill kind="muted">{status.total} domains</Pill>}</div>
          <div className="settings-grid internal-dns-grid">
            <label className="blocklist-domains"><span>Blocked domains</span><textarea disabled={!resolverActive || !draft.blocklistEnabled} rows={5} value={draft.domainsText} onChange={(event) => onDraftChange({ ...draft, domainsText: event.target.value })} /></label>
            <label className="blocklist-domains"><span>Blocklist files</span><textarea disabled={!resolverActive || !draft.blocklistEnabled} rows={3} value={draft.filesText} onChange={(event) => onDraftChange({ ...draft, filesText: event.target.value })} /></label>
            <label className="blocklist-domains"><span>Blocklist URLs</span><textarea disabled={!resolverActive || !draft.blocklistEnabled} rows={3} value={draft.urlsText} onChange={(event) => onDraftChange({ ...draft, urlsText: event.target.value })} /></label>
          </div>
          {status && status.blocklist_urls.length > 0 && (
            <ul className="blocklist-url-status">{status.blocklist_urls.map((entry) => (
              <li key={entry.url} className="blocklist-url-entry"><code>{entry.url}</code><div className="toolbar blocklist-url-actions"><ActionButton label="Validate URL" icon={Eye} busy={busy === `internal-dns-preview-${entry.url}`} onClick={() => onPreviewUrl(entry.url)} /><ActionButton label="Download & apply" icon={Download} busy={busy === `internal-dns-refresh-${entry.url}`} onClick={() => onRefreshUrl(entry.url)} /></div></li>
            ))}</ul>
          )}
          {!draft.blocklistEnabled && <p className="config-disabled-note">Enable the blocklist above to edit its sources.</p>}
        </details>

        <details>
          <summary>DNS forwarding</summary>
          <p className="muted-line">Forward only the listed domains to these DNS servers. Other queries use the upstream tab.</p>
          <div className="settings-grid internal-dns-grid">
            <label className="blocklist-domains"><span>DNS servers</span><textarea disabled={!resolverActive} rows={4} value={draft.forwardUpstreamsText} onChange={(event) => onDraftChange({ ...draft, forwardUpstreamsText: event.target.value })} /></label>
            <label className="blocklist-domains"><span>Domains</span><textarea disabled={!resolverActive} rows={4} value={draft.forwardDomainsText} onChange={(event) => onDraftChange({ ...draft, forwardDomainsText: event.target.value })} /></label>
          </div>
        </details>
      </SettingsTabs>

      <section className="panel dns-actions">
        <div><strong>Save and apply DNS settings.</strong><p className="muted-line">VPN clients are reconnected automatically only when client-facing DNS parameters change.</p></div>
        <div className="toolbar">
          <ActionButton label="Save" icon={Save} primary busy={busy === "internal-dns-settings" || busy === "internal-dns-apply"} onClick={onSave} />
        </div>
      </section>
      {commandOutput && (
        <LastCommandPanel
          title="Last DNS command"
          result={commandOutput}
          onClose={onClearCommand}
        />
      )}
    </div>
  );
}
