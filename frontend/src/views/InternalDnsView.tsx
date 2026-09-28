import { Download, Eye, Save } from "lucide-react";
import { LastCommandPanel } from "../components/CommandOutput";
import { SettingsTabs } from "../components/SettingsTabs";
import { ActionButton, Pill } from "../components/ui";
import type { ServerSettingsDraft } from "../lib/drafts";
import type { CommandResult, InternalDnsStatus } from "../api";
import type { RoutingDraft } from "./upstream/RoutingListSourcesPanel";

export type InternalDnsDraft = {
  enabled: boolean;
  listen: string;
  port: number;
  blocklistEnabled: boolean;
  localRecordsEnabled: boolean;
  publicUpstreamsText: string;
  publicDomainsText: string;
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
  dnsServerDraft,
  serverDraft,
  resolverRequired,
  busy,
  commandOutput,
  onClearCommand,
  onDraftChange,
  onDnsServerDraftChange,
  onServerDraftChange,
  onSave,
  onPreviewUrl,
  onRefreshUrl
}: {
  status: InternalDnsStatus | null;
  draft: InternalDnsDraft;
  dnsServerDraft: RoutingDraft;
  serverDraft: ServerSettingsDraft;
  resolverRequired: boolean;
  busy: string | null;
  commandOutput: CommandResult | CommandResult[] | null;
  onClearCommand: () => void;
  onDraftChange: (value: InternalDnsDraft) => void;
  onDnsServerDraftChange: (value: RoutingDraft) => void;
  onServerDraftChange: (value: ServerSettingsDraft) => void;
  onSave: () => void;
  onPreviewUrl: (url: string) => void;
  onRefreshUrl: (url: string) => void;
}) {
  const resolverActive = draft.enabled || resolverRequired;
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
              <div className="dns-chain-node">Upstream DNS rules / default upstream</div>
            </>
          )}
        </div>

        <div className="settings-grid dns-switches">
          <label className="switch" title={resolverRequired ? "Required by split or profile domains" : undefined}>
            <input
              checked={resolverActive}
              disabled={resolverRequired}
              onChange={(event) => onDraftChange({ ...draft, enabled: event.target.checked })}
              type="checkbox"
            />
            <span>Use built-in resolver</span>
          </label>
          {resolverRequired && (
            <p className="dns-lock-note">Locked on: split/profile domains require the built-in resolver.</p>
          )}
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
          <summary>Default upstream</summary>
          <div className="settings-grid internal-dns-grid">
            <label className="blocklist-domains">
              <span>Default upstream DNS servers</span>
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
            These are the server-wide upstream resolvers. VPN clients use them directly when the
            built-in resolver is off; otherwise the built-in resolver forwards unmatched queries to them.
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
          <p className="muted-line">Forward only the listed domains to these DNS servers. Other queries use the default upstream tab.</p>
          <div className="settings-grid internal-dns-grid">
            <label className="blocklist-domains"><span>DNS servers</span><textarea disabled={!resolverActive} rows={4} value={draft.publicUpstreamsText} onChange={(event) => onDraftChange({ ...draft, publicUpstreamsText: event.target.value })} /></label>
            <label className="blocklist-domains"><span>Domains</span><textarea disabled={!resolverActive} rows={4} value={draft.publicDomainsText} onChange={(event) => onDraftChange({ ...draft, publicDomainsText: event.target.value })} /></label>
          </div>
        </details>

        <details>
          <summary>Split DNS integration</summary>
          <p className="muted-line dns-shared-note">
            This switch belongs to split routing and controls whether split-routing domains are
            resolved through the built-in resolver.
          </p>
          <div className="settings-grid">
            <label className="switch"><input checked={dnsServerDraft.tunnelDns} onChange={(event) => onDnsServerDraftChange({ ...dnsServerDraft, tunnelDns: event.target.checked })} type="checkbox" /><span>Resolve split-routing domains through the built-in resolver</span></label>
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
