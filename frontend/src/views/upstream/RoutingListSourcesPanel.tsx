import { Download, Eye } from "lucide-react";
import { ActionButton, Pill } from "../../components/ui";
import type { RoutingListStatus } from "../../api";

export type RoutingDraft = {
  clientTraffic: boolean;
  mode: string;
  tunnelDns: boolean;
  hostTraffic: boolean;
  hostMode: string;
  hostDns: string;
  mainInterface: string;
  fwmark: string;
  tableId: number;
  nftPrefix: string;
  routesFilesText: string;
  routesUrlsText: string;
  domainsFilesText: string;
  domainsUrlsText: string;
  hostRoutesFilesText: string;
  hostRoutesUrlsText: string;
  hostDomainsFilesText: string;
  hostDomainsUrlsText: string;
};

export function RoutingListSourcesPanel({
  title,
  filesLabel,
  filesPlaceholder,
  urlsLabel,
  urlsPlaceholder,
  disabled,
  filesText,
  urlsText,
  status,
  busy,
  busyKeyPrefix,
  onFilesTextChange,
  onUrlsTextChange,
  onPreviewUrl,
  onRefreshUrl
}: {
  title: string;
  filesLabel: string;
  filesPlaceholder: string;
  urlsLabel: string;
  urlsPlaceholder: string;
  disabled: boolean;
  filesText: string;
  urlsText: string;
  status: RoutingListStatus | null;
  busy: string | null;
  busyKeyPrefix: string;
  onFilesTextChange: (value: string) => void;
  onUrlsTextChange: (value: string) => void;
  onPreviewUrl: (url: string) => void;
  onRefreshUrl: (url: string) => void;
}) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>{title}</h2>
        {status && <Pill kind="muted">{status.urls.length + status.files.length} sources</Pill>}
      </div>
      <div className="settings-grid internal-dns-grid">
        <label className="blocklist-domains" title={disabled ? "Inert until Upstream is enabled and Mode is Split above" : undefined}>
          <span>{filesLabel}</span>
          <textarea
            rows={3}
            disabled={disabled}
            placeholder={filesPlaceholder}
            value={filesText}
            onChange={(event) => onFilesTextChange(event.target.value)}
          />
        </label>
        <label className="blocklist-domains" title={disabled ? "Inert until Upstream is enabled and Mode is Split above" : undefined}>
          <span>{urlsLabel}</span>
          <textarea
            rows={3}
            disabled={disabled}
            placeholder={urlsPlaceholder}
            value={urlsText}
            onChange={(event) => onUrlsTextChange(event.target.value)}
          />
        </label>
      </div>
      {status && status.files.length > 0 && (
        <ul className="blocklist-file-status">
          {status.files.map((file) => (
            <li key={file.path}>
              <code>{file.path}</code>
              <span className="muted-line">
                {file.exists ? ` — ${file.count} entries` : " — file not found"}
              </span>
            </li>
          ))}
        </ul>
      )}
      {status && status.urls.length > 0 && (
        <ul className="blocklist-url-status">
          {status.urls.map((entry) => {
            const lastRefresh = entry.meta?.fetched_at
              ? new Date(entry.meta.fetched_at * 1000).toLocaleString()
              : null;
            return (
              <li key={entry.url} className="blocklist-url-entry">
                <code>{entry.url}</code>
                <span className="muted-line">
                  {entry.count} entries cached
                  {lastRefresh ? ` — last download: ${lastRefresh}` : ""}
                </span>
                <div className="toolbar blocklist-url-actions">
                  <ActionButton
                    label="Validate URL"
                    icon={Eye}
                    busy={busy === `${busyKeyPrefix}-preview-${entry.url}`}
                    onClick={() => onPreviewUrl(entry.url)}
                  />
                  <ActionButton
                    label="Download & apply"
                    icon={Download}
                    busy={busy === `${busyKeyPrefix}-refresh-${entry.url}`}
                    onClick={() => onRefreshUrl(entry.url)}
                  />
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
