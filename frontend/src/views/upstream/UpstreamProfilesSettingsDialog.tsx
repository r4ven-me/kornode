import { Save, X } from "lucide-react";
import type { FormEvent } from "react";
import { BulkListEditor } from "../../components/BulkListEditor";
import { SettingsTabs } from "../../components/SettingsTabs";
import { IconButton } from "../../components/ui";
import { type RoutingDraft, RoutingListSourcesPanel } from "./RoutingListSourcesPanel";
import type { RoutingListStatus } from "../../api";

export function UpstreamProfilesSettingsDialog({
  upstreamInterface,
  checkInterval,
  checkThreshold,
  checkSettleSeconds,
  failover,
  connectOnBoot,
  checkHost,
  hasActiveProfile,
  upstreamEnabled,
  hostRoutes,
  hostDomains,
  hostRoutesStatus,
  hostDomainsStatus,
  routingDraft,
  busy,
  onInterfaceChange,
  onCheckIntervalChange,
  onCheckThresholdChange,
  onCheckSettleSecondsChange,
  onFailoverChange,
  onConnectOnBootChange,
  onCheckHostChange,
  onRoutingDraftChange,
  onSaveHostRoutes,
  onSaveHostDomains,
  onPreviewHostRoutesUrl,
  onRefreshHostRoutesUrl,
  onPreviewHostDomainsUrl,
  onRefreshHostDomainsUrl,
  onClose,
  onSave
}: {
  upstreamInterface: string;
  checkInterval: number;
  checkThreshold: number;
  checkSettleSeconds: number;
  failover: boolean;
  connectOnBoot: boolean;
  checkHost: string;
  hasActiveProfile: boolean;
  upstreamEnabled: boolean;
  hostRoutes: string[];
  hostDomains: string[];
  hostRoutesStatus: RoutingListStatus | null;
  hostDomainsStatus: RoutingListStatus | null;
  routingDraft: RoutingDraft;
  busy: string | null;
  onInterfaceChange: (value: string) => void;
  onCheckIntervalChange: (value: number) => void;
  onCheckThresholdChange: (value: number) => void;
  onCheckSettleSecondsChange: (value: number) => void;
  onFailoverChange: (value: boolean) => void;
  onConnectOnBootChange: (value: boolean) => void;
  onCheckHostChange: (value: string) => void;
  onRoutingDraftChange: (value: RoutingDraft) => void;
  onSaveHostRoutes: (items: string[]) => void;
  onSaveHostDomains: (items: string[]) => void;
  onPreviewHostRoutesUrl: (url: string) => void;
  onRefreshHostRoutesUrl: (url: string) => void;
  onPreviewHostDomainsUrl: (url: string) => void;
  onRefreshHostDomainsUrl: (url: string) => void;
  onClose: () => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>Upstream profiles settings</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        <form className="upstream-settings-form" onSubmit={onSave}>
          <SettingsTabs ariaLabel="Upstream profiles settings">
          <details className="settings-details upstream-settings-section">
            <summary>Connection &amp; health</summary>
            <div className="settings-grid settings-details-body">
              <label>
                <span>Interface</span>
                <input
                  value={upstreamInterface}
                  onChange={(event) => onInterfaceChange(event.target.value)}
                />
              </label>
              <label title="Health-check target for the default profile, pinged through its tunnel">
                <span>Check host</span>
                <input
                  value={checkHost}
                  onChange={(event) => onCheckHostChange(event.target.value)}
                  placeholder="1.1.1.1"
                  disabled={!hasActiveProfile}
                />
              </label>
              <label>
                <span>Check interval (s)</span>
                <input
                  type="number"
                  value={checkInterval}
                  onChange={(event) =>
                    onCheckIntervalChange(Math.max(1, Number(event.target.value) || 5))
                  }
                />
              </label>
              <label>
                <span>Check threshold</span>
                <input
                  type="number"
                  value={checkThreshold}
                  onChange={(event) =>
                    onCheckThresholdChange(Math.max(1, Number(event.target.value) || 3))
                  }
                />
              </label>
              <label title="Grace window after a successful reconnect during which health-check failures aren't counted yet, so a still-settling tunnel can't immediately trigger another reconnect">
                <span>Check settle (s)</span>
                <input
                  type="number"
                  value={checkSettleSeconds}
                  onChange={(event) =>
                    onCheckSettleSecondsChange(Math.max(0, Number(event.target.value) || 0))
                  }
                />
              </label>
              <label
                className="switch"
                title="When health checks fail, try the other configured profiles in turn (after reconnecting the default one first)"
              >
                <input
                  checked={failover}
                  onChange={(event) => onFailoverChange(event.target.checked)}
                  type="checkbox"
                />
                <span>Failover</span>
              </label>
              <label
                className="switch"
                title="Whether the watchdog dials the default profile on its own the first time it sees it down after the server/container starts. Off leaves it disconnected after a restart until an admin connects it manually -- once any connection succeeds, normal reconnect-on-failure resumes regardless of this flag."
              >
                <input
                  checked={connectOnBoot}
                  onChange={(event) => onConnectOnBootChange(event.target.checked)}
                  type="checkbox"
                />
                <span>Connect on boot</span>
              </label>
            </div>
          </details>

          <details className="settings-details upstream-settings-section">
            <summary>Host traffic</summary>
            <label
              title="Domain-based host routing (host domains, split-DNS pushed by a server) only sees lookups that go through the built-in dnsmasq. Needs network_mode: host and a mount: resolv.conf → '/etc/resolv.conf:/host/etc/resolv.conf' (restored when kornode stops); systemd-resolved → '/etc/systemd/resolved.conf.d:/host/resolved.conf.d' (then restart systemd-resolved on the host once)."
            >
              <span>Host DNS</span>
              <select
                value={routingDraft.hostDns}
                onChange={(event) =>
                  onRoutingDraftChange({ ...routingDraft, hostDns: event.target.value })
                }
              >
                <option value="off">Leave the host resolver alone</option>
                <option value="resolv_conf">Point /etc/resolv.conf at dnsmasq</option>
                <option value="resolved">systemd-resolved drop-in</option>
              </select>
            </label>
            <SettingsTabs ariaLabel="Host traffic settings">
              <details className="settings-details">
                <summary>Routing settings</summary>
                <div className="settings-details-body">
                  <p className="muted-line">
                    Does this host itself send its own outbound traffic through the default
                    profile? Each profile can also carry its own host routes (and the lists its
                    server pushes) -- see the profile&rsquo;s edit dialog.
                    {!upstreamEnabled && " Inert until upstream profiles are enabled."}
                  </p>
                  <label
                    title={
                      routingDraft.hostPolicy === "full"
                        ? "Caution: matches ALL host-originated traffic, which can also capture the outbound Upstream connection itself and cause a routing loop unless your network already routes that address another way. Prefer Split with a curated route list when precision matters."
                        : undefined
                    }
                  >
                    <span>Route this host&rsquo;s own traffic through the default profile</span>
                    <select
                      disabled={!upstreamEnabled}
                      value={routingDraft.hostPolicy}
                      onChange={(event) =>
                        onRoutingDraftChange({ ...routingDraft, hostPolicy: event.target.value })
                      }
                    >
                      <option value="off">Off</option>
                      <option value="full">Full (all host traffic)</option>
                      <option value="split">Split (routes/domains in the Host routes tab)</option>
                    </select>
                  </label>
                </div>
              </details>

              <details className="settings-details">
                <summary>Host routes</summary>
                <div className="settings-details-body">
                  {routingDraft.hostPolicy === "split" ? (
                    <div className="routing-substep">
                      <p className="muted-line">
                        Own list, separate from the Routing tab&rsquo;s relay lists -- the host
                        follows these routes/domains, not the VPN users&rsquo;.
                      </p>
                      <section className="split">
                        <BulkListEditor
                          title="Host routes"
                          items={hostRoutes}
                          placeholder={"10.30.0.0/16\n203.0.113.9"}
                          busy={busy === "save-host-routes"}
                          disabled={!upstreamEnabled}
                          onSave={onSaveHostRoutes}
                        />
                        <BulkListEditor
                          title="Host domains"
                          items={hostDomains}
                          placeholder={"intranet.example\ncorp-internal.example.com"}
                          busy={busy === "save-host-domains"}
                          disabled={!upstreamEnabled}
                          onSave={onSaveHostDomains}
                        />
                      </section>
                    </div>
                  ) : (
                    <p className="muted-line">
                      Turn on host traffic with Host mode = Split (Routing settings) to edit a
                      route/domain list here.
                    </p>
                  )}
                </div>
              </details>

              <details className="settings-details">
                <summary>Files &amp; links</summary>
                <div className="settings-details-body">
                  {routingDraft.hostPolicy === "split" ? (
                    <div className="routing-substep">
                      <section className="split">
                        <RoutingListSourcesPanel
                          title="Host route sources"
                          urlsLabel="Host route URLs (one per line)"
                          urlsPlaceholder={"https://lists.example.com/host-routes.txt"}
                          disabled={!upstreamEnabled}
                          urlsText={routingDraft.hostRoutesUrlsText}
                          status={hostRoutesStatus}
                          busy={busy}
                          busyKeyPrefix="host-routes"
                          onUrlsTextChange={(value) =>
                            onRoutingDraftChange({ ...routingDraft, hostRoutesUrlsText: value })
                          }
                          onPreviewUrl={onPreviewHostRoutesUrl}
                          onRefreshUrl={onRefreshHostRoutesUrl}
                        />
                        <RoutingListSourcesPanel
                          title="Host domain sources"
                          urlsLabel="Host domain URLs (one per line)"
                          urlsPlaceholder={"https://lists.example.com/host-domains.txt"}
                          disabled={!upstreamEnabled}
                          urlsText={routingDraft.hostDomainsUrlsText}
                          status={hostDomainsStatus}
                          busy={busy}
                          busyKeyPrefix="host-domains"
                          onUrlsTextChange={(value) =>
                            onRoutingDraftChange({ ...routingDraft, hostDomainsUrlsText: value })
                          }
                          onPreviewUrl={onPreviewHostDomainsUrl}
                          onRefreshUrl={onRefreshHostDomainsUrl}
                        />
                      </section>
                      <p className="muted-line">
                        Host route/domain sources are saved together with the rest of this
                        dialog (Save settings below) -- fill these in, click Save, then
                        validate/download each URL.
                      </p>
                    </div>
                  ) : (
                    <p className="muted-line">
                      Turn on host traffic with Host mode = Split (Routing settings) to
                      configure external route/domain sources here.
                    </p>
                  )}
                </div>
              </details>
            </SettingsTabs>
          </details>

          <details className="settings-details upstream-settings-section">
            <summary>Advanced</summary>
            <div className="settings-grid settings-details-body">
              <label>
                <span>Main interface</span>
                <input
                  value={routingDraft.mainInterface}
                  onChange={(event) =>
                    onRoutingDraftChange({ ...routingDraft, mainInterface: event.target.value })
                  }
                  placeholder="auto"
                />
              </label>
              <label>
                <span>fwmark</span>
                <input
                  value={routingDraft.fwmark}
                  onChange={(event) =>
                    onRoutingDraftChange({ ...routingDraft, fwmark: event.target.value })
                  }
                />
              </label>
              <label>
                <span>Routing table id</span>
                <input
                  type="number"
                  value={routingDraft.tableId}
                  onChange={(event) =>
                    onRoutingDraftChange({
                      ...routingDraft,
                      tableId: Math.max(1, Number(event.target.value) || 1201)
                    })
                  }
                />
              </label>
              <label>
                <span>nftables prefix</span>
                <input
                  value={routingDraft.nftPrefix}
                  onChange={(event) =>
                    onRoutingDraftChange({ ...routingDraft, nftPrefix: event.target.value })
                  }
                />
              </label>
            </div>
          </details>
          </SettingsTabs>

          <div className="modal-actions">
            <button
              className="primary-button"
              disabled={busy === "upstream-settings" || busy === "routing-settings"}
              type="submit"
            >
              <Save size={18} aria-hidden="true" />
              <span>Save</span>
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
