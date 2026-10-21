import { Save, X } from "lucide-react";
import type { FormEvent } from "react";
import { SettingsTabs } from "../../components/SettingsTabs";
import { IconButton } from "../../components/ui";
import type { RoutingDraft } from "../../lib/drafts";

export function UpstreamProfilesSettingsDialog({
  upstreamInterface,
  checkInterval,
  checkThreshold,
  checkSettleSeconds,
  failover,
  connectOnBoot,
  checkHost,
  hasActiveProfile,
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
          <details className="settings-details upstream-settings-section" data-capability="routing.host_dns.status">
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

          <details className="settings-details upstream-settings-section" data-capability="routing.settings">
            <summary>Host DNS &amp; uplink</summary>
            <div className="settings-grid settings-details-body">
              <label
                title="Domain-based host routing only sees lookups that go through the built-in dnsmasq. Needs network_mode: host and a mount: resolv.conf → '/etc/resolv.conf:/host/etc/resolv.conf' (restored when kornode stops); systemd-resolved → '/etc/systemd/resolved.conf.d:/host/resolved.conf.d' (then restart systemd-resolved on the host once)."
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
            </div>
          </details>
          </SettingsTabs>

          <div className="modal-actions">
            <button
              className="primary-button"
              disabled={busy === "upstream-settings" || busy === "routing-settings"}
              type="submit"
              data-capability="upstream.settings"
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
