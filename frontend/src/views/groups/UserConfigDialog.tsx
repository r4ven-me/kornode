import { Save, Trash2, X } from "lucide-react";
import type { UserConfigModalState } from "../../app/types";
import { KorclientHint } from "../../components/KorclientHint";
import { BooleanField, ListField, NumberField, TextField } from "../../components/fields";
import { ActionButton, IconButton } from "../../components/ui";
import { splitLines } from "../../lib/drafts";
import { type UserConfigBoolKey, type UserConfigListKey, type UserConfigNumberKey, type UserConfigStringKey, nullableBoolean, nullableNumber } from "../../lib/userConfig";
import type { UserConfig } from "../../api";

export function UserConfigDialog({
  state,
  busy,
  title,
  saveBusyKey,
  deleteBusyKey,
  onChange,
  onClose,
  onDelete,
  onSave
}: {
  state: UserConfigModalState;
  busy: string | null;
  title?: string;
  saveBusyKey?: string;
  deleteBusyKey?: string;
  onChange: (draft: UserConfig) => void;
  onClose: () => void;
  onDelete: () => void;
  onSave: () => void;
}) {
  if (!state) {
    return null;
  }
  const { username, draft } = state;
  const update = (value: Partial<UserConfig>) => onChange({ ...draft, ...value });
  const updateList = (field: UserConfigListKey, value: string) =>
    update({ [field]: splitLines(value) });
  const updateString = (field: UserConfigStringKey, value: string) =>
    update({ [field]: value } as Partial<UserConfig>);
  const updateNumber = (field: UserConfigNumberKey, value: string) =>
    update({ [field]: nullableNumber(value) } as Partial<UserConfig>);
  const updateBoolean = (field: UserConfigBoolKey, value: string) =>
    update({ [field]: nullableBoolean(value) } as Partial<UserConfig>);
  const saving = busy === (saveBusyKey ?? `user-config-save-${username}`);
  const deleting = busy === (deleteBusyKey ?? `user-config-delete-${username}`);
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel user-config-dialog" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>{title ?? `${username} config`}</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        <form
          className="user-config-form"
          onSubmit={(event) => {
            event.preventDefault();
            onSave();
          }}
        >
          <section>
            <h3>Addressing</h3>
            <div className="settings-grid">
              <TextField label="Explicit IPv4" value={draft.explicit_ipv4} onChange={(value) => updateString("explicit_ipv4", value)} />
              <TextField label="Explicit IPv6" value={draft.explicit_ipv6} onChange={(value) => updateString("explicit_ipv6", value)} />
              <TextField label="IPv4 network" value={draft.ipv4_network} onChange={(value) => updateString("ipv4_network", value)} />
              <TextField label="IPv4 netmask" value={draft.ipv4_netmask} onChange={(value) => updateString("ipv4_netmask", value)} />
              <TextField label="IPv6 network" value={draft.ipv6_network} onChange={(value) => updateString("ipv6_network", value)} />
              <NumberField label="IPv6 prefix" value={draft.ipv6_subnet_prefix} min={1} max={128} onChange={(value) => updateNumber("ipv6_subnet_prefix", value)} />
              <TextField label="Hostname" value={draft.hostname} onChange={(value) => updateString("hostname", value)} />
            </div>
          </section>

          <section>
            <h3>
              DNS and routes
              <KorclientHint text="Routes and Split DNS below reach any client over the standard AnyConnect handshake, and are also synced live to connected Korvus clients (Config → Upstream, Profiles tab, on the other server: “Use routes and domains pushed by the server” with a sync URL) via GET /api/client/routing — changes apply without reconnecting." />
            </h3>
            <div className="settings-grid">
              <ListField label="DNS" value={draft.dns} onChange={(value) => updateList("dns", value)} />
              <ListField label="NBNS" value={draft.nbns} onChange={(value) => updateList("nbns", value)} />
              <ListField
                label="Split DNS"
                value={draft.split_dns}
                korclientHint="A Korvus client resolves these through its own dnsmasq and routes the results through the tunnel automatically. A stock OpenConnect client only gets DNS-suffix scoping, with no real traffic routing."
                onChange={(value) => updateList("split_dns", value)}
              />
              <ListField
                label="Routes"
                value={draft.routes}
                korclientHint="A Korvus client applies this as an nftables policy-route (kept out of the OS routing table). A stock OpenConnect client gets it as a plain pushed route instead."
                onChange={(value) => updateList("routes", value)}
              />
              <ListField label="No routes" value={draft.no_routes} onChange={(value) => updateList("no_routes", value)} />
              <ListField label="IRoutes" value={draft.iroutes} onChange={(value) => updateList("iroutes", value)} />
            </div>
          </section>

          <section>
            <h3>Limits</h3>
            <div className="settings-grid">
              <NumberField label="RX bytes/s" value={draft.rx_data_per_sec} min={0} onChange={(value) => updateNumber("rx_data_per_sec", value)} />
              <NumberField label="TX bytes/s" value={draft.tx_data_per_sec} min={0} onChange={(value) => updateNumber("tx_data_per_sec", value)} />
              <TextField label="Net priority" value={draft.net_priority} onChange={(value) => updateString("net_priority", value)} />
              <NumberField label="MTU" value={draft.mtu} min={576} max={65535} onChange={(value) => updateNumber("mtu", value)} />
              <NumberField label="Max same clients" value={draft.max_same_clients} min={1} onChange={(value) => updateNumber("max_same_clients", value)} />
              <NumberField label="Stats report time" value={draft.stats_report_time} min={0} onChange={(value) => updateNumber("stats_report_time", value)} />
            </div>
          </section>

          <section>
            <h3>Timeouts</h3>
            <div className="settings-grid">
              <NumberField label="Keepalive" value={draft.keepalive} min={0} onChange={(value) => updateNumber("keepalive", value)} />
              <NumberField label="DPD" value={draft.dpd} min={0} onChange={(value) => updateNumber("dpd", value)} />
              <NumberField label="Mobile DPD" value={draft.mobile_dpd} min={0} onChange={(value) => updateNumber("mobile_dpd", value)} />
              <NumberField label="Session timeout" value={draft.session_timeout} min={1} onChange={(value) => updateNumber("session_timeout", value)} />
              <NumberField label="Idle timeout" value={draft.idle_timeout} min={1} onChange={(value) => updateNumber("idle_timeout", value)} />
              <NumberField label="Mobile idle timeout" value={draft.mobile_idle_timeout} min={1} onChange={(value) => updateNumber("mobile_idle_timeout", value)} />
            </div>
          </section>

          <section>
            <h3>Policy</h3>
            <div className="settings-grid">
              <BooleanField label="Deny roaming" value={draft.deny_roaming} onChange={(value) => updateBoolean("deny_roaming", value)} />
              <BooleanField label="No UDP" value={draft.no_udp} onChange={(value) => updateBoolean("no_udp", value)} />
              <BooleanField label="Tunnel all DNS" value={draft.tunnel_all_dns} onChange={(value) => updateBoolean("tunnel_all_dns", value)} />
              <BooleanField label="Restrict to routes" value={draft.restrict_user_to_routes} onChange={(value) => updateBoolean("restrict_user_to_routes", value)} />
              <TextField label="Restrict to ports" value={draft.restrict_user_to_ports} onChange={(value) => updateString("restrict_user_to_ports", value)} />
            </div>
          </section>

          <div className="modal-actions">
            <ActionButton
              label="Clear"
              icon={Trash2}
              danger
              busy={deleting}
              onClick={onDelete}
            />
            <button className="primary-button" disabled={saving} type="submit">
              <Save size={18} aria-hidden="true" />
              <span>{saving ? "Working" : "Save"}</span>
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
