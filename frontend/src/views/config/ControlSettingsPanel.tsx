import { useEffect, useState } from "react";
import { requestJson } from "../../api";

type ControlSettings = {
  enabled: boolean;
  port: number;
  long_poll_seconds: number;
  report_interval_seconds: number;
  offline_after_seconds: number;
  cert_lifetime_days: number;
  enroll_token_ttl_minutes: number;
  bundle_history: number;
  min_agent_version: string;
  signing_key: string | null;
};

const DEFAULTS: ControlSettings = {
  enabled: false, port: 8444, long_poll_seconds: 60, report_interval_seconds: 30,
  offline_after_seconds: 90, cert_lifetime_days: 90, enroll_token_ttl_minutes: 60,
  bundle_history: 20, min_agent_version: "2.0.0", signing_key: null
};
const NUMBERS = [
  ["port", "Control plane port", 1, 65535],
  ["long_poll_seconds", "Long poll (seconds)", 1, 300],
  ["report_interval_seconds", "Report interval (seconds)", 5, 3600],
  ["offline_after_seconds", "Offline threshold (seconds)", 10, 86400],
  ["cert_lifetime_days", "Agent certificate lifetime (days)", 3, 3650],
  ["enroll_token_ttl_minutes", "Enrollment token lifetime (minutes)", 1, 1440],
  ["bundle_history", "Bundle history", 3, 500]
] as const;

type Props = {
  config: Record<string, unknown> | null;
  onNotice: (kind: "ok" | "warning" | "error", text: string) => void;
};

function readSettings(config: Props["config"]): ControlSettings {
  const control = (config?.control ?? {}) as Partial<ControlSettings>;
  // Select settings only; signing_key is a filesystem path, never key material.
  return Object.fromEntries(Object.entries(DEFAULTS).map(([key, value]) =>
    [key, control[key as keyof ControlSettings] ?? value])) as ControlSettings;
}

export function ControlSettingsPanel({ config, onNotice }: Props) {
  const [draft, setDraft] = useState(() => readSettings(config));
  const [busy, setBusy] = useState(false);
  useEffect(() => setDraft(readSettings(config)), [config]);
  return <section className="panel" data-capability="control.settings">
    <div className="panel-header"><h2>Agent control plane</h2></div>
    <p className="field-help">These settings require a hub restart. The advanced deployment field below stores only a signing-key path, never private key material. Saving does not create or rotate keys.</p>
    <form data-capability="control.settings" onSubmit={async event => {
      event.preventDefault(); setBusy(true);
      try {
        const result = await requestJson<{ control: ControlSettings }>("/api/web-config/control-settings", "session", { method: "POST", body: JSON.stringify(draft) });
        setDraft(readSettings({ control: result.control }));
        onNotice("warning", "Control settings saved. Restart the hub to apply them.");
      } catch {
        onNotice("error", "Could not save control settings. Check the values and try again.");
      } finally { setBusy(false); }
    }}>
      <fieldset className="settings-grid" disabled={busy || !config}>
        <label className="switch"><input data-config-field="control.enabled" type="checkbox" checked={draft.enabled} onChange={event => setDraft({ ...draft, enabled: event.target.checked })} /><span>Enable agent control plane</span></label>
        {NUMBERS.map(([key, label, min, max]) => <label key={key}><span>{label}</span><input data-config-field={`control.${key}`} type="number" required min={min} max={max} value={draft[key]} onChange={event => setDraft({ ...draft, [key]: Number(event.target.value) })} /></label>)}
        <label><span>Minimum agent version</span><input data-config-field="control.min_agent_version" required pattern="[0-9]+\.[0-9]+\.[0-9]+" value={draft.min_agent_version} onChange={event => setDraft({ ...draft, min_agent_version: event.target.value })} /></label>
        <label><span>Signing-key path (advanced deployment setting)</span><input data-config-field="control.signing_key" value={draft.signing_key ?? ""} aria-describedby="control-signing-key-help" placeholder="Default path (blank = null)" onChange={event => setDraft({ ...draft, signing_key: event.target.value || null })} /></label>
        <p id="control-signing-key-help" className="field-help">Restart required. Enter a filesystem path only, not a PEM key. Blank uses the default location. Saving never creates or rotates key files.</p>
      </fieldset>
      <div className="panel-footer"><button className="action-button primary" disabled={busy || !config} data-capability="control.settings">{busy ? "Working" : "Save control settings"}</button></div>
    </form>
  </section>;
}
