import { useEffect, useRef, useState } from "react";
import type { JsonObject } from "../../agentsApi";

const FIELDS = [
  ["routes", "Routes"], ["domains", "Domains"],
  ["route_urls", "Route list URLs"], ["domain_urls", "Domain list URLs"]
] as const;

export function DestinationFields({ value, label, disabled, onChange }: {
  value: JsonObject; label: string; disabled: boolean; onChange: (value: JsonObject) => void;
}) {
  return <div className="settings-grid">
    {FIELDS.map(([key, title]) => <DestinationLines key={key} field={key} label={`${label} ${title.toLowerCase()}`} title={title} disabled={disabled}
      values={Array.isArray(value[key]) ? value[key] as string[] : []}
      onChange={values => onChange({ ...value, [key]: values })} />)}
  </div>;
}

function DestinationLines({ field, values, label, title, disabled, onChange }: {
  field: string; values: string[]; label: string; title: string; disabled: boolean; onChange: (values: string[]) => void;
}) {
  const [text, setText] = useState(values.join("\n"));
  const serialized = JSON.stringify(values);
  const last = useRef(serialized);
  useEffect(() => {
    if (last.current !== serialized) {
      last.current = serialized;
      setText((JSON.parse(serialized) as string[]).join("\n"));
    }
  }, [serialized]);
  return <label><span>{title} (one per line)</span>
    <textarea data-config-field={`DestSet.${field}`} aria-label={label} rows={3} disabled={disabled} value={text} onChange={event => {
      setText(event.target.value);
      const next = event.target.value.split(/\r?\n/).map(item => item.trim()).filter(Boolean);
      last.current = JSON.stringify(next); onChange(next);
    }} />
  </label>;
}

export function DestinationSets({ sets, disabled, onChange }: {
  sets: JsonObject; disabled: boolean; onChange: (value: JsonObject) => void;
}) {
  const [name, setName] = useState("");
  return <section className="view-stack" aria-label="Destination sets">
    <h3>Destination sets</h3>
    {Object.entries(sets).map(([key, value]) => <fieldset key={key} disabled={disabled}>
      <legend>{key}</legend>
      <DestinationFields value={(value ?? {}) as JsonObject} label={`Set ${key}`} disabled={disabled} onChange={next => onChange({ ...sets, [key]: next })} />
      <button type="button" className="action-button danger" onClick={() => {
        const next = { ...sets }; delete next[key]; onChange(next);
      }}>Remove destination set {key}</button>
    </fieldset>)}
    <div className="settings-grid">
      <label><span>New destination set name</span><input disabled={disabled} value={name} onChange={event => setName(event.target.value)} /></label>
      <button type="button" className="action-button" disabled={disabled || !name.trim() || Object.hasOwn(sets, name.trim())} onClick={() => {
        onChange({ ...sets, [name.trim()]: { routes: [], domains: [], route_urls: [], domain_urls: [] } }); setName("");
      }}>Add destination set</button>
    </div>
  </section>;
}
