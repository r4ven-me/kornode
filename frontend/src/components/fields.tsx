import { useEffect, useState } from "react";
import { splitLines } from "../lib/drafts";
import { listText } from "../lib/userConfig";
import { KorclientHint } from "./KorclientHint";

export function TextField({
  label,
  value,
  onChange
}: {
  label: string;
  value: string | null;
  onChange: (value: string) => void;
}) {
  return (
    <label>
      <span>{label}</span>
      <input value={value ?? ""} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

export function NumberField({
  label,
  value,
  min,
  max,
  onChange
}: {
  label: string;
  value: number | null;
  min?: number;
  max?: number;
  onChange: (value: string) => void;
}) {
  return (
    <label>
      <span>{label}</span>
      <input
        max={max}
        min={min}
        type="number"
        value={value ?? ""}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

export function ListField({
  label,
  value,
  onChange,
  hint,
  korclientHint
}: {
  label: string;
  value: string[];
  onChange: (value: string) => void;
  hint?: string;
  korclientHint?: string;
}) {
  // Keep the raw text locally so typing spaces/newlines is not eaten by the
  // parent's parse-on-change normalization; the parent still receives every
  // keystroke and stores the parsed list.
  const [text, setText] = useState(() => listText(value));
  useEffect(() => {
    setText((current) =>
      splitLines(current).join("\n") === value.join("\n") ? current : listText(value)
    );
  }, [value]);
  return (
    <label>
      <span>
        {label}
        {korclientHint && <KorclientHint text={korclientHint} />}
      </span>
      <textarea
        rows={3}
        value={text}
        onChange={(event) => {
          setText(event.target.value);
          onChange(event.target.value);
        }}
      />
      {hint && <small className="muted-line">{hint}</small>}
    </label>
  );
}

export function BooleanField({
  label,
  value,
  onChange
}: {
  label: string;
  value: boolean | null;
  onChange: (value: string) => void;
}) {
  return (
    <label>
      <span>{label}</span>
      <select value={value === null ? "" : String(value)} onChange={(event) => onChange(event.target.value)}>
        <option value="">Inherit</option>
        <option value="true">True</option>
        <option value="false">False</option>
      </select>
    </label>
  );
}
