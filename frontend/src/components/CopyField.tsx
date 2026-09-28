import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { IconButton } from "./ui";

// Read-only value with a copy-to-clipboard button (pins, fingerprints, ...).
export function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied; the value stays selectable.
    }
  };
  return (
    <label className="copy-field">
      <span>{label}</span>
      <span className="copy-field-row">
        <input readOnly value={value} onFocus={(event) => event.target.select()} />
        <IconButton
          label={copied ? "Copied" : `Copy ${label}`}
          icon={copied ? Check : Copy}
          onClick={() => void copy()}
        />
      </span>
    </label>
  );
}
