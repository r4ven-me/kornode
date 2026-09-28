import { Save } from "lucide-react";
import { useEffect, useState } from "react";
import { ActionButton } from "./ui";

export function BulkListEditor({
  title,
  items,
  placeholder,
  busy,
  disabled = false,
  onSave
}: {
  title: string;
  items: string[];
  placeholder: string;
  busy: boolean;
  disabled?: boolean;
  onSave: (items: string[]) => void;
}) {
  const [draft, setDraft] = useState(items.join("\n"));
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (!dirty) {
      setDraft(items.join("\n"));
    }
  }, [items, dirty]);

  const handleSave = () => {
    const parsed = draft
      .split(/[\s,]+/)
      .map((entry) => entry.trim())
      .filter(Boolean);
    onSave(parsed);
    setDirty(false);
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>{title}</h2>
      </div>
      <p className="muted-line">
        One per line (or space/comma-separated). Paste a whole list at once; format is
        validated on save.
      </p>
      <textarea
        className="bulk-list-textarea"
        disabled={disabled}
        value={draft}
        placeholder={placeholder}
        onChange={(event) => {
          setDraft(event.target.value);
          setDirty(true);
        }}
        rows={8}
      />
      <div className="panel-footer">
        <ActionButton
          label="Save"
          icon={Save}
          primary
          busy={busy}
          disabled={disabled}
          onClick={handleSave}
        />
      </div>
    </section>
  );
}
