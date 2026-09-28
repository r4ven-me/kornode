import { Upload } from "lucide-react";
import type { ChangeEvent } from "react";

export type CertSourceMode = "upload" | "base64" | "path";

export function CertSourceField({
  label,
  mode,
  pathValue,
  base64Value,
  fileName,
  pathPlaceholder,
  onModeChange,
  onPathChange,
  onBase64Change,
  onFileSelected
}: {
  label: string;
  mode: CertSourceMode;
  pathValue: string;
  base64Value: string;
  fileName: string | null;
  pathPlaceholder?: string;
  onModeChange: (mode: CertSourceMode) => void;
  onPathChange: (value: string) => void;
  onBase64Change: (value: string) => void;
  onFileSelected: (base64: string, fileName: string) => void;
}) {
  const readFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === "string" ? reader.result : "";
      onFileSelected(result.slice(result.indexOf(",") + 1), file.name);
    };
    reader.readAsDataURL(file);
  };

  return (
    <div className="field-label cert-source-field">
      <span>{label}</span>
      <div className="cert-source-toggle" role="group" aria-label={`${label} source`}>
        <button
          type="button"
          className={mode === "upload" ? "active" : ""}
          onClick={() => onModeChange("upload")}
        >
          Upload
        </button>
        <button
          type="button"
          className={mode === "base64" ? "active" : ""}
          onClick={() => onModeChange("base64")}
        >
          Base64
        </button>
        <button
          type="button"
          className={mode === "path" ? "active" : ""}
          onClick={() => onModeChange("path")}
        >
          Path
        </button>
      </div>
      {mode === "upload" && (
        <span className="file-picker">
          <input type="file" onChange={readFile} />
          <span className="file-picker-button">
            <Upload size={16} aria-hidden="true" />
            Choose file
          </span>
          <span className="file-picker-name">{fileName ?? "No file selected"}</span>
        </span>
      )}
      {mode === "base64" && (
        <textarea
          value={base64Value}
          onChange={(event) => onBase64Change(event.target.value)}
          placeholder="base64-encoded file content"
          rows={3}
        />
      )}
      {mode === "path" && (
        <input
          value={pathValue}
          onChange={(event) => onPathChange(event.target.value)}
          placeholder={pathPlaceholder}
        />
      )}
    </div>
  );
}
