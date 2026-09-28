import { Upload } from "lucide-react";
import type { ChangeEvent } from "react";

export function FilePicker({
  accept,
  file,
  label,
  title,
  onChange
}: {
  accept: string;
  file: File | null;
  label: string;
  title: string;
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <label className="file-picker" title={title}>
      <input accept={accept} onChange={onChange} type="file" />
      <span className="file-picker-button">
        <Upload size={16} aria-hidden="true" />
        {label}
      </span>
      <span className="file-picker-name">{file?.name ?? "No file selected"}</span>
    </label>
  );
}
