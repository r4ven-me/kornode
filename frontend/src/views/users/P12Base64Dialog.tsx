import { Copy, X } from "lucide-react";
import { useState } from "react";
import type { P12Base64ModalState } from "../../app/types";
import { IconButton } from "../../components/ui";

export function P12Base64Dialog({
  state,
  onClose
}: {
  state: P12Base64ModalState;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState<"line" | "block" | null>(null);
  if (!state) {
    return null;
  }
  const singleLine = state.base64.replace(/\s+/g, "");
  // Matches the line wrapping of the Linux `base64` utility (76 columns per
  // line, trailing newline), so pasting this output elsewhere behaves the
  // same as piping the file through `base64`.
  const wrapped = `${singleLine.replace(/(.{76})/g, "$1\n")}\n`;
  const copyToClipboard = async (variant: "line" | "block") => {
    try {
      await navigator.clipboard.writeText(variant === "line" ? singleLine : wrapped);
      setCopied(variant);
      window.setTimeout(() => setCopied(null), 2000);
    } catch {
      // Clipboard access can be denied by the browser; the text is still
      // selectable in the textarea below.
    }
  };
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel p12-base64-dialog" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>{state.username}.p12 (Base64)</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        <textarea
          className="p12-base64-textarea"
          readOnly
          value={wrapped}
          onFocus={(event) => event.target.select()}
        />
        <p className="muted-line">
          One line suits env vars (KORCLIENT_AUTH__P12_BASE64) and .env files; the wrapped
          block matches the `base64` utility output for YAML or shell pipelines.
        </p>
        <div className="modal-actions">
          <button
            className="primary-button"
            onClick={() => void copyToClipboard("line")}
            type="button"
          >
            <Copy size={18} aria-hidden="true" />
            <span>{copied === "line" ? "Copied" : "Copy one line"}</span>
          </button>
          <button
            className="primary-button"
            onClick={() => void copyToClipboard("block")}
            type="button"
          >
            <Copy size={18} aria-hidden="true" />
            <span>{copied === "block" ? "Copied" : "Copy block"}</span>
          </button>
        </div>
      </section>
    </div>
  );
}
