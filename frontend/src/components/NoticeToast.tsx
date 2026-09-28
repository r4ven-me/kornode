import { X } from "lucide-react";
import type { Notice } from "../app/types";

export function NoticeToast({
  notice,
  onClose,
  onPauseChange
}: {
  notice: NonNullable<Notice>;
  onClose: () => void;
  onPauseChange: (paused: boolean) => void;
}) {
  return (
    <div
      className={`notice-toast status ${notice.kind}`}
      onMouseEnter={() => onPauseChange(true)}
      onMouseLeave={() => onPauseChange(false)}
      role="status"
    >
      <span>{notice.text}</span>
      <button aria-label="Close notification" onClick={onClose} title="Close" type="button">
        <X size={15} aria-hidden="true" />
      </button>
    </div>
  );
}
