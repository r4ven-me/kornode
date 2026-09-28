import { useCallback, useId, useRef, useState } from "react";
import { RavenIcon } from "./ui";

export function KorclientHint({ text }: { text: string }) {
  const bubbleId = useId();
  const triggerRef = useRef<HTMLSpanElement>(null);
  // Positioned in JS (not CSS :hover) and rendered position: fixed so the
  // bubble escapes clipping by scrollable modal ancestors (overflow: auto)
  // and stays inside the viewport regardless of which grid column it's in.
  const [pos, setPos] = useState<{ top: number; left: number; placement: "top" | "bottom" } | null>(
    null
  );

  const show = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const margin = 10;
    const halfWidth = 140;
    const left = Math.min(
      Math.max(rect.left + rect.width / 2, margin + halfWidth),
      window.innerWidth - margin - halfWidth
    );
    const placement: "top" | "bottom" = rect.top > 90 ? "top" : "bottom";
    const top = placement === "top" ? rect.top - 9 : rect.bottom + 9;
    setPos({ top, left, placement });
  }, []);

  const hide = useCallback(() => setPos(null), []);

  return (
    <span
      aria-describedby={bubbleId}
      className="korclient-hint"
      onBlur={hide}
      onFocus={show}
      onMouseEnter={show}
      onMouseLeave={hide}
      ref={triggerRef}
      tabIndex={0}
    >
      <RavenIcon className="korclient-hint-icon" />
      {pos && (
        <span
          className={`korclient-hint-bubble korclient-hint-bubble-${pos.placement}`}
          id={bubbleId}
          role="tooltip"
          style={{ left: pos.left, top: pos.top }}
        >
          {text}
        </span>
      )}
    </span>
  );
}
