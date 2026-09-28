import { Check, Copy, RefreshCw, Wand2 } from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { IconButton } from "./ui";

export const PASSWORD_GENERATOR_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
export const PASSWORD_GENERATOR_DIGITS = "0123456789";
// Punctuation only: no quotes, backslash, backtick, `$`, `;`, `&`, `|`, `<`, `>`, or `%`,
// so a generated password never needs escaping in shells, YAML, or config templates.
export const PASSWORD_GENERATOR_SPECIAL = "!@#^*()-_=+[]{}:,.?~";

export function passwordGeneratorRandomInt(max: number): number {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return array[0] % max;
}

export function generatePassword(length: number, useDigits: boolean, useSpecial: boolean): string {
  const pools = [PASSWORD_GENERATOR_LETTERS];
  if (useDigits) {
    pools.push(PASSWORD_GENERATOR_DIGITS);
  }
  if (useSpecial) {
    pools.push(PASSWORD_GENERATOR_SPECIAL);
  }
  const combinedPool = pools.join("");
  const required = pools.map((pool) => pool[passwordGeneratorRandomInt(pool.length)]);
  const chars = [...required];
  for (let i = chars.length; i < length; i++) {
    chars.push(combinedPool[passwordGeneratorRandomInt(combinedPool.length)]);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = passwordGeneratorRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.slice(0, Math.max(length, required.length)).join("");
}

export function PasswordGeneratorButton({ onApply }: { onApply: (password: string) => void }) {
  const [open, setOpen] = useState(false);
  const [length, setLength] = useState(16);
  const [useDigits, setUseDigits] = useState(true);
  const [useSpecial, setUseSpecial] = useState(true);
  const [generated, setGenerated] = useState("");
  const [copied, setCopied] = useState(false);
  const [menuPosition, setMenuPosition] = useState({ top: -9999, left: -9999 });
  const containerRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    setGenerated(generatePassword(length, useDigits, useSpecial));
    setCopied(false);
  }, [open, length, useDigits, useSpecial]);

  useLayoutEffect(() => {
    if (!open || !containerRef.current || !menuRef.current) {
      return;
    }
    const updatePosition = () => {
      if (!containerRef.current || !menuRef.current) {
        return;
      }
      const buttonRect = containerRef.current.getBoundingClientRect();
      const menuRect = menuRef.current.getBoundingClientRect();
      const spaceBelow = window.innerHeight - buttonRect.bottom;
      const top =
        spaceBelow < menuRect.height + 12 && buttonRect.top > menuRect.height + 12
          ? Math.max(8, buttonRect.top - menuRect.height - 6)
          : buttonRect.bottom + 6;
      const left = Math.min(
        Math.max(8, buttonRect.right - menuRect.width),
        window.innerWidth - menuRect.width - 8
      );
      setMenuPosition({ top, left });
    };
    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open, generated]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(generated);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied by the browser; the password is still visible to copy manually.
    }
  };

  return (
    <div className="password-generator" ref={containerRef}>
      <IconButton
        label="Generate password"
        icon={Wand2}
        onClick={() => setOpen((value) => !value)}
      />
      {open && (
        <div
          className="password-generator-menu"
          style={{ top: menuPosition.top, left: menuPosition.left }}
          ref={menuRef}
          role="dialog"
          aria-label="Generate password"
        >
          <label>
            <span>Length: {length}</span>
            <input
              type="range"
              min={8}
              max={64}
              value={length}
              onChange={(event) => setLength(Number(event.target.value))}
            />
          </label>
          <label className="mini-check">
            <input
              type="checkbox"
              checked={useDigits}
              onChange={(event) => setUseDigits(event.target.checked)}
            />
            <span>Digits</span>
          </label>
          <label className="mini-check">
            <input
              type="checkbox"
              checked={useSpecial}
              onChange={(event) => setUseSpecial(event.target.checked)}
            />
            <span>Special characters</span>
          </label>
          <code className="password-generator-preview">{generated}</code>
          <div className="password-generator-actions">
            <IconButton
              label="Regenerate"
              icon={RefreshCw}
              onClick={() => setGenerated(generatePassword(length, useDigits, useSpecial))}
            />
            <IconButton label={copied ? "Copied" : "Copy"} icon={copied ? Check : Copy} onClick={() => void copy()} />
            <button
              className="primary-button"
              type="button"
              onClick={() => {
                onApply(generated);
                setOpen(false);
              }}
            >
              <Check size={16} aria-hidden="true" />
              <span>Use</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
