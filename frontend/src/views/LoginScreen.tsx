import { KeyRound, Moon, Sun } from "lucide-react";
import type { FormEvent } from "react";
import type { Notice, Theme } from "../app/types";
import { IconButton, RavenMark } from "../components/ui";

export function LoginScreen({
  form,
  busy,
  notice,
  theme,
  totpRequired,
  onChange,
  onSubmit,
  onToggleTheme
}: {
  form: { username: string; password: string; totpCode: string };
  busy: boolean;
  notice: Notice;
  theme: Theme;
  totpRequired: boolean;
  onChange: (value: { username: string; password: string; totpCode: string }) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onToggleTheme: () => void;
}) {
  return (
    <main className="login-shell">
      <form className="login-panel" onSubmit={onSubmit}>
        <div className="login-header">
          <div className="brand login-brand">
            <RavenMark />
            <strong>Korvus Node</strong>
          </div>
          <IconButton
            label={theme === "dark" ? "Light theme" : "Dark theme"}
            icon={theme === "dark" ? Sun : Moon}
            onClick={onToggleTheme}
          />
        </div>
        <label>
          <span>Username</span>
          <input
            autoComplete="username"
            value={form.username}
            onChange={(event) => onChange({ ...form, username: event.target.value })}
            required
          />
        </label>
        <label>
          <span>Password</span>
          <input
            autoComplete="current-password"
            type="password"
            value={form.password}
            onChange={(event) => onChange({ ...form, password: event.target.value })}
            required
          />
        </label>
        {totpRequired && (
          <label>
            <span>Authenticator code</span>
            <input
              autoComplete="one-time-code"
              inputMode="numeric"
              maxLength={6}
              value={form.totpCode}
              onChange={(event) => onChange({ ...form, totpCode: event.target.value })}
              autoFocus
              required
            />
          </label>
        )}
        {notice && <span className={`status ${notice.kind}`}>{notice.text}</span>}
        <button className="primary-button" disabled={busy} type="submit">
          <KeyRound size={18} aria-hidden="true" />
          <span>{busy ? "Signing in" : "Sign in"}</span>
        </button>
      </form>
    </main>
  );
}
