import { type FormEvent, useState } from "react";
import { login, setCsrfToken } from "../../api";
import { errorMessage } from "../../lib/errors";
import type { PanelCore } from "../core";

export function useLogin(core: PanelCore) {
  const { loadAll, setAuthInfo, setAuthToken, setBusy, setNotice } = core;
  const [loginForm, setLoginForm] = useState({ username: "", password: "", totpCode: "" });
  const [totpRequired, setTotpRequired] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy("login");
    setNotice(null);
    try {
      const info = await login(
        loginForm.username.trim(),
        loginForm.password,
        totpRequired ? loginForm.totpCode.trim() : undefined
      );
      setCsrfToken(info.csrf_token);
      setAuthInfo(info);
      setAuthToken("session");
      setLoginForm({ username: "", password: "", totpCode: "" });
      setTotpRequired(false);
      await loadAll("session", { includeExtras: true });
    } catch (error) {
      const text = errorMessage(error);
      if (text === "totp_code_required") {
        setTotpRequired(true);
        setNotice({ kind: "warning", text: "Enter your authenticator code to continue" });
      } else if (text === "invalid_totp_code") {
        setTotpRequired(true);
        setNotice({ kind: "error", text: "Invalid authenticator code" });
      } else {
        setTotpRequired(false);
        setNotice({ kind: "error", text });
      }
    } finally {
      setBusy(null);
    }
  };

  return { loginForm, setLoginForm, totpRequired, submit };
}
