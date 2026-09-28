import { type FormEvent, useCallback, useEffect, useState } from "react";
import {
  type LogRotationSettings,
  type LogTail,
  fetchLog,
  runLogRotation,
  saveLogRotationSettings
} from "../../api";
import { errorMessage, isAuthError } from "../../lib/errors";
import type { PanelCore } from "../core";
import type { Tab } from "../types";

export function useLogs(core: PanelCore, tab: Tab) {
  const { authInfo, authToken, busy, logout, runAction, setBusy, setNotice, state } = core;
  const [logRequest, setLogRequest] = useState({ name: "supervisord.log", lines: 100 });
  const [liveLog, setLiveLog] = useState(false);
  const [logTail, setLogTail] = useState<LogTail | null>(null);
  const [logRotationDraft, setLogRotationDraft] = useState<LogRotationSettings>({
    enabled: false,
    max_size_mb: 50,
    max_age: 0,
    max_age_unit: "days",
    keep_files: 5
  });

  core.registerHydrator("logs", ({ logRotation }) => {
    if (logRotation) {
      setLogRotationDraft(logRotation);
    }
  });

  // Keep the selection on a file that exists, preferring the most useful one.
  useEffect(() => {
    if (state.logFiles.length === 0) {
      return;
    }
    if (state.logFiles.some((file) => file.name === logRequest.name)) {
      return;
    }
    const preferred =
      state.logFiles.find((file) => file.name === "api.log") ??
      state.logFiles.find((file) => file.name === "ocserv.log") ??
      state.logFiles.find((file) => file.name === "supervisord.log") ??
      state.logFiles[0];
    setLogRequest((current) => ({ ...current, name: preferred.name }));
  }, [logRequest.name, state.logFiles]);

  const loadLogTail = useCallback(
    async (showNotice = true) => {
      if (!authToken) {
        return;
      }
      if (showNotice && busy) {
        setNotice({ kind: "warning", text: "wait for the current operation to finish" });
        return;
      }
      if (showNotice) {
        setBusy("fetch-log");
        setNotice(null);
      }
      try {
        const result = await fetchLog(authToken, logRequest.name, logRequest.lines);
        setLogTail(result);
        if (showNotice) {
          setNotice({ kind: "ok", text: `Loaded ${logRequest.name}` });
        }
      } catch (error) {
        const text = errorMessage(error);
        if (showNotice || !isAuthError(text)) {
          setNotice({ kind: "error", text });
        }
        if (isAuthError(text)) {
          logout(false);
        }
      } finally {
        if (showNotice) {
          setBusy(null);
        }
      }
    },
    [authToken, busy, logRequest.lines, logRequest.name, logout, setBusy, setNotice]
  );

  useEffect(() => {
    if (!liveLog || tab !== "logs" || !authToken || !authInfo || !logRequest.name) {
      return;
    }
    void loadLogTail(false);
    const interval = window.setInterval(() => void loadLogTail(false), 2500);
    return () => window.clearInterval(interval);
  }, [authInfo, authToken, liveLog, loadLogTail, logRequest.name, tab]);

  const fetchLogAction = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await loadLogTail(true);
  };

  const saveRotation = () =>
    void runAction("log-rotation-save", "Log rotation settings saved", (token) =>
      saveLogRotationSettings(token, logRotationDraft)
    );

  const rotateNow = async () => {
    const result = await runAction("log-rotation-run", "Logs rotated", (token) =>
      runLogRotation(token)
    );
    if (result) {
      setNotice({
        kind: "ok",
        text: result.rotated.length
          ? `Rotated: ${result.rotated.join(", ")}`
          : "No logs needed rotation"
      });
    }
  };

  return {
    logRequest,
    setLogRequest,
    liveLog,
    setLiveLog,
    logTail,
    logRotationDraft,
    setLogRotationDraft,
    fetchLog: fetchLogAction,
    saveRotation,
    rotateNow
  };
}
