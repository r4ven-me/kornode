import { useCallback, useEffect, useRef, useState } from "react";
import { type SessionRecord, fetchSessions, kickSession } from "../../api";
import { confirmAction } from "../../lib/async";
import { errorMessage, isAuthError } from "../../lib/errors";
import { parseTrafficBytes, rateFromDelta, sessionKey } from "../../lib/format";
import type { PanelCore } from "../core";
import type { SessionRates, SessionSample, Tab } from "../types";

export function useSessions(core: PanelCore, tab: Tab) {
  const { authInfo, authToken, dryRun, recordCommand, runAction, setNotice, setState } = core;
  const [sessionRates, setSessionRates] = useState<SessionRates>({});
  const sessionSamplesRef = useRef<Record<string, SessionSample>>({});

  const updateSessions = useCallback(
    (sessions: SessionRecord[]) => {
      const now = Date.now();
      const previous = sessionSamplesRef.current;
      const nextSamples: Record<string, SessionSample> = {};
      const nextRates: SessionRates = {};
      for (const session of sessions) {
        const key = sessionKey(session);
        const rxBytes = parseTrafficBytes(session.rx);
        const txBytes = parseTrafficBytes(session.tx);
        const before = previous[key];
        if (before) {
          const elapsed = Math.max((now - before.timestamp) / 1000, 1);
          nextRates[key] = {
            download: rateFromDelta(before.txBytes, txBytes, elapsed),
            upload: rateFromDelta(before.rxBytes, rxBytes, elapsed)
          };
        } else {
          nextRates[key] = { download: null, upload: null };
        }
        nextSamples[key] = { rxBytes, txBytes, timestamp: now };
      }
      sessionSamplesRef.current = nextSamples;
      setSessionRates(nextRates);
      setState((current) => ({ ...current, sessions }));
    },
    [setState]
  );

  core.registerHydrator("sessions", (snapshot) => {
    if (snapshot.sessions) {
      updateSessions(snapshot.sessions);
    }
  });

  useEffect(() => {
    if (tab !== "sessions" || !authToken || !authInfo) {
      return;
    }
    const refreshSessions = () => {
      fetchSessions(authToken)
        .then(updateSessions)
        .catch((error: unknown) => {
          const text = errorMessage(error);
          if (!isAuthError(text)) {
            setNotice({ kind: "warning", text });
          }
        });
    };
    refreshSessions();
    const interval = window.setInterval(refreshSessions, 5000);
    return () => window.clearInterval(interval);
  }, [authInfo, authToken, setNotice, tab, updateSessions]);

  const kick = async (username: string) => {
    if (!confirmAction(`Disconnect all active sessions for ${username}?`)) {
      return;
    }
    const result = await runAction(
      `kick-${username}`,
      `Kick requested for ${username}`,
      (token) => kickSession(token, username, dryRun),
      { dryRunAware: true }
    );
    recordCommand("sessions", result);
  };

  return { sessionRates, updateSessions, kick };
}
