import { useCallback, useEffect, useRef, useState } from "react";
import {
  type AuthInfo,
  fetchAuthInfo,
  fetchCertificateStatus,
  fetchConfig,
  fetchConfigSource,
  fetchDiagnostics,
  fetchDomains,
  fetchDomainsStatus,
  fetchGroups,
  fetchHealth,
  fetchHostDomains,
  fetchHostDomainsStatus,
  fetchHostRoutes,
  fetchHostRoutesStatus,
  fetchIdentity,
  fetchInternalDnsStatus,
  fetchLogFiles,
  fetchLogRotationSettings,
  fetchOtpRecords,
  fetchRenderedConfig,
  fetchRoutes,
  fetchRoutesStatus,
  fetchServerProcesses,
  fetchServerStatus,
  fetchSessions,
  fetchSoftwareVersions,
  fetchUpstreamProfiles,
  fetchUpstreamStatus,
  fetchUsers,
  logout as logoutSession,
  setCsrfToken
} from "../api";
import { settledValue } from "../lib/async";
import { errorMessage, isAuthError } from "../lib/errors";
import { emptyState } from "./state";
import type { AppState, CommandOutput, CommandOutputKey, Notice } from "./types";

type Loaded<F extends (...args: never[]) => Promise<unknown>> = Awaited<ReturnType<F>>;

// The successfully loaded responses that feature hooks copy into their
// editable drafts after every loadAll() (see registerHydrator()).
export type LoadSnapshot = {
  sessions?: Loaded<typeof fetchSessions>;
  config?: Loaded<typeof fetchConfig>;
  configSource?: Loaded<typeof fetchConfigSource>;
  certificateStatus?: Loaded<typeof fetchCertificateStatus>;
  logRotation?: Loaded<typeof fetchLogRotationSettings>;
  internalDns?: Loaded<typeof fetchInternalDnsStatus>;
  identity?: Loaded<typeof fetchIdentity>;
  upstream?: Loaded<typeof fetchUpstreamStatus>;
};

export type Hydrator = (snapshot: LoadSnapshot) => void;

export type RunActionOptions = { reload?: boolean; dryRunAware?: boolean };

// State and actions shared by every panel area: auth, the loaded AppState,
// busy/notice handling and the runAction() wrapper all mutations go through.
export function usePanelCore() {
  const [dryRun, setDryRun] = useState(false);
  const [authToken, setAuthToken] = useState<string | null>("session");
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  const [state, setState] = useState<AppState>(emptyState);
  const [notice, setNotice] = useState<Notice>(null);
  const [noticePaused, setNoticePaused] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [commandOutputs, setCommandOutputs] = useState<
    Partial<Record<CommandOutputKey, CommandOutput>>
  >({});
  // Registered by feature hooks on every render, so loadAll() always calls
  // their latest closures.
  const hydrators = useRef<Record<string, Hydrator>>({});

  useEffect(() => {
    if (!notice || noticePaused) {
      return;
    }
    const timeout = window.setTimeout(() => setNotice(null), notice.kind === "error" ? 8000 : 5000);
    return () => window.clearTimeout(timeout);
  }, [notice, noticePaused]);

  const logout = useCallback((clearNotice = true) => {
    void logoutSession().catch(() => undefined);
    setCsrfToken(null);
    setAuthToken(null);
    setAuthInfo(null);
    setState(emptyState);
    setCommandOutputs({});
    if (clearNotice) {
      setNotice(null);
    }
  }, []);

  const recordCommand = (target: CommandOutputKey, result: CommandOutput) => {
    setCommandOutputs((current) => ({ ...current, [target]: result }));
  };

  const clearCommand = (target: CommandOutputKey) => {
    setCommandOutputs((current) => ({ ...current, [target]: null }));
  };

  const loadAll = useCallback(
    async (token: string, options: { includeExtras?: boolean } = {}) => {
      const includeExtras = options.includeExtras ?? false;
      setLoading(true);
      try {
        // Diagnostics and software-version checks each shell out to ~10
        // system commands; only run them on initial load / explicit
        // refresh, not after every unrelated action.
        const [results, extraResults] = await Promise.all([
          Promise.allSettled([
            fetchHealth(),
            fetchServerStatus(token),
            fetchServerProcesses(token),
            fetchUsers(token),
            fetchGroups(token),
            fetchOtpRecords(token),
            fetchSessions(token),
            fetchRoutes(token),
            fetchDomains(token),
            fetchRoutesStatus(token),
            fetchDomainsStatus(token),
            fetchHostRoutes(token),
            fetchHostDomains(token),
            fetchHostRoutesStatus(token),
            fetchHostDomainsStatus(token),
            fetchIdentity(token),
            fetchInternalDnsStatus(token),
            fetchUpstreamStatus(token),
            fetchUpstreamProfiles(token),
            fetchConfig(token),
            fetchConfigSource(token),
            fetchRenderedConfig(token),
            fetchLogFiles(token),
            fetchCertificateStatus(token),
            fetchLogRotationSettings(token)
          ]),
          includeExtras
            ? Promise.allSettled([fetchDiagnostics(token), fetchSoftwareVersions(token)])
            : Promise.resolve(null)
        ]);
        const authFailure = [...results, ...(extraResults ?? [])].find(
          (result) => result.status === "rejected" && isAuthError(errorMessage(result.reason))
        );
        if (authFailure?.status === "rejected") {
          throw authFailure.reason;
        }
        const [
          health,
          serverStatus,
          serverProcesses,
          users,
          groups,
          otpRecords,
          sessions,
          routes,
          domains,
          routesStatus,
          domainsStatus,
          hostRoutes,
          hostDomains,
          hostRoutesStatus,
          hostDomainsStatus,
          identity,
          internalDns,
          upstream,
          upstreamProfiles,
          config,
          configSource,
          renderedConfig,
          logFiles,
          certificateStatus,
          logRotation
        ] = results;
        setState((current) => ({
          health: settledValue(health, current.health),
          serverStatus: settledValue(serverStatus, current.serverStatus),
          serverProcesses: settledValue(serverProcesses, current.serverProcesses),
          users: settledValue(users, current.users),
          groups: settledValue(groups, current.groups),
          otpRecords: settledValue(otpRecords, current.otpRecords),
          sessions: current.sessions,
          routes: settledValue(routes, current.routes),
          domains: settledValue(domains, current.domains),
          routesStatus: settledValue(routesStatus, current.routesStatus),
          domainsStatus: settledValue(domainsStatus, current.domainsStatus),
          hostRoutes: settledValue(hostRoutes, current.hostRoutes),
          hostDomains: settledValue(hostDomains, current.hostDomains),
          hostRoutesStatus: settledValue(hostRoutesStatus, current.hostRoutesStatus),
          hostDomainsStatus: settledValue(hostDomainsStatus, current.hostDomainsStatus),
          identity: settledValue(identity, current.identity),
          internalDns: settledValue(internalDns, current.internalDns),
          upstream: settledValue(upstream, current.upstream),
          upstreamProfiles: settledValue(upstreamProfiles, current.upstreamProfiles),
          config: settledValue(config, current.config),
          configSource: settledValue(configSource, current.configSource),
          renderedConfig: settledValue(renderedConfig, current.renderedConfig),
          logFiles: settledValue(logFiles, current.logFiles),
          certificateStatus: settledValue(certificateStatus, current.certificateStatus),
          diagnostics: extraResults
            ? settledValue(extraResults[0], current.diagnostics)
            : current.diagnostics,
          softwareVersions: extraResults
            ? settledValue(extraResults[1], current.softwareVersions)
            : current.softwareVersions
        }));
        const snapshot: LoadSnapshot = {};
        if (sessions.status === "fulfilled") snapshot.sessions = sessions.value;
        if (config.status === "fulfilled") snapshot.config = config.value;
        if (configSource.status === "fulfilled") snapshot.configSource = configSource.value;
        if (certificateStatus.status === "fulfilled") {
          snapshot.certificateStatus = certificateStatus.value;
        }
        if (logRotation.status === "fulfilled") snapshot.logRotation = logRotation.value;
        if (internalDns.status === "fulfilled") snapshot.internalDns = internalDns.value;
        if (identity.status === "fulfilled") snapshot.identity = identity.value;
        if (upstream.status === "fulfilled") snapshot.upstream = upstream.value;
        for (const hydrate of Object.values(hydrators.current)) {
          hydrate(snapshot);
        }
        const failureCount = results.filter((result) => result.status === "rejected").length;
        if (failureCount > 0) {
          setNotice({
            kind: "warning",
            text: `${failureCount} dashboard request${failureCount === 1 ? "" : "s"} failed`
          });
        }
      } catch (error) {
        const text = errorMessage(error);
        setNotice({ kind: "error", text });
        if (isAuthError(text)) {
          logout(false);
        }
      } finally {
        setLoading(false);
      }
    },
    [logout]
  );

  useEffect(() => {
    if (!authToken || authInfo) {
      return;
    }
    fetchAuthInfo()
      .then((info) => {
        setCsrfToken(info.csrf_token);
        setAuthInfo(info);
        void loadAll(authToken, { includeExtras: true });
      })
      .catch((error: unknown) => {
        const text = errorMessage(error);
        if (!isAuthError(text)) {
          setNotice({ kind: "error", text });
        }
        logout(false);
      });
  }, [authInfo, authToken, loadAll, logout]);

  const runAction = async <T>(
    key: string,
    success: string,
    action: (token: string) => Promise<T>,
    options: RunActionOptions = {}
  ): Promise<T | null> => {
    if (!authToken) {
      setNotice({ kind: "error", text: "authentication required" });
      return null;
    }
    if (busy) {
      setNotice({ kind: "warning", text: "wait for the current operation to finish" });
      return null;
    }
    setBusy(key);
    setNotice(null);
    try {
      const result = await action(authToken);
      if (options.reload !== false) {
        await loadAll(authToken);
      }
      const showDryRun = Boolean(options.dryRunAware && dryRun);
      setNotice({
        kind: showDryRun ? "warning" : "ok",
        text: showDryRun ? `${success} (dry-run)` : success
      });
      return result;
    } catch (error) {
      setBusy(null);
      const text = errorMessage(error);
      setNotice({ kind: "error", text });
      if (isAuthError(text)) {
        logout(false);
      }
      return null;
    } finally {
      setBusy(null);
    }
  };

  // Like runAction() for operations that don't reload panel data and report
  // their own success notice (downloads, read-only dialogs).
  const runBusyTask = async (key: string, task: (token: string) => Promise<void>) => {
    if (!authToken) {
      return;
    }
    setBusy(key);
    setNotice(null);
    try {
      await task(authToken);
    } catch (error) {
      const text = errorMessage(error);
      setNotice({ kind: "error", text });
      if (isAuthError(text)) {
        logout(false);
      }
    } finally {
      setBusy(null);
    }
  };

  // Called during render: keeps the registered hydrator's closure current.
  const registerHydrator = (key: string, hydrate: Hydrator) => {
    hydrators.current[key] = hydrate;
  };

  return {
    dryRun,
    setDryRun,
    authToken,
    setAuthToken,
    authInfo,
    setAuthInfo,
    state,
    setState,
    notice,
    setNotice,
    setNoticePaused,
    busy,
    setBusy,
    loading,
    commandOutputs,
    recordCommand,
    clearCommand,
    logout,
    loadAll,
    runAction,
    runBusyTask,
    registerHydrator
  };
}

export type PanelCore = ReturnType<typeof usePanelCore>;
