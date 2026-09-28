import { useEffect, useMemo, useRef, useState } from "react";
import {
  type InterfaceStats,
  type SessionRecord,
  applyNft,
  fetchInterfaceStats,
  fetchServerProcesses,
  fetchServerStatus,
  fetchSessions,
  reloadServer,
  restartServer,
  startServer,
  stopServer,
  writeRenderedConfig
} from "../../api";
import { confirmAction, delay } from "../../lib/async";
import { diagnosticKind } from "../../lib/errors";
import { serverRuntimeState } from "../../lib/serverStatus";
import type { PanelCore } from "../core";
import {
  INTERFACE_HISTORY_CAP,
  type InterfaceRatePoint,
  type InterfaceSample,
  type Tab
} from "../types";

export function useDashboard(
  core: PanelCore,
  tab: Tab,
  updateSessions: (sessions: SessionRecord[]) => void
) {
  const { authInfo, authToken, dryRun, recordCommand, runAction, setState, state } = core;
  const interfaceSampleRef = useRef<InterfaceSample | null>(null);
  const [interfaceName, setInterfaceName] = useState<string | null>(null);
  const [interfaceHistory, setInterfaceHistory] = useState<InterfaceRatePoint[]>([]);

  useEffect(() => {
    if (tab !== "dashboard" || !authToken || !authInfo) {
      return;
    }
    const refreshInterfaceStats = () => {
      fetchInterfaceStats(authToken)
        .then((stats: InterfaceStats) => {
          setInterfaceName(stats.interface);
          const now = Date.now();
          const previous = interfaceSampleRef.current;
          if (
            stats.rx_bytes !== null &&
            stats.tx_bytes !== null &&
            previous &&
            now > previous.timestamp
          ) {
            const elapsed = (now - previous.timestamp) / 1000;
            const rx = Math.max(stats.rx_bytes - previous.rxBytes, 0) / elapsed;
            const tx = Math.max(stats.tx_bytes - previous.txBytes, 0) / elapsed;
            setInterfaceHistory((current) => [
              ...current.slice(-(INTERFACE_HISTORY_CAP - 1)),
              { rx, tx }
            ]);
          }
          interfaceSampleRef.current =
            stats.rx_bytes !== null && stats.tx_bytes !== null
              ? { rxBytes: stats.rx_bytes, txBytes: stats.tx_bytes, timestamp: now }
              : null;
        })
        .catch(() => {
          // interface load is a best-effort widget; stay silent on transient errors
        });
    };
    refreshInterfaceStats();
    const interval = window.setInterval(refreshInterfaceStats, 3000);
    return () => window.clearInterval(interval);
  }, [authInfo, authToken, tab]);

  const diagnosticScore = useMemo(() => {
    const values = Object.values(state.diagnostics ?? {});
    return {
      ok: values.filter((item) => diagnosticKind(item) !== "error").length,
      total: values.length
    };
  }, [state.diagnostics]);

  const refreshServerStatus = async (
    token: string,
    expectedState?: "running" | "stopped"
  ): Promise<void> => {
    const attempts = expectedState ? 8 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const [serverStatus, serverProcesses] = await Promise.all([
        fetchServerStatus(token),
        fetchServerProcesses(token)
      ]);
      setState((current) => ({ ...current, serverStatus, serverProcesses }));
      if (!expectedState || serverRuntimeState(serverStatus) === expectedState) {
        return;
      }
      await delay(350);
    }
  };

  const startServerAction = async () => {
    const result = await runAction(
      "start-server",
      "Server start requested",
      (token) => startServer(token, dryRun),
      { reload: dryRun, dryRunAware: true }
    );
    recordCommand("dashboard", result);
    if (result !== null && authToken && !dryRun) {
      await refreshServerStatus(authToken, "running");
    }
  };

  const stopServerAction = async () => {
    if (!confirmAction("Stop the VPN server? Active sessions will be disconnected.")) {
      return;
    }
    const result = await runAction(
      "stop-server",
      "Server stop requested",
      (token) => stopServer(token, dryRun),
      { reload: dryRun, dryRunAware: true }
    );
    recordCommand("dashboard", result);
    if (result !== null && authToken && !dryRun) {
      await refreshServerStatus(authToken, "stopped");
    }
  };

  const reloadServerAction = async () => {
    const result = await runAction(
      "reload-server",
      "Korvus Node reload requested",
      (token) => reloadServer(token, dryRun),
      { dryRunAware: true }
    );
    recordCommand("dashboard", result);
    if (result !== null && authToken && !dryRun) {
      await refreshServerStatus(authToken);
    }
  };

  const restartServerAction = async () => {
    if (!confirmAction("Restart ocserv? Active sessions will be disconnected.")) {
      return;
    }
    const result = await runAction(
      "restart-server",
      "ocserv restart requested",
      (token) => restartServer(token, dryRun),
      { dryRunAware: true }
    );
    recordCommand("dashboard", result);
    if (result !== null && authToken && !dryRun) {
      await refreshServerStatus(authToken, "running");
      const sessions = await fetchSessions(authToken);
      updateSessions(sessions);
    }
  };

  // Shared by the Dashboard and the Config view's "Render configs" buttons.
  const writeConfig = () =>
    void runAction("write-config", "Generated configs written", writeRenderedConfig);

  const applyNftAction = async () => {
    const result = await runAction(
      "apply-nft",
      "nftables rules applied",
      (token) => applyNft(token, dryRun),
      { dryRunAware: true }
    );
    recordCommand("dashboard", result);
  };

  return {
    interfaceName,
    interfaceHistory,
    diagnosticScore,
    startServer: startServerAction,
    stopServer: stopServerAction,
    reloadServer: reloadServerAction,
    restartServer: restartServerAction,
    writeConfig,
    applyNft: applyNftAction
  };
}
