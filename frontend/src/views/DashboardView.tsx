import { Play, RefreshCw, Save, Square, Terminal } from "lucide-react";
import type { AppState, InterfaceRatePoint } from "../app/types";
import { CommandBlock, LastCommandPanel } from "../components/CommandOutput";
import { ActionButton, Metric, Pill } from "../components/ui";
import { diagnosticKind } from "../lib/errors";
import { formatBytes } from "../lib/format";
import { dashboardProcessCount, serverRuntimeState } from "../lib/serverStatus";
import type { CommandResult } from "../api";

export function DashboardView({
  state,
  diagnosticScore,
  busy,
  interfaceName,
  interfaceHistory,
  onStartServer,
  onStopServer,
  onReloadServer,
  onRestartServer,
  onWriteConfig,
  onApplyNft,
  commandOutput,
  onClearCommand
}: {
  state: AppState;
  diagnosticScore: { ok: number; total: number };
  busy: string | null;
  interfaceName: string | null;
  interfaceHistory: InterfaceRatePoint[];
  onStartServer: () => void;
  onStopServer: () => void;
  onReloadServer: () => void;
  onRestartServer: () => void;
  onWriteConfig: () => void;
  onApplyNft: () => void;
  commandOutput: CommandResult | CommandResult[] | null;
  onClearCommand: () => void;
}) {
  const runtimeState = serverRuntimeState(state.serverStatus);
  const serverRunning = runtimeState === "running";
  const serverStopped = runtimeState === "stopped";
  const processCount = dashboardProcessCount(state);
  const nftFilter = state.diagnostics?.["nft filter table"];
  const nftNat = state.diagnostics?.["nft nat table"];
  const nftReady =
    Boolean(nftFilter && nftNat) &&
    diagnosticKind(nftFilter as CommandResult) !== "error" &&
    diagnosticKind(nftNat as CommandResult) !== "error";

  return (
    <div className="view-stack">
      <section className="metric-grid">
        <Metric label="Users" value={state.users.length.toString()} />
        <Metric label="Sessions" value={state.sessions.length.toString()} />
        <Metric label="Routes" value={state.routes.length.toString()} />
        <Metric label="Diagnostics" value={`${diagnosticScore.ok}/${diagnosticScore.total}`} />
        <Metric
          label="Processes"
          value={`${processCount.running}/${processCount.total}`}
        />
        <Metric label="Firewall/NAT" value={nftReady ? "Ready" : "Check rules"} />
        <Metric label="Logs" value={state.logFiles.length.toString()} />
        <Metric label="Config" value={state.configSource?.exists ? "Persistent" : "Default"} />
      </section>
      <ConfigurationPrecedencePanel />
      <InterfaceLoadPanel name={interfaceName} history={interfaceHistory} />
      <section className="panel">
        <div className="panel-header">
          <h2>Korvus Node</h2>
          <div className="toolbar">
            <Pill kind={serverRunning ? "ok" : serverStopped ? "muted" : "warning"}>
              {serverRunning ? "Running" : serverStopped ? "Stopped" : "Unknown"}
            </Pill>
            <ActionButton
              label="Start"
              icon={Play}
              disabled={serverRunning}
              busy={busy === "start-server"}
              onClick={onStartServer}
            />
            <ActionButton
              label="Stop"
              icon={Square}
              danger
              disabled={!serverRunning}
              busy={busy === "stop-server"}
              onClick={onStopServer}
            />
            <ActionButton
              label="Reload"
              icon={RefreshCw}
              disabled={!serverRunning}
              busy={busy === "reload-server"}
              onClick={onReloadServer}
            />
            <ActionButton
              label="Restart ocserv"
              icon={RefreshCw}
              danger
              disabled={!serverRunning}
              busy={busy === "restart-server"}
              onClick={onRestartServer}
            />
            <ActionButton
              label="Render configs"
              icon={Save}
              title="Write generated Korvus Node, supervisor, dnsmasq and nftables files from YAML"
              busy={busy === "write-config"}
              onClick={onWriteConfig}
            />
            <ActionButton
              label="Apply firewall/NAT"
              icon={Terminal}
              title="Apply generated nftables firewall, split-routing and VPN masquerade rules"
              busy={busy === "apply-nft"}
              onClick={onApplyNft}
            />
          </div>
        </div>
        <CommandBlock result={state.serverStatus} />
      </section>
      {commandOutput && (
        <LastCommandPanel title="Last command" result={commandOutput} onClose={onClearCommand} />
      )}
      <section className="panel software-panel">
        <div className="panel-header">
          <h2>Software versions</h2>
          <Pill kind={state.softwareVersions.length > 0 ? "ok" : "muted"}>
            {state.softwareVersions.length.toString()}
          </Pill>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Component</th>
                <th>Version</th>
                <th>Probe</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {state.softwareVersions.map((item) => (
                <tr key={item.name}>
                  <td className="strong-cell">{item.name}</td>
                  <td>{item.version}</td>
                  <td>
                    <code>{item.command?.join(" ") ?? "built-in"}</code>
                  </td>
                  <td>
                    <Pill
                      kind={
                        item.status === "ok"
                          ? "ok"
                          : item.status === "missing"
                            ? "warning"
                            : "muted"
                      }
                    >
                      {item.status}
                    </Pill>
                  </td>
                </tr>
              ))}
              {state.softwareVersions.length === 0 && (
                <tr>
                  <td colSpan={4}>No version data loaded yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export function ConfigurationPrecedencePanel() {
  const sources = [
    { label: "Application defaults", accent: false },
    { label: ".env", accent: false },
    { label: "Environment", accent: false },
    { label: "YAML / Web panel", accent: true },
    { label: "CLI flags", accent: false }
  ];

  return (
    <section className="panel config-precedence-panel">
      <div className="panel-header">
        <div>
          <h2>Configuration precedence</h2>
          <p className="muted-line">Sources are applied from left to right.</p>
        </div>
        <Pill kind="ok">YAML-first</Pill>
      </div>
      <div className="config-precedence-chain" aria-label="Configuration source precedence">
        {sources.map((source, index) => (
          <div className="config-precedence-step" key={source.label}>
            {index > 0 && (
              <span className="config-precedence-arrow" aria-hidden="true">
                →
              </span>
            )}
            <div className={`config-precedence-node${source.accent ? " accent" : ""}`}>
              {source.label}
            </div>
          </div>
        ))}
      </div>
      <p className="config-precedence-note">
        A source on the right overrides the same setting on the left. Settings saved in the Web
        panel are written to YAML; environment values are used when a field is absent from YAML.
      </p>
    </section>
  );
}

export function InterfaceLoadPanel({
  name,
  history
}: {
  name: string | null;
  history: InterfaceRatePoint[];
}) {
  const latest = history[history.length - 1];
  const rxValues = history.map((point) => point.rx);
  const txValues = history.map((point) => point.tx);
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Interface load</h2>
        <Pill kind={name ? "ok" : "muted"}>{name ?? "unresolved"}</Pill>
      </div>
      <div className="interface-graph">
        <div className="interface-graph-row">
          <span className="interface-graph-label">RX</span>
          <span className="interface-graph-value">
            {latest ? `${formatBytes(latest.rx)}/s` : "-"}
          </span>
          <Sparkline values={rxValues} />
        </div>
        <div className="interface-graph-row">
          <span className="interface-graph-label">TX</span>
          <span className="interface-graph-value">
            {latest ? `${formatBytes(latest.tx)}/s` : "-"}
          </span>
          <Sparkline values={txValues} />
        </div>
      </div>
    </section>
  );
}

export const SPARKLINE_BLOCKS = "▁▂▃▄▅▆▇█";

export function sparklineChar(value: number, max: number): string {
  const ratio = max > 0 ? Math.min(value / max, 1) : 0;
  const index = Math.round(ratio * (SPARKLINE_BLOCKS.length - 1));
  return SPARKLINE_BLOCKS[index];
}

export function Sparkline({ values }: { values: number[] }) {
  if (values.length === 0) {
    return <span className="interface-graph-spark empty">waiting for samples...</span>;
  }
  const max = Math.max(...values, 1);
  return (
    <span className="interface-graph-spark" role="img" aria-label="throughput history">
      {values.map((value, index) => (
        <span key={index}>{sparklineChar(value, max)}</span>
      ))}
    </span>
  );
}
