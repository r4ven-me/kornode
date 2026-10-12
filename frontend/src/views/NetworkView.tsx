import { GitCompareArrows, Play, RefreshCw, Search } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import {
  applyNetPlan,
  explainNetPolicy,
  fetchNetPlan,
  fetchNetStatus,
  type NetApplyResult,
  type NetExplainResult,
  type NetPlan,
  type NetStatus
} from "../api";
import { errorMessage } from "../lib/errors";
import { netDriftCount, netPlanLines } from "../lib/net";
import { ActionButton, EmptyState, Pill } from "../components/ui";

export function NetworkView({ token }: { token: string }) {
  const [plan, setPlan] = useState<NetPlan | null>(null);
  const [status, setStatus] = useState<NetStatus | null>(null);
  const [explain, setExplain] = useState<NetExplainResult | null>(null);
  const [src, setSrc] = useState("host");
  const [dst, setDst] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [applyResult, setApplyResult] = useState<NetApplyResult | null>(null);

  const refresh = async () => {
    setBusy("net-refresh");
    setError(null);
    try {
      const [nextPlan, nextStatus] = await Promise.all([
        fetchNetPlan(token),
        fetchNetStatus(token)
      ]);
      setPlan(nextPlan);
      setStatus(nextStatus);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  useEffect(() => {
    void refresh();
  }, [token]);

  const apply = async (dryRun: boolean) => {
    setBusy(dryRun ? "net-apply-dry-run" : "net-apply");
    setError(null);
    setApplyResult(null);
    try {
      const result = await applyNetPlan(token, dryRun);
      setApplyResult(result);
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const submitExplain = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy("net-explain");
    setError(null);
    setExplain(null);
    try {
      setExplain(await explainNetPolicy(token, src.trim(), dst.trim()));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="view-stack">
      {error && <section className="panel notice-error">{error}</section>}
      <section className="panel" data-capability="net.plan">
        <div className="panel-header">
          <div>
            <h2>Plan</h2>
            <p className="muted-line">Compiled network policy compared with the kernel.</p>
          </div>
          <div className="toolbar">
            <ActionButton
              label="Refresh"
              icon={RefreshCw}
              busy={busy === "net-refresh"}
              onClick={() => void refresh()}
            />
            <ActionButton
              label="Dry run"
              icon={GitCompareArrows}
              busy={busy === "net-apply-dry-run"}
              onClick={() => void apply(true)}
              data-capability="net.apply"
            />
            <ActionButton
              label="Apply"
              icon={Play}
              primary
              busy={busy === "net-apply"}
              onClick={() => void apply(false)}
              data-capability="net.apply"
            />
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Mark</th>
                <th>Table</th>
                <th>Interface</th>
                <th>State</th>
                <th>Kill-switch</th>
              </tr>
            </thead>
            <tbody>
              {(plan?.exits ?? []).map((exit) => (
                <tr key={exit.name}>
                  <td className="strong-cell">{exit.name}</td>
                  <td><code>{exit.mark}</code></td>
                  <td>{exit.table ?? "-"}</td>
                  <td>{exit.interface}</td>
                  <td><Pill kind={exit.up ? "ok" : "muted"}>{exit.up ? "up" : "down"}</Pill></td>
                  <td>{exit.kill_switch ? "on" : "off"}</td>
                </tr>
              ))}
              {plan && plan.exits.length === 0 && (
                <tr><td colSpan={6}>No exits compiled.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {plan?.warnings.length ? (
          <ul className="warning-list">
            {plan.warnings.map((warning) => <li key={warning}>{warning}</li>)}
          </ul>
        ) : null}
        <div className="command-output">
          <pre>{netPlanLines(plan?.ops ?? []).join("\n")}</pre>
        </div>
        {applyResult && (
          <p className="muted-line">
            {applyResult.dry_run ? "Dry run completed." : `Applied via ${applyResult.via ?? "net service"}.`}
          </p>
        )}
      </section>

      <section className="panel" data-capability="net.explain">
        <div className="panel-header">
          <h2>Explain</h2>
        </div>
        <form className="inline-form" onSubmit={submitExplain}>
          <label>
            <span>Source</span>
            <input value={src} onChange={(event) => setSrc(event.target.value)} required />
          </label>
          <label>
            <span>Destination</span>
            <input value={dst} onChange={(event) => setDst(event.target.value)} required />
          </label>
          <button className="primary-button" disabled={busy === "net-explain"} type="submit">
            <Search size={18} aria-hidden="true" />
            <span>{busy === "net-explain" ? "Working" : "Explain"}</span>
          </button>
        </form>
        {explain ? (
          <dl className="detail-grid">
            <div><dt>From class</dt><dd>{explain.from_class}</dd></div>
            <div><dt>Matched rule</dt><dd><code>{explain.matched_rule ? JSON.stringify(explain.matched_rule) : "-"}</code></dd></div>
            <div><dt>Implicit</dt><dd>{explain.implicit ?? "-"}</dd></div>
            <div><dt>Mark</dt><dd>{explain.mark ?? "-"}</dd></div>
            <div><dt>Table</dt><dd>{explain.table ?? "-"}</dd></div>
            <div><dt>Route</dt><dd>{explain.route ?? "-"}</dd></div>
            <div><dt>NAT</dt><dd>{explain.nat ?? "-"}</dd></div>
            <div><dt>Kernel check</dt><dd>{explain.kernel_check ?? "-"}</dd></div>
            <div><dt>Warnings</dt><dd>{explain.warnings.length ? explain.warnings.join("; ") : "-"}</dd></div>
          </dl>
        ) : (
          <EmptyState text="No explanation yet" />
        )}
      </section>

      <section className="panel" data-capability="net.status">
        <div className="panel-header">
          <h2>Reconciler</h2>
          <Pill kind={status?.running ? "ok" : "muted"}>
            {status?.running ? "Running" : "Stopped"}
          </Pill>
        </div>
        <p className="muted-line">
          passes: {status?.passes ?? 0} · last error: {status?.last_error ?? "none"} · drift:{" "}
          {netDriftCount(status)}
        </p>
      </section>
    </div>
  );
}
