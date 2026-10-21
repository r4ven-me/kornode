import { useEffect, useState } from "react";
import { agentGet, agentWrite, type Policy, type Rule, type Source } from "../../agentsApi";
import type { NetExplainResult } from "../../api";
import { EgressRules, NEW_RULE, type DeadRule, type ExplainState } from "./EgressRules";

type Shown = { policy: Policy; warnings: string[]; dead_rules?: DeadRule[] };
type Mode = "rules" | "json";

const EMPTY_SOURCE: Source = { name: "", interface: "", cidr: "", export: true };

/** Hub egress rules and attached access-server sources (spec 02): one editor, the same service as `korctl egress`. */
export function HubEgress({ token }: { token: string | null }) {
  const [shown, setShown] = useState<Shown | null>(null);
  const [policy, setPolicy] = useState<Policy>({});
  const [mode, setMode] = useState<Mode>("rules");
  const [text, setText] = useState("");
  const [live, setLive] = useState<{ dead: DeadRule[]; warnings: string[]; problem: string } | null>(null);
  const [explain, setExplain] = useState<ExplainState>(null);
  const [probe, setProbe] = useState({ src: "host", dst: "" });
  const [draft, setDraft] = useState<Source>(EMPTY_SOURCE);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [note, setNote] = useState("");
  const fail = (reason: unknown) => setError(String(reason instanceof Error ? reason.message : reason));
  const load = (next: Shown) => { setShown(next); setPolicy(next.policy); setText(JSON.stringify(next.policy, null, 2)); setLive(null); setExplain(null); };
  useEffect(() => { void agentGet<Shown>("/api/egress", token).then(load).catch(fail); }, [token]);
  async function run(action: () => Promise<unknown>, done: (result: never) => void) {
    setBusy(true); setError(""); setNote("");
    try { done((await action()) as never); } catch (reason) { fail(reason); } finally { setBusy(false); }
  }
  const parse = (): Policy => (mode === "json" ? JSON.parse(text) : policy) as Policy;
  const dirty = mode === "rules" && shown !== null && JSON.stringify(policy) !== JSON.stringify(shown.policy);
  // Unsaved rule edits are checked in the background so dead rules are marked while editing.
  useEffect(() => {
    if (!dirty) { setLive(null); return; }
    const timer = window.setTimeout(() => {
      agentWrite("/api/egress/check", "POST", policy, token)
        .then(r => setLive({ dead: (r.dead_rules as DeadRule[] | undefined) ?? [], warnings: (r.warnings as string[] | undefined) ?? [], problem: "" }))
        .catch(reason => setLive({ dead: [], warnings: [], problem: String(reason instanceof Error ? reason.message : reason) }));
    }, 400);
    return () => window.clearTimeout(timer);
  }, [policy, dirty, token]);
  const sources = shown?.policy.sources ?? [];
  const rules = policy.egress ?? [];
  const setRules = (egress: Rule[]) => { setPolicy({ ...policy, egress }); setExplain(null); };
  const switchMode = (next: Mode) => {
    try {
      if (next === "json") setText(JSON.stringify(policy, null, 2));
      else setPolicy(JSON.parse(text) as Policy);
      setError(""); setMode(next);
    } catch (reason) { fail(reason); }
  };
  const warnings = dirty ? (live?.warnings ?? []) : (shown?.warnings ?? []);
  const deadRules = dirty ? (live?.dead ?? []) : (shown?.dead_rules ?? []);
  const classes = ["clients", "host", "fabric", ...sources.map(s => s.name)];
  return <section className="panel" data-capability="egress.hub.show">
    <div className="panel-header"><h2>Egress and sources</h2></div>
    <p className="field-help">First match wins; traffic of clients and sources that matches no rule is dropped. <code>exit:&lt;n&gt;</code> sends it through another node with the exit role.</p>
    {error && <p role="alert">{error}</p>}{note && <p role="status">{note}</p>}
    {live?.problem && dirty && <p role="status" className="muted-line">Draft is not valid yet: {live.problem}</p>}
    {warnings.map(w => <p key={w} className="muted-line">{w}</p>)}
    <ul className="agent-items" data-capability="sources.hub.list">{sources.map(s => <li key={s.name}>
      <span>{s.name} · {s.interface} · {s.cidr}{s.export === false ? " · not exported" : ""}</span>
      <div className="row-actions">
        <button className="action-button" type="button" onClick={() => setDraft({ ...EMPTY_SOURCE, ...s })}>Edit</button>
        <button className="action-button" type="button" disabled={busy || dirty} data-capability="sources.hub.delete" onClick={() => {
          if (!window.confirm(`Remove source ${s.name}? Rules that reference it must be removed first.`)) return;
          void run(() => agentWrite(`/api/sources/${encodeURIComponent(s.name)}`, "DELETE", undefined, token), (r: Shown) => load(r));
        }}>Remove</button>
      </div></li>)}</ul>
    <form onSubmit={e => { e.preventDefault(); void run(() => agentWrite(`/api/sources/${encodeURIComponent(draft.name)}`, "PUT", { interface: draft.interface, cidr: draft.cidr, export: draft.export, ...(draft.allow_outside_pool ? { allow_outside_pool: true } : {}), ...(draft.description ? { description: draft.description } : {}) }, token), (r: Shown) => { load(r); setDraft(EMPTY_SOURCE); }); }}>
      <fieldset className="agent-fields" disabled={busy || dirty}>
        <label>Source name<input value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} required /></label>
        <label>Source interface<input value={draft.interface} onChange={e => setDraft({ ...draft, interface: e.target.value })} required /></label>
        <label>Source CIDR<input value={draft.cidr} onChange={e => setDraft({ ...draft, cidr: e.target.value })} required /></label>
        <label className="agent-check"><input type="checkbox" checked={draft.export} onChange={e => setDraft({ ...draft, export: e.target.checked })} /> Export to the fabric</label>
        <button className="action-button" data-capability="sources.hub.set">Save source</button>
      </fieldset>
    </form>
    {dirty && <p className="field-help">Unsaved rule changes: save or discard them before editing sources.</p>}
    <div className="egress-tabs" role="tablist">
      <button type="button" role="tab" aria-selected={mode === "rules"} className={`action-button${mode === "rules" ? " primary" : ""}`} onClick={() => switchMode("rules")}>Rules</button>
      <button type="button" role="tab" aria-selected={mode === "json"} className={`action-button${mode === "json" ? " primary" : ""}`} onClick={() => switchMode("json")}>JSON (advanced)</button>
    </div>
    <form onSubmit={e => { e.preventDefault(); void run(async () => agentWrite("/api/egress", "PUT", parse(), token), (r: Shown) => { load(r); setNote("Policy saved."); }); }}>
      {mode === "json"
        ? <label>Policy (JSON: sources, sets, egress)<textarea className="agent-code" rows={14} value={text} onChange={e => setText(e.target.value)} /></label>
        : <>
          <EgressRules rules={rules} disabled={busy} classes={classes} deadRules={deadRules} explain={explain} onChange={setRules} />
          <button type="button" className="action-button" disabled={busy} onClick={() => setRules([...rules, NEW_RULE])}>Add rule</button>
          <div className="egress-explain-bar">
            <label>Explain from<input aria-label="Explain source" value={probe.src} onChange={e => setProbe({ ...probe, src: e.target.value })} placeholder="host or client IP" /></label>
            <label>to<input aria-label="Explain destination" value={probe.dst} onChange={e => setProbe({ ...probe, dst: e.target.value })} placeholder="destination IP" /></label>
            <button type="button" className="action-button" disabled={busy || dirty || !probe.dst} title={dirty ? "Save the rules first: explain uses the saved policy" : undefined}
              onClick={() => void run(async () => agentWrite("/api/net/explain", "POST", probe, token), (r: NetExplainResult) => setExplain({ result: r, ...probe }))}>Explain</button>
          </div>
          {explain && explain.result.matched_rule === null && <p role="status" className="egress-explain">{explain.result.implicit ?? "No rule matched."}</p>}
        </>}
      <div className="panel-footer">
        {dirty && <button type="button" className="action-button" disabled={busy} onClick={() => setPolicy(shown?.policy ?? {})}>Discard changes</button>}
        <button className="action-button" type="button" disabled={busy} data-capability="egress.hub.check" onClick={() => void run(async () => agentWrite("/api/egress/check", "POST", parse(), token), () => setNote("Policy is valid."))}>Check</button>
        <button className="action-button primary" disabled={busy} data-capability="egress.hub.set">Save policy</button>
      </div>
    </form>
  </section>;
}
