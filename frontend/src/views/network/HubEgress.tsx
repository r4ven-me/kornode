import { useEffect, useState } from "react";
import { agentGet, agentWrite, type Policy, type Source } from "../../agentsApi";

type Shown = { policy: Policy; warnings: string[] };

const EMPTY_SOURCE: Source = { name: "", interface: "", cidr: "", export: true };

/** Hub egress rules and attached access-server sources (spec 02): one editor, the same service as `korctl egress`. */
export function HubEgress({ token }: { token: string | null }) {
  const [shown, setShown] = useState<Shown | null>(null);
  const [text, setText] = useState("");
  const [draft, setDraft] = useState<Source>(EMPTY_SOURCE);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [note, setNote] = useState("");
  const fail = (reason: unknown) => setError(String(reason instanceof Error ? reason.message : reason));
  const load = (next: Shown) => { setShown(next); setText(JSON.stringify(next.policy, null, 2)); };
  useEffect(() => { void agentGet<Shown>("/api/egress", token).then(load).catch(fail); }, [token]);
  async function run(action: () => Promise<unknown>, done: (result: never) => void) {
    setBusy(true); setError(""); setNote("");
    try { done((await action()) as never); } catch (reason) { fail(reason); } finally { setBusy(false); }
  }
  const parse = (): Record<string, unknown> => JSON.parse(text) as Record<string, unknown>;
  const sources = shown?.policy.sources ?? [];
  return <section className="panel" data-capability="egress.hub.show">
    <div className="panel-header"><h2>Egress and sources</h2></div>
    <p className="field-help">First match wins; traffic of clients and sources that matches no rule is dropped. <code>exit:&lt;n&gt;</code> sends it through another node with the exit role.</p>
    {error && <p role="alert">{error}</p>}{note && <p role="status">{note}</p>}
    {(shown?.warnings ?? []).map(w => <p key={w} className="muted-line">{w}</p>)}
    <ul className="agent-items" data-capability="sources.hub.list">{sources.map(s => <li key={s.name}>
      <span>{s.name} · {s.interface} · {s.cidr}{s.export === false ? " · not exported" : ""}</span>
      <div className="row-actions">
        <button className="action-button" type="button" onClick={() => setDraft({ ...EMPTY_SOURCE, ...s })}>Edit</button>
        <button className="action-button" type="button" disabled={busy} data-capability="sources.hub.delete" onClick={() => {
          if (!window.confirm(`Remove source ${s.name}? Rules that reference it must be removed first.`)) return;
          void run(() => agentWrite(`/api/sources/${encodeURIComponent(s.name)}`, "DELETE", undefined, token), (r: Shown) => load(r));
        }}>Remove</button>
      </div></li>)}</ul>
    <form onSubmit={e => { e.preventDefault(); void run(() => agentWrite(`/api/sources/${encodeURIComponent(draft.name)}`, "PUT", { interface: draft.interface, cidr: draft.cidr, export: draft.export }, token), (r: Shown) => { load(r); setDraft(EMPTY_SOURCE); }); }}>
      <fieldset className="agent-fields" disabled={busy}>
        <label>Source name<input value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} required /></label>
        <label>Source interface<input value={draft.interface} onChange={e => setDraft({ ...draft, interface: e.target.value })} required /></label>
        <label>Source CIDR<input value={draft.cidr} onChange={e => setDraft({ ...draft, cidr: e.target.value })} required /></label>
        <label className="agent-check"><input type="checkbox" checked={draft.export} onChange={e => setDraft({ ...draft, export: e.target.checked })} /> Export to the fabric</label>
        <button className="action-button" data-capability="sources.hub.set">Save source</button>
      </fieldset>
    </form>
    <form onSubmit={e => { e.preventDefault(); void run(async () => agentWrite("/api/egress", "PUT", parse(), token), (r: Shown) => { load(r); setNote("Policy saved."); }); }}>
      <label>Policy (JSON: sources, sets, egress)<textarea className="agent-code" rows={14} value={text} onChange={e => setText(e.target.value)} /></label>
      <div className="panel-footer">
        <button className="action-button" type="button" disabled={busy} data-capability="egress.hub.check" onClick={() => void run(async () => agentWrite("/api/egress/check", "POST", parse(), token), () => setNote("Policy is valid."))}>Check</button>
        <button className="action-button primary" disabled={busy} data-capability="egress.hub.set">Save policy</button>
      </div>
    </form>
  </section>;
}
