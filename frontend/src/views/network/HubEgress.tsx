import { useEffect, useRef, useState } from "react";
import { agentGet, agentWrite, type Policy, type Rule, type Source } from "../../agentsApi";
import type { NetExplainResult } from "../../api";
import { DestinationSets } from "./DestinationSets";
import { EgressRules, NEW_RULE, type DeadRule, type ExplainState } from "./EgressRules";

type Shown = { policy: Policy; warnings: string[]; dead_rules?: DeadRule[] };
type Mode = "rules" | "json";

const EMPTY_SOURCE: Source = { name: "", interface: "", cidr: "", export: true, allow_outside_pool: false, description: "" };

/** Hub egress rules and attached access-server sources (spec 02): two panels over one policy, the same service as `korctl egress`. */
export function HubEgress({ token, focus, active = true }: { token: string | null; focus?: "sources"; active?: boolean }) {
  const sourcesPanel = useRef<HTMLElement>(null);
  useEffect(() => {
    if (active && focus === "sources") {
      sourcesPanel.current?.scrollIntoView({ block: "start" });
      sourcesPanel.current?.focus({ preventScroll: true });
    }
  }, [focus, active]);
  const [shown, setShown] = useState<Shown | null>(null);
  const [policy, setPolicy] = useState<Policy>({});
  const [mode, setMode] = useState<Mode>("rules");
  const [text, setText] = useState("");
  const [live, setLive] = useState<{ dead: DeadRule[]; warnings: string[]; problem: string } | null>(null);
  const [explain, setExplain] = useState<ExplainState>(null);
  const [probe, setProbe] = useState({ src: "host", dst: "" });
  const [draft, setDraft] = useState<Source>(EMPTY_SOURCE);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [note, setNote] = useState("");
  const [noticeScope, setNoticeScope] = useState<"rules" | "sources">("rules");
  const fail = (reason: unknown) => setError(String(reason instanceof Error ? reason.message : reason));
  const load = (next: Shown) => { setShown(next); setPolicy(next.policy); setText(JSON.stringify(next.policy, null, 2)); setLive(null); setExplain(null); };
  useEffect(() => { void agentGet<Shown>("/api/egress", token).then(load).catch(fail); }, [token]);
  async function run(scope: "rules" | "sources", action: () => Promise<unknown>, done: (result: never) => void) {
    setBusy(true); setError(""); setNote(""); setNoticeScope(scope);
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
  const classes = ["clients", "host", "interlink", ...sources.map(s => s.name)];
  const notices = (scope: "rules" | "sources") => scope === noticeScope && <>{error && <p role="alert">{error}</p>}{note && <p role="status">{note}</p>}</>;
  return <>
    <section className="panel" data-capability="egress.hub.show">
      <div className="panel-header"><div><h2>Egress rules</h2><p className="muted-line">Choose an exit for traffic arriving at this hub. Rules run top to bottom: the first match wins, and unmatched traffic is dropped. Destination sets below are reusable lists of addresses and domains, not source networks.</p></div></div>
      <dl className="detail-grid">
        <div><dt>local</dt><dd>Leave through this hub’s own connection.</dd></div>
        <div><dt>upstream:&lt;profile&gt;</dt><dd>Leave through an external VPN profile.</dd></div>
        <div><dt>node:&lt;n&gt;</dt><dd>Leave through remote node n, which must have the gateway role.</dd></div>
      </dl>
      {notices("rules")}
      {live?.problem && dirty && <p role="status" className="muted-line">Draft is not valid yet: {live.problem}</p>}
      {warnings.map(w => <p key={w} className="muted-line">{w}</p>)}
      <div className="egress-tabs" role="tablist">
        <button type="button" role="tab" aria-selected={mode === "rules"} className={`action-button${mode === "rules" ? " primary" : ""}`} onClick={() => switchMode("rules")}>Rules</button>
        <button type="button" role="tab" aria-selected={mode === "json"} className={`action-button${mode === "json" ? " primary" : ""}`} onClick={() => switchMode("json")}>JSON (advanced)</button>
      </div>
      <form data-capability="egress.hub.set" onSubmit={e => { e.preventDefault(); void run("rules", async () => agentWrite("/api/egress", "PUT", parse(), token), (r: Shown) => { load(r); setNote("Policy saved."); }); }}>
        {mode === "json"
          ? <label className="egress-json">Policy (JSON: sources, sets, egress)<textarea className="agent-code" rows={14} value={text} onChange={e => setText(e.target.value)} /></label>
          : <>
            <DestinationSets sets={policy.sets ?? {}} disabled={busy} onChange={sets => { setPolicy({ ...policy, sets }); setExplain(null); }} />
            <EgressRules rules={rules} disabled={busy} classes={classes} deadRules={deadRules} explain={explain} onChange={setRules} />
            <button type="button" className="action-button" disabled={busy} onClick={() => setRules([...rules, NEW_RULE])}>Add rule</button>
            <details className="network-rule-test">
              <summary>Test a saved rule</summary>
              <p className="muted-line">Find and highlight the matching rule without changing the network. This uses the saved policy; save or discard your draft first. For route, NAT and runtime details, open Kernel diagnostics.</p>
            <div className="egress-explain-bar">
              <label>Explain from<input aria-label="Explain source" value={probe.src} onChange={e => setProbe({ ...probe, src: e.target.value })} placeholder="host or client IP" /></label>
              <label>to<input aria-label="Explain destination" value={probe.dst} onChange={e => setProbe({ ...probe, dst: e.target.value })} placeholder="destination IP" /></label>
              <button type="button" className="action-button" disabled={busy || dirty || !probe.dst} title={dirty ? "Save the rules first: explain uses the saved policy" : undefined}
                onClick={() => void run("rules", async () => agentWrite("/api/net/explain", "POST", probe, token), (r: NetExplainResult) => setExplain({ result: r, ...probe }))}>Explain</button>
            </div>
            {explain && explain.result.matched_rule === null && <p role="status" className="egress-explain">{explain.result.implicit ?? "No rule matched."}</p>}
            </details>
          </>}
        <div className="panel-footer">
          {dirty && <button type="button" className="action-button" disabled={busy} onClick={() => setPolicy(shown?.policy ?? {})}>Discard changes</button>}
          <button className="action-button" type="button" disabled={busy} data-capability="egress.hub.check" onClick={() => void run("rules", async () => agentWrite("/api/egress/check", "POST", parse(), token), () => setNote("Policy is valid."))}>Check</button>
          <button className="action-button primary" disabled={busy} data-capability="egress.hub.set">Save policy</button>
        </div>
      </form>
    </section>
    <section className="panel" ref={sourcesPanel} tabIndex={-1} aria-label="Hub sources editor">
      <div className="panel-header"><div><h2>Sources</h2><p className="muted-line">Attach a network served by another VPN service on this hub, such as wg-easy or Amnezia. This registers its existing interface and subnet; it does not create a VPN server or enroll a remote node. Use its source name in egress rules to choose where its traffic goes.</p></div><span className="pill muted">{sources.length || "none"}</span></div>
      {notices("sources")}
      {shown && sources.length === 0 && <p className="muted-line">No local source networks attached. Add one below only if another VPN service already runs on this hub.</p>}
      <ul className="agent-items" data-capability="sources.hub.list">{sources.map(s => <li key={s.name}>
        <span>{s.name} · {s.interface} · {s.cidr}{s.export === false ? " · not exported" : ""}</span>
        <div className="row-actions">
          <button className="action-button" type="button" onClick={() => setDraft({ ...EMPTY_SOURCE, ...s })}>Edit</button>
          <button className="action-button" type="button" disabled={busy || dirty} data-capability="sources.hub.delete" onClick={() => {
            if (!window.confirm(`Remove source ${s.name}? Rules that reference it must be removed first.`)) return;
            void run("sources", () => agentWrite(`/api/sources/${encodeURIComponent(s.name)}`, "DELETE", undefined, token), (r: Shown) => load(r));
          }}>Remove</button>
        </div></li>)}</ul>
      <form data-capability="sources.hub.set" onSubmit={e => { e.preventDefault(); void run("sources", () => agentWrite(`/api/sources/${encodeURIComponent(draft.name)}`, "PUT", { interface: draft.interface, cidr: draft.cidr, export: draft.export, allow_outside_pool: draft.allow_outside_pool ?? false, description: draft.description ?? "" }, token), (r: Shown) => { load(r); setDraft(EMPTY_SOURCE); }); }}>
        <fieldset className="agent-resource-stack" disabled={busy || dirty}>
          <legend>Attach or update a local source</legend>
          <div className="agent-fields">
            <div><label>Source name<input aria-describedby="hub-source-name-help" data-config-field="sources[].name" value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} required /></label><p id="hub-source-name-help" className="field-help">Identifier used in egress rules, for example wg. Use the same name to update an existing source.</p></div>
            <div><label>Source interface<input aria-describedby="hub-source-interface-help" data-config-field="sources[].interface" value={draft.interface} onChange={e => setDraft({ ...draft, interface: e.target.value })} required /></label><p id="hub-source-interface-help" className="field-help">Existing Linux interface visible to kornode, for example wg0 or awg0. Not the outbound exit interface.</p></div>
            <div><label>Source CIDR<input aria-describedby="hub-source-cidr-help" data-config-field="sources[].cidr" value={draft.cidr} onChange={e => setDraft({ ...draft, cidr: e.target.value })} required /></label><p id="hub-source-cidr-help" className="field-help">Subnet of clients behind that interface, for example 10.8.1.0/24. Not the server’s public IP or a destination list.</p></div>
            <label>Source description<input data-config-field="sources[].description" maxLength={200} value={draft.description ?? ""} onChange={e => setDraft({ ...draft, description: e.target.value })} /></label>
          </div>
          <fieldset className="agent-resource-stack">
            <legend>Reachability &amp; address allocation</legend>
            <div><label className="agent-check"><input aria-describedby="hub-source-export-help" data-config-field="sources[].export" type="checkbox" checked={draft.export} onChange={e => setDraft({ ...draft, export: e.target.checked })} /> Export to the interlink</label><p id="hub-source-export-help" className="field-help">Advertise this subnet to other nodes over the server-to-server interlink. This does not select an exit for its traffic; egress rules do that.</p></div>
            <div><label className="agent-check"><input aria-describedby="hub-source-pool-help" data-config-field="sources[].allow_outside_pool" type="checkbox" checked={draft.allow_outside_pool ?? false} onChange={e => setDraft({ ...draft, allow_outside_pool: e.target.checked })} /> Allow outside derived source pool</label><p id="hub-source-pool-help" className="field-help">Advanced exception for an existing subnet outside this hub’s allocated source address range. Overlap checks still apply; leave off when using the allocated range.</p></div>
          </fieldset>
          {dirty && <p className="field-help">Unsaved rule changes: save or discard them before editing sources.</p>}
          <div className="panel-footer"><button className="action-button primary" data-capability="sources.hub.set">Save source</button></div>
        </fieldset>
      </form>
    </section>
  </>;
}
