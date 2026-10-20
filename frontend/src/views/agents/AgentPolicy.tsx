import { useEffect, useState } from "react";
import type { Mutate, Policy, Rule } from "../../agentsApi";

export function AgentPolicy({ policy, busy, mutate }: { policy: Policy; busy: boolean; mutate: Mutate }) {
  const [rules, setRules] = useState<Rule[]>(policy.egress ?? []);
  const [destinations, setDestinations] = useState<string[]>((policy.egress ?? []).map(r => JSON.stringify(r.to)));
  // Raw text of the comma-separated "From" inputs; parsed only on submit so commas can be typed.
  const [froms, setFroms] = useState<string[]>((policy.egress ?? []).map(r => r.from.join(", ")));
  const [sets, setSets] = useState(JSON.stringify(policy.sets ?? {}, null, 2));
  const [error, setError] = useState("");
  useEffect(() => {
    setRules(policy.egress ?? []); setDestinations((policy.egress ?? []).map(r => JSON.stringify(r.to)));
    setFroms((policy.egress ?? []).map(r => r.from.join(", ")));
    setSets(JSON.stringify(policy.sets ?? {}, null, 2)); setError("");
  }, [policy]);
  function update(index: number, patch: Partial<Rule>) { setRules(rules.map((r, i) => i === index ? { ...r, ...patch } : r)); }
  return <section className="panel" data-capability="agent.policy.show">
    <h2>Egress policy</h2><p className="field-help">First match wins. The compiler preserves the fabric recovery path. Domain/URL resolution and node-to-node exits are not supported yet and are refused by the backend. Use explicit CIDRs; a saved policy is not proof of connectivity.</p>
    <form onSubmit={e => {
      e.preventDefault(); setError("");
      try {
        const egress = rules.map((rule, i) => ({ ...rule, from: froms[i].split(",").map(v => v.trim()).filter(Boolean), to: JSON.parse(destinations[i]) }));
        void mutate("/policy", "PUT", { ...policy, sets: JSON.parse(sets), egress });
      } catch { setError("Destination and destination-set fields must contain valid JSON. Backend validates policy semantics."); }
    }}><fieldset disabled={busy} className="agent-rule-list">
      {rules.map((rule, index) => <fieldset className="agent-fields agent-rule" key={index}>
        <legend>Rule {index + 1}</legend>
        <label>Rule ID<input value={rule.id ?? ""} onChange={e => update(index, { id: e.target.value || null })} /></label>
        <label>From (comma-separated)<input value={froms[index]} onChange={e => setFroms(froms.map((v, i) => i === index ? e.target.value : v))} /></label>
        <label>Destination (JSON)<input value={destinations[index]} onChange={e => setDestinations(destinations.map((v, i) => i === index ? e.target.value : v))} /><small>Examples: "any", "fabric", {"{\"set\":\"corp\"}"}, {"{\"routes\":[\"192.0.2.0/24\"]}"}.</small></label>
        <label>Via<input list="agent-exits" value={rule.via} onChange={e => update(index, { via: e.target.value })} /></label>
        <label className="agent-check"><input type="checkbox" checked={rule.kill_switch ?? true} onChange={e => update(index, { kill_switch: e.target.checked })} /> Kill switch</label>
        <div className="row-actions"><button className="action-button" type="button" onClick={() => { setRules(rules.filter((_, i) => i !== index)); setDestinations(destinations.filter((_, i) => i !== index)); setFroms(froms.filter((_, i) => i !== index)); }}>Remove rule</button>{index > 0 && <button className="action-button" type="button" onClick={() => {
          const next = [...rules], dest = [...destinations], from = [...froms]; [next[index - 1], next[index]] = [next[index], next[index - 1]]; [dest[index - 1], dest[index]] = [dest[index], dest[index - 1]]; [from[index - 1], from[index]] = [from[index], from[index - 1]]; setRules(next); setDestinations(dest); setFroms(from);
        }}>Move up</button>}</div>
      </fieldset>)}
      <datalist id="agent-exits"><option value="local" /><option value="fabric" /><option value="drop" /></datalist>
      <button className="action-button" type="button" onClick={() => { setRules([...rules, { from: ["host"], to: "any", via: "local", kill_switch: true }]); setDestinations([...destinations, '"any"']); setFroms([...froms, "host"]); }}>Add rule</button>
      <label>Destination sets (JSON)<textarea className="agent-code" rows={8} value={sets} onChange={e => setSets(e.target.value)} /></label>
    </fieldset>{error && <p role="alert">{error}</p>}<div className="panel-footer"><button className="action-button primary" disabled={busy} data-capability="agent.policy.set">Save policy</button></div></form>
  </section>;
}
