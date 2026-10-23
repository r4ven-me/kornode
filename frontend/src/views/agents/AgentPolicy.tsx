import { useEffect, useState } from "react";
import type { JsonObject, Mutate, Policy, Rule } from "../../agentsApi";
import { EgressRules } from "../network/EgressRules";
import { DestinationSets } from "../network/DestinationSets";

const NEW_AGENT_RULE: Rule = { from: ["host"], to: "any", via: "local" };

/** Egress policy of one agent: the same ordered rule editor as the hub's (Network → Egress and sources). */
export function AgentPolicy({ policy, busy, mutate }: { policy: Policy; busy: boolean; mutate: Mutate }) {
  const [rules, setRules] = useState<Rule[]>(policy.egress ?? []);
  const [sets, setSets] = useState(JSON.stringify(policy.sets ?? {}, null, 2));
  const [error, setError] = useState("");
  useEffect(() => {
    setRules(policy.egress ?? []);
    setSets(JSON.stringify(policy.sets ?? {}, null, 2));
    setError("");
  }, [policy]);
  let parsedSets: JsonObject | null = null;
  try {
    const value: unknown = JSON.parse(sets);
    if (value && typeof value === "object" && !Array.isArray(value)) parsedSets = value as JsonObject;
  } catch { /* The advanced editor retains invalid JSON for correction. */ }
  const classes = ["clients", "host", "fabric", ...(policy.sources ?? []).map(source => source.name)];
  return <section className="panel" data-capability="agent.policy.show">
    <h2>Egress policy</h2>
    <p className="field-help">First match wins; drag a rule or use the arrows to reorder. The compiler preserves the fabric recovery path. A saved policy is not proof of connectivity: the backend validates semantics and refuses what the node cannot run.</p>
    <form data-capability="agent.policy.set" onSubmit={e => {
      e.preventDefault(); setError("");
      let parsed: Policy["sets"];
      try { parsed = JSON.parse(sets); } catch { setError("Destination sets must contain valid JSON."); return; }
      void mutate("/policy", "PUT", { ...policy, sets: parsed, egress: rules });
    }}>
      <fieldset disabled={busy} className="agent-rule-list">
        <EgressRules rules={rules} disabled={busy} classes={classes} deadRules={[]} explain={null} onChange={setRules} />
        <button className="action-button" type="button" onClick={() => setRules([...rules, NEW_AGENT_RULE])}>Add rule</button>
        {parsedSets !== null && <DestinationSets sets={parsedSets} disabled={busy} onChange={value => setSets(JSON.stringify(value, null, 2))} />}
        <label>Destination sets (JSON)<textarea className="agent-code" rows={8} value={sets} onChange={e => setSets(e.target.value)} /></label>
      </fieldset>
      {error && <p role="alert">{error}</p>}
      <div className="panel-footer"><button className="action-button primary" disabled={busy} data-capability="agent.policy.set">Save policy</button></div>
    </form>
  </section>;
}
