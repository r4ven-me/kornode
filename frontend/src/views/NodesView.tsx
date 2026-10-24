import { useEffect, useState } from "react";
import { agentGet, type Agent } from "../agentsApi";
import type { InterlinkSettingsDraft } from "../lib/drafts";
import { AgentsView } from "./agents/AgentsView";
import { InterlinkDns } from "./agents/InterlinkDns";

type Section = "overview" | "settings" | "dns";
const SECTIONS: Array<[Section, string]> = [["overview", "Node list"], ["settings", "Interlink addressing"], ["dns", "Interlink DNS"]];

export function NodesView({ token, dryRun, draft, busy, onDraftChange, onSave, onOpenSources }: {
  token: string | null;
  dryRun: boolean;
  draft: InterlinkSettingsDraft;
  busy: boolean;
  onDraftChange: (draft: InterlinkSettingsDraft) => void;
  onSave: () => void;
  onOpenSources: () => void;
}) {
  const [section, setSection] = useState<Section>("overview");
  const [agents, setAgents] = useState<Agent[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    if (section !== "dns") return;
    let active = true;
    void agentGet<{ agents: Agent[] }>("/api/agents", token)
      .then(next => { if (active) { setAgents(next.agents); setError(""); } })
      .catch(reason => { if (active) setError(String(reason instanceof Error ? reason.message : reason)); });
    return () => { active = false; };
  }, [section, token]);

  return <div className="nodes-view">
    <label className="subnav-select"><span>Nodes section</span><select aria-label="Nodes section" value={section} onChange={e => setSection(e.target.value as Section)}>{SECTIONS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
    <nav className="subnav" aria-label="Nodes sections">{SECTIONS.map(([id, label]) => <button key={id} type="button" className={`subnav-item${section === id ? " active" : ""}`} aria-current={section === id ? "page" : undefined} onClick={() => setSection(id)}>{label}</button>)}</nav>
    {/* Keep the selected agent and unsaved detail forms when visiting Settings or DNS. */}
    <div hidden={section !== "overview"}><AgentsView token={token} dryRun={dryRun} active={section === "overview"} onOpenSources={onOpenSources} /></div>
    {section === "settings" && <section className="panel" data-capability="interlink.settings">
      <div className="panel-header"><div><h2>Interlink settings</h2><p className="muted-line">Addresses of every node derive from these values; <code>{"{id}"}</code> is the node ID. Change the defaults only when they collide with your networks.</p></div></div>
      <form onSubmit={e => { e.preventDefault(); onSave(); }}>
        <fieldset className="agent-fields" disabled={busy}>
          <label>Hub node ID<input type="number" min={1} max={254} value={draft.nodeId} onChange={e => onDraftChange({ ...draft, nodeId: Number(e.target.value) || 1 })} required /></label>
          <label>Interlink CIDR<input aria-label="Interlink CIDR" value={draft.cidr} onChange={e => onDraftChange({ ...draft, cidr: e.target.value })} required /><small>Private transport network connecting the hub and agents, not the VPN client pool.</small></label>
          <label>Client pool template<input aria-label="Client pool template" value={draft.clientPool} onChange={e => onDraftChange({ ...draft, clientPool: e.target.value })} required /><small>VPN client subnet per node. {"{id}"} is replaced with the node ID.</small></label>
          <label>Source pool template<input aria-label="Source pool template" value={draft.sourcePool} onChange={e => onDraftChange({ ...draft, sourcePool: e.target.value })} required /><small>Address pool allocated to each node’s local sources.</small></label>
          <label>Enroll pool<input aria-label="Enroll pool" value={draft.enrollPool} onChange={e => onDraftChange({ ...draft, enrollPool: e.target.value })} required /><small>Temporary addresses used during agent enrollment.</small></label>
          <label>Interlink domain<input value={draft.domain} onChange={e => onDraftChange({ ...draft, domain: e.target.value })} required /></label>
          <label>Reserved CIDRs (one per line)<textarea aria-label="Reserved CIDRs (one per line)" rows={4} value={draft.reserved} onChange={e => onDraftChange({ ...draft, reserved: e.target.value })} /><small>Networks to exclude from automatic address allocation.</small></label>
        </fieldset>
        <div className="panel-footer"><button className="action-button primary" disabled={busy}>Save interlink settings</button></div>
      </form>
    </section>}
    {section === "dns" && <>{error && <p role="alert">Could not load record scopes: {error}</p>}<InterlinkDns token={token} agents={agents} /></>}
  </div>;
}
