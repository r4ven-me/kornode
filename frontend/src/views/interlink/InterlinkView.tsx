import { useEffect, useState } from "react";
import { agentGet, type Agent, type Prefix, type Source } from "../../agentsApi";

type InterlinkNode = { id: number; name: string; roles: string[]; state: Agent["state"]; online: boolean; interlink_address: string; prefixes: Prefix[] };
type Interlink = { interlink: { cidr: string }; hub: { interlink_address: string; server_name: string; prefixes: Prefix[] }; nodes: InterlinkNode[]; sources: Source[] };

const prefixes = (list: Prefix[]) => list.length ? list.map(p => `${p.prefix}${p.export ? "" : " (not exported)"}`).join(", ") : "no prefixes";

/** Topology is also the agent picker; management remains available if topology cannot load. */
export function InterlinkView({ token, agents, selected, busy, loading, active = true, onSelect, onOpenSources }: {
  token: string | null;
  agents: Agent[];
  selected: string | null;
  busy: boolean;
  loading: boolean;
  active?: boolean;
  onSelect: (name: string) => void;
  onOpenSources: () => void;
}) {
  const [data, setData] = useState<Interlink | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!active) return;
    let current = true;
    void agentGet<Interlink>("/api/interlink", token)
      .then(next => { if (current) { setData(next); setError(""); } })
      .catch(reason => { if (current) setError(String(reason instanceof Error ? reason.message : reason)); });
    return () => { current = false; };
  }, [token, agents, active]);

  return <section className="panel" data-capability="interlink.show">
    <div className="panel-header"><div><h2>Topology</h2><p className="muted-line">The hub and its agents. Select an agent to manage its settings, networks and activity below.</p></div><span className="pill muted">{data?.interlink.cidr ?? "interlink"}</span></div>
    {error && <p role="alert">Topology unavailable: {error}. Agent management is still available below.</p>}
    {data && <div className="node-hub"><strong>Hub · {data.hub.interlink_address}</strong><span>{data.hub.server_name}</span><span>{prefixes(data.hub.prefixes)}</span></div>}
    {loading ? <p>Loading agents…</p> : agents.length === 0 ? <p>No agents registered yet.</p> : <ul className="agent-list" aria-label="Agent nodes">{agents.map(agent => {
      const node = data?.nodes.find(n => n.id === agent.id);
      return <li key={agent.id}><button className={selected === agent.name ? "agent-summary active" : "agent-summary"} type="button" disabled={busy} aria-pressed={selected === agent.name} data-capability="agent.show" onClick={() => onSelect(agent.name)}>
        <strong>{agent.name} · node {agent.id}</strong>
        <span>{agent.state} · {agent.online ? "online" : "offline"}{agent.roles.length ? ` · ${agent.roles.join(", ")}` : ""}</span>
        {node && <span>{node.interlink_address} · {prefixes(node.prefixes)}</span>}
        <span>desired {agent.desired_version} / reported {agent.applied_version}</span>
      </button></li>;
    })}</ul>}
    <p className="field-help">Hub prefixes follow the client pool and exported hub sources. Edit sources in Network, not in the topology.</p>
    {data && data.sources.length > 0 && <><h3 className="panel-section-title">Hub sources</h3><ul className="agent-items">{data.sources.map(s => <li key={s.name}><span>{s.name} · {s.interface} · {s.cidr}{s.export === false ? " · not exported" : ""}</span></li>)}</ul></>}
    <div className="panel-footer"><button className="action-button" type="button" onClick={onOpenSources}>Manage hub sources in Network</button></div>
  </section>;
}
