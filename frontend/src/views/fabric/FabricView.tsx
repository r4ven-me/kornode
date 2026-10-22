import { useEffect, useState } from "react";
import { agentGet, agentWrite, type Agent, type Prefix, type Source } from "../../agentsApi";
import { FabricDns } from "../agents/FabricDns";

type Settings = { node_id: number; cidr: string; client_pool: string; source_pool: string; enroll_pool: string; domain: string; reserved: string[] };
type FabricNode = { id: number; name: string; roles: string[]; state: Agent["state"]; online: boolean; fabric_address: string; prefixes: Prefix[] };
type Fabric = { fabric: Settings; hub: { fabric_address: string; server_name: string; prefixes: Prefix[] }; nodes: FabricNode[]; sources: Source[] };

const FIELDS: Array<[Exclude<keyof Settings, "reserved" | "node_id">, string]> = [["cidr", "Fabric CIDR"], ["client_pool", "Client pool"], ["source_pool", "Source pool"], ["enroll_pool", "Enroll pool"], ["domain", "Fabric domain"]];

/** The fabric in one place (spec 07): addressing, nodes with their prefixes, DNS zone, hub sources. Same service as `korctl fabric`. */
export function FabricView({ token }: { token: string | null }) {
  const [data, setData] = useState<Fabric | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [note, setNote] = useState("");
  const fail = (reason: unknown) => setError(String(reason instanceof Error ? reason.message : reason));
  const load = (next: Fabric) => { setData(next); setDraft(next.fabric); };
  useEffect(() => { void agentGet<Fabric>("/api/fabric", token).then(load).catch(fail); }, [token]);
  async function save() {
    if (!draft) return;
    setBusy(true); setError(""); setNote("");
    try { await agentWrite("/api/fabric", "PATCH", draft, token); load(await agentGet<Fabric>("/api/fabric", token)); setNote("Fabric settings saved."); }
    catch (reason) { fail(reason); } finally { setBusy(false); }
  }
  const prefixes = (list: Prefix[]) => list.length ? list.map(p => `${p.prefix}${p.export ? "" : " (not exported)"}`).join(", ") : "no prefixes";
  return <div className="view-stack">
    <section className="panel" data-capability="fabric.show">
      <div className="panel-header"><div><h2>Topology</h2><p className="muted-line">The hub and every agent with their fabric address and the networks they announce.</p></div><span className="pill muted">{data?.fabric.cidr ?? "fabric"}</span></div>
      {error && <p role="alert">{error}</p>}{note && <p role="status">{note}</p>}
      {data && <ul className="agent-items">
        <li><span>hub · {data.hub.fabric_address} · {data.hub.server_name} · {prefixes(data.hub.prefixes)}</span></li>
        {data.nodes.map(n => <li key={n.id}><span>{n.name} · {n.fabric_address} · {n.state}{n.state === "active" ? (n.online ? " · online" : " · offline") : ""}{n.roles.length ? ` · ${n.roles.join(", ")}` : ""} · {prefixes(n.prefixes)}</span></li>)}
      </ul>}
      {data && <p className="field-help">Hub prefixes follow the client pool and the hub sources; add, change or remove a source (and whether it is exported) in Network → Sources.</p>}
      {data && data.sources.length > 0 && <><h3 className="panel-section-title">Hub sources</h3><ul className="agent-items">{data.sources.map(s => <li key={s.name}><span>{s.name} · {s.interface} · {s.cidr}{s.export === false ? " · not exported" : ""}</span></li>)}</ul></>}
    </section>
    <section className="panel" data-capability="fabric.settings">
      <div className="panel-header"><div><h2>Fabric settings</h2><p className="muted-line">Addresses of every node derive from these values; <code>{"{id}"}</code> is the node ID. The defaults fit most setups: change them only when they collide with your own networks.</p></div></div>
      {draft && <form onSubmit={e => { e.preventDefault(); void save(); }}>
        <fieldset className="agent-fields" disabled={busy}>
          <label>Hub node ID<input type="number" min={1} max={254} value={draft.node_id} onChange={e => setDraft({ ...draft, node_id: Number(e.target.value) || 1 })} required /></label>
          {FIELDS.map(([key, label]) => <label key={key}>{label}<input value={draft[key]} onChange={e => setDraft({ ...draft, [key]: e.target.value })} required /></label>)}
          <label>Reserved addresses (comma separated)<input value={draft.reserved.join(", ")} onChange={e => setDraft({ ...draft, reserved: e.target.value.split(",").map(v => v.trim()).filter(Boolean) })} /></label>
        </fieldset>
        <div className="panel-footer"><button className="action-button primary" disabled={busy}>Save fabric settings</button></div>
      </form>}
    </section>
    <FabricDns token={token} agents={data?.nodes ?? []} />
  </div>;
}
