import { useEffect, useState } from "react";
import { agentGet, agentWrite, type Agent } from "../../agentsApi";

export type ZoneRecord = { fqdn: string; type: "A" | "AAAA" | "CNAME"; value: string; node: string | null; generated: boolean };
type Zone = { domain: string; records: ZoneRecord[] };

/** The name as the API takes it: relative to the zone, or to node<id>.<zone> for agent records. */
function relative(record: ZoneRecord, domain: string): string {
  return record.node && record.node !== "hub" ? record.fqdn.slice(0, record.fqdn.lastIndexOf(".node")) : record.fqdn.slice(0, -(domain.length + 1));
}

/** Fabric DNS zone (spec 07 "DNS"): the hub answers it, agents answer their node<id> part. */
export function FabricDns({ token, agents }: { token: string | null; agents: Array<Pick<Agent, "id" | "name" | "state">> }) {
  const [zone, setZone] = useState<Zone | null>(null);
  const [name, setName] = useState(""), [type, setType] = useState<ZoneRecord["type"]>("A"), [value, setValue] = useState(""), [node, setNode] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const fail = (reason: unknown) => setError(String(reason instanceof Error ? reason.message : reason));
  const refresh = () => agentGet<Zone>("/api/dns/records", token).then(setZone);
  useEffect(() => { void refresh().catch(fail); }, [token]); // eslint-disable-line react-hooks/exhaustive-deps
  async function write(method: "POST" | "DELETE", body: Record<string, unknown>) {
    setBusy(true); setError("");
    try { setZone(await agentWrite("/api/dns/records", method, body, token) as unknown as Zone); return true; }
    catch (reason) { fail(reason); return false; }
    finally { setBusy(false); }
  }
  const domain = zone?.domain ?? "";
  return <section className="panel" data-capability="dns.record.list"><div className="panel-header"><div><h2>Fabric DNS</h2><p className="muted-line">The hub answers every name in the zone; each agent answers its own node zone even while the hub is unreachable.</p></div><span className="pill muted">{domain || "zone"}</span></div>
    {error && <p role="alert">{error}</p>}
    <ul className="agent-items">{(zone?.records ?? []).map(r => <li key={`${r.fqdn}/${r.type}/${r.value}`}><span>{r.fqdn} · {r.type} · {r.value}{r.generated ? " · generated" : ` · ${r.node ?? "hub"}`}</span>
      {!r.generated && <div className="row-actions"><button className="action-button" type="button" disabled={busy} data-capability="dns.record.delete" onClick={() => {
        if (!window.confirm(`Delete ${r.type} record ${r.fqdn}?`)) return;
        void write("DELETE", { name: relative(r, domain), type: r.type, value: r.value, node: r.node === "hub" ? null : r.node });
      }}>Delete</button></div>}</li>)}</ul>
    <form onSubmit={e => { e.preventDefault(); void write("POST", { name, type, value, node: node || null }).then(ok => { if (ok) { setName(""); setValue(""); } }); }}>
      <fieldset className="agent-fields" disabled={busy}>
        <label>Record name (relative to the zone)<input value={name} onChange={e => setName(e.target.value)} required /></label>
        <label>Record type<select value={type} onChange={e => setType(e.target.value as ZoneRecord["type"])}><option>A</option><option>AAAA</option><option>CNAME</option></select></label>
        <label>Record value<input value={value} onChange={e => setValue(e.target.value)} required /></label>
        <label>Record scope<select value={node} onChange={e => setNode(e.target.value)}><option value="">Hub-wide ({domain})</option>{agents.filter(a => a.state !== "revoked").map(a => <option key={a.id} value={a.name}>{a.name} (node{a.id}.{domain})</option>)}</select></label>
      </fieldset>
      <div className="panel-footer"><button className="action-button primary" disabled={busy} data-capability="dns.record.add">Add record</button></div>
    </form>
  </section>;
}
