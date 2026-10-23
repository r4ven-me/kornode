import { useState } from "react";
import type { AccessListener, AccessUser, Mutate, Prefix, Source, Upstream } from "../../agentsApi";

const lines = (text: string) => text.split(/[\n,]+/).map(v => v.trim()).filter(Boolean);

export function PrefixEditor({ prefixes, busy, mutate }: { prefixes: Prefix[]; busy: boolean; mutate: Mutate }) {
  const [prefix, setPrefix] = useState(""); const [exported, setExported] = useState(true);
  return <section className="panel">
    <h2>Networks</h2><p className="field-help">Client pools are derived. Full interlink routing of exported networks is P4; registry changes are not proof of reachability.</p>
    <ul className="agent-items" data-capability="agent.prefix.list">{prefixes.map(p => <li key={p.prefix}><span>{p.prefix} · {p.kind} · {p.export ? "export" : "local"}</span>{p.kind === "lan" && <button className="action-button" type="button" disabled={busy} data-capability="agent.prefix.delete" onClick={() => void mutate("/prefixes", "DELETE", { prefix: p.prefix }, `Remove exported network ${p.prefix}?`)}>Remove</button>}</li>)}</ul>
    <form onSubmit={e => { e.preventDefault(); void mutate("/prefixes", "POST", { prefix, kind: "lan", export: exported }); }}>
      <fieldset className="agent-fields" disabled={busy}><label>LAN prefix<input value={prefix} onChange={e => setPrefix(e.target.value)} required /></label><label className="agent-check"><input type="checkbox" checked={exported} onChange={e => setExported(e.target.checked)} /> Export prefix</label></fieldset>
      <div className="panel-footer"><button className="action-button primary" disabled={busy} data-capability="agent.prefix.add">Add network</button></div>
    </form>
  </section>;
}

export function SourceEditor({ sources, busy, mutate }: { sources: Source[]; busy: boolean; mutate: Mutate }) {
  const empty: Source = { name: "", interface: "", cidr: "", export: true, allow_outside_pool: false, description: "" };
  const [draft, setDraft] = useState<Source>(empty); const [editing, setEditing] = useState(false);
  return <section className="panel"><h2>Attached sources</h2><p className="field-help">kornode does not create external VPN interfaces. Full source/interlink integration is P4.</p>
    <ul className="agent-items" data-capability="agent.source.list">{sources.map(s => <li key={s.name}><span>{s.name} · {s.interface} · {s.cidr}</span><div className="row-actions"><button className="action-button" type="button" onClick={() => { setDraft(s); setEditing(true); }}>Edit</button><button className="action-button" type="button" disabled={busy} data-capability="agent.source.delete" onClick={() => void mutate(`/sources/${encodeURIComponent(s.name)}`, "DELETE", undefined, `Remove source ${s.name}? Referencing rules must be removed first.`)}>Remove</button></div></li>)}</ul>
    <form onSubmit={e => { e.preventDefault(); const { name, ...data } = draft; void mutate(`/sources/${encodeURIComponent(name)}`, "PUT", data); }}>
      <fieldset className="agent-fields" disabled={busy}>
        <label>Source name<input value={draft.name} disabled={editing} onChange={e => setDraft({ ...draft, name: e.target.value })} required /></label>
        <label>Source interface<input value={draft.interface} onChange={e => setDraft({ ...draft, interface: e.target.value })} required /></label>
        <label>Source CIDR<input value={draft.cidr} onChange={e => setDraft({ ...draft, cidr: e.target.value })} required /></label>
        <label>Source description<input value={draft.description ?? ""} onChange={e => setDraft({ ...draft, description: e.target.value })} /></label>
        <label className="agent-check"><input type="checkbox" checked={draft.export} onChange={e => setDraft({ ...draft, export: e.target.checked })} /> Export source</label>
        <label className="agent-check"><input type="checkbox" checked={draft.allow_outside_pool ?? false} onChange={e => setDraft({ ...draft, allow_outside_pool: e.target.checked })} /> Allow outside derived source pool</label>
      </fieldset>
      <div className="panel-footer"><button className="action-button" type="button" onClick={() => { setDraft(empty); setEditing(false); }}>New source</button><button className="action-button primary" disabled={busy} data-capability="agent.source.set">Save source</button></div>
    </form>
  </section>;
}

export function UpstreamEditor({ upstreams, busy, mutate }: { upstreams: Upstream[]; busy: boolean; mutate: Mutate }) {
  const empty: Upstream = { name: "", interface: "", server: "", port: 443, auth_type: "password", transport: "tcp", username: "", enabled: true };
  const [draft, setDraft] = useState<Upstream>(empty); const [editing, setEditing] = useState(false);
  const [password, setPassword] = useState(""); const [key, setKey] = useState(""); const [camouflage, setCamouflage] = useState("");
  const [clearCamouflage, setClearCamouflage] = useState(false);
  function load(value: Upstream, isEdit: boolean) { setDraft(value); setEditing(isEdit); setPassword(""); setKey(""); setCamouflage(""); setClearCamouflage(false); }
  return <section className="panel"><h2>External upstreams</h2><p className="field-help">Credentials are write-only; blank preserves existing values. p12 and server-pushed routes are not supported by the current agent.</p>
    <ul className="agent-items" data-capability="agent.upstream.list">{upstreams.map(u => <li key={u.name}><span>{u.name} · {u.server}:{u.port} · {u.credentials_set ? "credentials set" : "no credentials"}</span><div className="row-actions"><button className="action-button" type="button" onClick={() => load(u, true)}>Edit</button><button className="action-button" type="button" disabled={busy} data-capability="agent.upstream.delete" onClick={() => void mutate(`/upstreams/${encodeURIComponent(u.name)}`, "DELETE", undefined, `Delete upstream ${u.name}? Referencing rules must be removed first.`)}>Delete</button></div></li>)}</ul>
    <form onSubmit={e => {
      e.preventDefault(); const { name, credentials_set: _credentials, ...spec } = draft;
      const data: Record<string, unknown> = { ...spec };
      if (password) data.password = password; if (key) data.key = key;
      if (clearCamouflage) data.camouflage = null; else if (camouflage) data.camouflage = camouflage;
      void mutate(`/upstreams/${encodeURIComponent(name)}`, "PUT", data).then(ok => { if (ok) { setPassword(""); setKey(""); setCamouflage(""); } });
    }}><fieldset className="agent-fields" disabled={busy}>
      <label>Upstream name<input value={draft.name} disabled={editing} onChange={e => setDraft({ ...draft, name: e.target.value })} required /></label>
      <label>Server<input value={draft.server} onChange={e => setDraft({ ...draft, server: e.target.value })} required /></label>
      <label>Port<input type="number" value={draft.port} onChange={e => setDraft({ ...draft, port: Number(e.target.value) })} required /></label>
      <label>Tunnel interface<input value={draft.interface} onChange={e => setDraft({ ...draft, interface: e.target.value })} required /></label>
      <label>Authentication<select value={draft.auth_type} onChange={e => setDraft({ ...draft, auth_type: e.target.value as Upstream["auth_type"] })}><option value="password">Password</option><option value="cert">PEM certificate + key</option></select></label>
      <label>Upstream transport<select value={draft.transport ?? "tcp"} onChange={e => setDraft({ ...draft, transport: e.target.value })}><option value="tcp">TCP</option><option value="auto">Auto</option></select></label>
      {draft.auth_type === "password" ? <><label>Username<input autoComplete="off" value={draft.username ?? ""} onChange={e => setDraft({ ...draft, username: e.target.value })} /></label><label>Password<input type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} /></label></> : <><label>Certificate PEM<textarea value={draft.cert_pem ?? ""} onChange={e => setDraft({ ...draft, cert_pem: e.target.value })} /></label><label>New private key PEM<textarea autoComplete="off" value={key} onChange={e => setKey(e.target.value)} /></label></>}
      <label>Server certificate pin<input value={draft.server_cert_pin ?? ""} onChange={e => setDraft({ ...draft, server_cert_pin: e.target.value || undefined })} /></label>
      <label>Health check host<input value={draft.check_host ?? ""} onChange={e => setDraft({ ...draft, check_host: e.target.value || undefined })} /></label>
      <label>DNS addresses<textarea value={(draft.dns ?? []).join("\n")} onChange={e => setDraft({ ...draft, dns: lines(e.target.value) })} /></label>
      <label>Upstream camouflage secret<input type="password" autoComplete="new-password" value={camouflage} disabled={clearCamouflage} onChange={e => setCamouflage(e.target.value)} /></label>
      <label className="agent-check"><input type="checkbox" checked={clearCamouflage} onChange={e => setClearCamouflage(e.target.checked)} /> Clear upstream camouflage</label>
      <label className="agent-check"><input type="checkbox" checked={draft.enabled ?? true} onChange={e => setDraft({ ...draft, enabled: e.target.checked })} /> Enabled upstream</label>
    </fieldset><div className="panel-footer"><button className="action-button" type="button" onClick={() => load(empty, false)}>New upstream</button><button className="action-button primary" disabled={busy} data-capability="agent.upstream.set">Save upstream</button></div></form>
  </section>;
}

export function AccessUserEditor({ users, busy, mutate }: { users: AccessUser[]; busy: boolean; mutate: Mutate }) {
  const [username, setUsername] = useState(""); const [password, setPassword] = useState("");
  const [groups, setGroups] = useState(""); const [enabled, setEnabled] = useState(true); const [editing, setEditing] = useState(false);
  return <section className="panel"><h2>Access users</h2><p role="status">Users reach the agent as password hashes in its signed bundle and keep working while the hub is unreachable. Configure the access listener first.</p>
    <ul className="agent-items" data-capability="agent.user.list">{users.map(u => <li key={u.username}><span>{u.username} · {u.enabled ? "enabled" : "disabled"} · {u.groups.join(", ")}</span><div className="row-actions"><button className="action-button" type="button" onClick={() => { setUsername(u.username); setGroups(u.groups.join(", ")); setEnabled(u.enabled); setEditing(true); setPassword(""); }}>Edit</button><button className="action-button" type="button" disabled={busy} data-capability="agent.user.delete" onClick={() => void mutate(`/users/${encodeURIComponent(u.username)}`, "DELETE", undefined, `Delete registry user ${u.username}?`)}>Delete</button></div></li>)}</ul>
    <form onSubmit={e => { e.preventDefault(); const data: Record<string, unknown> = { groups: lines(groups), enabled }; if (password) data.password = password; void mutate(`/users/${encodeURIComponent(username)}`, "PUT", data).then(ok => { if (ok) setPassword(""); }); }}>
      <fieldset className="agent-fields" disabled={busy}>
        <label>Access username<input value={username} disabled={editing} onChange={e => setUsername(e.target.value)} required /></label>
        <label>New access password<input type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} required={!editing} /></label>
        <label>Groups (comma-separated)<input value={groups} onChange={e => setGroups(e.target.value)} /></label>
        <label className="agent-check"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} /> User enabled</label>
      </fieldset>
      <div className="panel-footer"><button className="action-button" type="button" onClick={() => { setUsername(""); setPassword(""); setGroups(""); setEnabled(true); setEditing(false); }}>New user</button><button className="action-button primary" disabled={busy} data-capability="agent.user.set">Save access user</button></div>
    </form>
  </section>;
}

export function AccessListenerEditor({ access, busy, mutate }: { access: AccessListener; busy: boolean; mutate: Mutate }) {
  const [hostname, setHostname] = useState(access.hostname ?? ""); const [port, setPort] = useState(String(access.port ?? 443));
  const [udp, setUdp] = useState(access.udp ?? false); const [reissue, setReissue] = useState(false);
  return <section className="panel" data-capability="agent.access.show"><h2>Access listener</h2>
    <p role="status">{access.configured ? `ocserv on ${access.hostname}:${access.port}; server certificate ${access.certificate?.pin ?? ""} valid until ${access.certificate?.not_after ?? "unknown"}.` : "Not configured: the agent runs no VPN server."}</p>
    <form onSubmit={e => { e.preventDefault(); void mutate("/access", "PUT", { hostname, port: Number(port), udp, reissue }).then(ok => { if (ok) setReissue(false); }); }}>
      <fieldset className="agent-fields" disabled={busy}>
        <label>Listener hostname or IP<input value={hostname} onChange={e => setHostname(e.target.value)} required /></label>
        <label>Listener port<input type="number" min={1} max={65535} value={port} onChange={e => setPort(e.target.value)} required /></label>
        <label className="agent-check"><input type="checkbox" checked={udp} onChange={e => setUdp(e.target.checked)} /> Allow DTLS (UDP)</label>
        <label className="agent-check"><input type="checkbox" checked={reissue} onChange={e => setReissue(e.target.checked)} /> Issue a new server certificate</label>
      </fieldset>
      <div className="panel-footer"><button className="action-button primary" disabled={busy} data-capability="agent.access.set">Save access listener</button>
        {access.configured && <button className="action-button" type="button" disabled={busy} data-capability="agent.access.delete" onClick={() => void mutate("/access", "DELETE", undefined, "Remove the access listener? Connected VPN clients of this agent are disconnected.")}>Remove listener</button>}</div>
    </form>
  </section>;
}
