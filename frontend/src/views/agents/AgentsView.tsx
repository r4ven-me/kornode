import { useEffect, useRef, useState } from "react";
import "./agents.css";
import { agentGet, agentPath, agentWrite, downloadAgentArtifact, loadAgent, type Agent, type ControlStatus, type Detail, type JsonObject, type Mutate } from "../../agentsApi";
import { AgentActivity } from "./AgentActivity";
import { AgentPolicy } from "./AgentPolicy";
import { AccessListenerEditor, AccessUserEditor, PrefixEditor, SourceEditor, UpstreamEditor } from "./AgentResources";
import { AgentSettings } from "./AgentSettings";

type Section = "settings" | "networks" | "policy" | "upstreams" | "users" | "activity";

export function EnrollmentDialog({ token, onClose }: { token: string; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [copied, setCopied] = useState(false);
  const [revealed, setRevealed] = useState(false);
  async function copy() {
    // navigator.clipboard is undefined on plain HTTP: fall back to showing the token.
    try {
      if (!navigator.clipboard) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(token);
      setCopied(true);
    } catch { setCopied(false); setRevealed(true); }
  }
  useEffect(() => {
    if (typeof dialog.current?.showModal === "function") dialog.current.showModal();
    else dialog.current?.setAttribute("open", "");
  }, []);
  return <dialog ref={dialog} className="agent-enrollment modal-panel" onCancel={onClose} onClose={onClose} aria-labelledby="agent-enrollment-title">
    <h2 id="agent-enrollment-title">One-time enrollment token</h2>
    <p>Copy now. It is not stored in browser storage or shown in agent lists. Re-issuing invalidates the previous token.</p>
    <label>Enrollment token<input type={revealed ? "text" : "password"} readOnly value={token} autoComplete="off" onFocus={e => revealed && e.currentTarget.select()} /></label>
    <div className="panel-footer"><button className="action-button" type="button" onClick={() => void copy()}>Copy token</button><button className="action-button" type="button" onClick={() => setRevealed(v => !v)}>{revealed ? "Hide token" : "Show token"}</button><button className="action-button" type="button" autoFocus onClick={onClose}>Close and forget token</button></div>
    <p role="status">{copied ? "Token copied. Treat your clipboard as sensitive." : revealed ? "Copy is unavailable here (needs HTTPS): select the token above and copy it manually." : ""}</p>
  </dialog>;
}

export function AgentsView({ token, dryRun = false }: { token: string | null; dryRun?: boolean }) {
  const [agents, setAgents] = useState<Agent[]>([]); const [control, setControl] = useState<ControlStatus | null>(null);
  const [selected, setSelected] = useState<string | null>(null), [detail, setDetail] = useState<Detail | null>(null);
  const selectedRef = useRef(selected); selectedRef.current = selected;
  const [section, setSection] = useState<Section>("settings");
  const [busy, setBusy] = useState(false), [loading, setLoading] = useState(true);
  const [error, setError] = useState(""), [message, setMessage] = useState("");
  const [enrollment, setEnrollment] = useState<string | null>(null);
  const [name, setName] = useState(""), [id, setId] = useState(""), [description, setDescription] = useState("");
  const [roles, setRoles] = useState<string[]>([]), [forceReuse, setForceReuse] = useState(false);

  async function refreshList() {
    const [list, status] = await Promise.all([agentGet<{ agents: Agent[] }>("/api/agents", token), agentGet<ControlStatus>("/api/control", token)]);
    setAgents(list.agents); setControl(status);
  }
  async function refreshDetail(name: string) {
    const next = await loadAgent(name, token);
    if (selectedRef.current === name) setDetail(next);
  }
  useEffect(() => {
    let active = true;
    Promise.all([agentGet<{ agents: Agent[] }>("/api/agents", token), agentGet<ControlStatus>("/api/control", token)])
      .then(([list, status]) => { if (active) { setAgents(list.agents); setControl(status); } })
      .catch(reason => { if (active) setError(String(reason instanceof Error ? reason.message : reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [token]);
  useEffect(() => {
    let active = true; setDetail(null); setError("");
    if (selected) void loadAgent(selected, token).then(next => { if (active) setDetail(next); }).catch(reason => { if (active) setError(String(reason instanceof Error ? reason.message : reason)); });
    return () => { active = false; };
  }, [selected, token]);
  useEffect(() => {
    let active = true, inFlight = false;
    const timer = setInterval(() => {
      if (inFlight) return;
      inFlight = true;
      const current = selected;
      void Promise.all([
        agentGet<{ agents: Agent[] }>("/api/agents", token), agentGet<ControlStatus>("/api/control", token),
        current ? agentGet<{ reports: JsonObject[] }>(agentPath(current, "/reports"), token) : Promise.resolve(null),
        current ? agentGet<{ commands: Detail["commands"] }>(agentPath(current, "/commands"), token) : Promise.resolve(null)
      ]).then(([list, status, reports, commands]) => {
        if (!active) return;
        setAgents(list.agents); setControl(status);
        if (current && current === selectedRef.current && reports && commands) setDetail(old => old ? { ...old, reports: reports.reports, commands: commands.commands } : old);
      }).catch(reason => { if (active) setError(String(reason instanceof Error ? reason.message : reason)); })
        .finally(() => { inFlight = false; });
    }, 5000);
    return () => { active = false; clearInterval(timer); };
  }, [selected, token]);

  const mutate: Mutate = async (suffix, method, body, confirmation) => {
    if (!selected) return false;
    if (dryRun && !(suffix === "/revoke" || suffix === "/commands" || suffix === "" && method === "DELETE")) {
      setError("Preview mode: this action has no dry-run. Disable preview to apply it."); return false;
    }
    if (!dryRun && confirmation && !window.confirm(confirmation)) return false;
    setBusy(true); setError(""); setMessage("");
    try {
      const data = await agentWrite(agentPath(selected, suffix), method, dryRun ? { ...(suffix === "/commands" ? body as JsonObject : {}), dry_run: true } : body, token);
      if (typeof data.token === "string") setEnrollment(data.token);
      setMessage(dryRun ? "Preview completed; no mutation applied." : "Management action completed. Agent application is tracked separately by reported version.");
      if (!dryRun && method === "DELETE" && suffix === "") { setSelected(null); setDetail(null); }
      else if (!dryRun) await refreshDetail(selected);
      await refreshList();
      return true;
    } catch (reason) { setError(String(reason instanceof Error ? reason.message : reason)); return false; }
    finally { setBusy(false); }
  };
  async function read(suffix: string): Promise<JsonObject | null> {
    if (!selected) return null;
    try { return await agentGet<JsonObject>(agentPath(selected, suffix), token); }
    catch (reason) { setError(String(reason instanceof Error ? reason.message : reason)); return null; }
  }
  async function rotate() {
    if (!dryRun && !window.confirm("Announce a new bundle signing key and promote it after seven days? Agents offline during the window may require re-enrollment.")) return;
    setBusy(true); setError("");
    try { await agentWrite("/api/control/rotate-signing-key", "POST", { dry_run: dryRun }, token); await refreshList(); setMessage(dryRun ? "Rotation preview only." : "New signing key announced. Existing key remains in use for seven days."); }
    catch (reason) { setError(String(reason instanceof Error ? reason.message : reason)); }
    finally { setBusy(false); }
  }
  const live = agents.find(a => a.name === selected);
  return <div className="view-stack agents-view">
    <section className="panel" data-capability="control.status"><div className="panel-header"><h2>Agents</h2><span className="pill muted">Control API {control?.enabled ? "enabled" : "disabled"}</span></div>
      <p>{control?.agents ?? 0} registered · {control?.active ?? 0} enrolled · signing key {control?.signing_key_id ?? "not initialized"}</p>
      {control?.rotation && <p role="status">Rotation: {control.rotation.phase}; promotion {control.rotation.promotes_at}. {control.rotation.warning}</p>}
      <div className="panel-footer"><button className="action-button" type="button" disabled={busy} data-capability="agent.list" onClick={() => void refreshList().catch(reason => setError(String(reason)))}>Refresh agents</button><button className="action-button" type="button" disabled={busy} data-capability="control.rotate_key" onClick={() => void rotate()}>Rotate signing key{dryRun ? " (preview)" : ""}</button></div>
    </section>
    {error && <section className="panel" role="alert">{error}</section>}{message && <p role="status">{message}</p>}
    <section className="panel"><h2>Registered agents</h2>{loading ? <p>Loading agents…</p> : agents.length === 0 ? <p>No agents registered yet.</p> : <ul className="agent-list">{agents.map(a => <li key={a.id}><button className={selected === a.name ? "agent-summary active" : "agent-summary"} type="button" disabled={busy} aria-pressed={selected === a.name} onClick={() => { setSelected(a.name); setSection("settings"); }}><strong>{a.name} · node {a.id}</strong><span>{a.state} · {a.online ? "online" : "offline"}</span><span>desired {a.desired_version} / reported {a.applied_version}</span></button></li>)}</ul>}</section>
    <details className="panel"><summary>Add agent</summary><form onSubmit={e => {
      e.preventDefault();
      if (forceReuse && !dryRun && !window.confirm(`Force reuse of ID ${id} for ${name}, bypassing its quarantine?`)) return;
      setBusy(true); setError(""); setMessage("");
      void agentWrite("/api/agents", "POST", { name, id: id ? Number(id) : null, description, roles, force_reuse: forceReuse, dry_run: dryRun }, token).then(async data => {
        if (typeof data.token === "string") setEnrollment(data.token);
        if (dryRun) setMessage(`Preview: node ID ${data.id}; no agent created.`);
        else { const created = data.agent as Agent; setSelected(created.name); setSection("settings"); setName(""); setId(""); setDescription(""); setRoles([]); setForceReuse(false); }
        await refreshList();
      }).catch(reason => setError(String(reason instanceof Error ? reason.message : reason))).finally(() => setBusy(false));
    }}><fieldset className="agent-fields" disabled={busy}>
      <label>Agent name<input value={name} onChange={e => setName(e.target.value)} required /></label>
      <label>Node ID (blank = automatic)<input type="number" value={id} onChange={e => setId(e.target.value)} /></label>
      <label>New agent description<input value={description} onChange={e => setDescription(e.target.value)} /></label>
      <div className="agent-checks">{["access", "exit"].map(role => <label key={role}><input type="checkbox" checked={roles.includes(role)} onChange={e => setRoles(e.target.checked ? [...roles, role] : roles.filter(r => r !== role))} /> {role} role</label>)}</div>
      <label className="agent-check"><input type="checkbox" checked={forceReuse} onChange={e => setForceReuse(e.target.checked)} /> Force ID reuse (bypass 30-day quarantine)</label>
    </fieldset><div className="panel-footer"><button className="action-button primary" disabled={busy} data-capability="agent.create">{dryRun ? "Preview creation" : "Create agent and token"}</button></div></form></details>
    {selected && !detail && <p role="status">Loading agent details…</p>}
    {detail && <>
      <label className="agent-section">Agent section<select value={section} onChange={e => setSection(e.target.value as Section)}><option value="settings">Settings and enrollment</option><option value="networks">Networks and sources</option><option value="policy">Egress policy</option><option value="upstreams">Upstreams</option>{detail.agent.roles.includes("access") && <option value="users">Access listener and users</option>}<option value="activity">Reports, bundles and commands</option></select></label>
      {live && <p role="status">{live.online ? "Online" : "Offline"} · last seen {live.last_seen ?? "never"} · desired {live.desired_version} / reported {live.applied_version}</p>}
      <div key={detail.agent.id}>
        {section === "settings" && <AgentSettings agent={detail.agent} busy={busy} mutate={mutate} />}
        <fieldset disabled={detail.agent.state === "revoked"} className="agent-resource-stack">
          {section === "networks" && <><PrefixEditor prefixes={detail.prefixes} busy={busy} mutate={mutate} /><SourceEditor sources={detail.policy.sources ?? []} busy={busy} mutate={mutate} /></>}
          {section === "policy" && <AgentPolicy policy={detail.policy} busy={busy} mutate={mutate} />}
          {section === "upstreams" && <UpstreamEditor upstreams={detail.upstreams} busy={busy} mutate={mutate} />}
          {section === "users" && detail.agent.roles.includes("access") && <><AccessListenerEditor access={detail.access} busy={busy} mutate={mutate} /><AccessUserEditor users={detail.users} busy={busy} mutate={mutate} /></>}
        </fieldset>
        {section === "activity" && <AgentActivity name={detail.agent.name} reports={detail.reports} commands={detail.commands} bundles={detail.bundles} busy={busy} mutate={mutate} read={read} download={async id => { try { await downloadAgentArtifact(detail.agent.name, id, token); } catch (reason) { setError(String(reason instanceof Error ? reason.message : reason)); } }} />}
      </div>
    </>}
    {enrollment && <EnrollmentDialog token={enrollment} onClose={() => setEnrollment(null)} />}
  </div>;
}
