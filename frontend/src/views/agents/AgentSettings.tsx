import { useEffect, useState } from "react";
import type { Agent, Mutate } from "../../agentsApi";
import { AGENT_ROLES, ROLE_HINTS } from "./roles";

export function AgentSettings({ agent, busy, mutate }: { agent: Agent; busy: boolean; mutate: Mutate }) {
  const [description, setDescription] = useState(agent.description);
  const [roles, setRoles] = useState(agent.roles);
  const [transport, setTransport] = useState(agent.transport.transport ?? "tcp");
  const [dpd, setDpd] = useState(agent.transport.dpd ?? 20);
  const [keepalive, setKeepalive] = useState(agent.transport.keepalive ?? 25);
  const [camouflage, setCamouflage] = useState("");
  const [clearSecret, setClearSecret] = useState(false);
  useEffect(() => {
    setDescription(agent.description); setRoles(agent.roles);
    setTransport(agent.transport.transport ?? "tcp");
    setDpd(agent.transport.dpd ?? 20); setKeepalive(agent.transport.keepalive ?? 25);
    setCamouflage(""); setClearSecret(false);
  }, [agent]);
  return <section className="panel" data-capability="agent.show">
    <div className="panel-header"><h2>{agent.name} · node {agent.id}</h2><span className="pill muted">{agent.state} · {agent.online ? "online" : "offline"}</span></div>
    <p>Desired {agent.desired_version} / reported {agent.applied_version}. Last seen: {agent.last_seen ?? "never"}. Certificate: {agent.cert_not_after ?? "not enrolled"}.</p>
    <p className="field-help">Access agents serve VPN clients; gateway agents can provide an internet exit for other nodes.</p>
    <form onSubmit={event => {
      event.preventDefault();
      const tuning: Record<string, unknown> = { transport, dpd, keepalive };
      if (clearSecret) tuning.camouflage = null;
      else if (camouflage) tuning.camouflage = camouflage;
      void mutate("", "PATCH", { description, roles, transport: tuning });
    }}>
      <fieldset className="agent-fields" disabled={busy || agent.state === "revoked"}>
        <label>Description<textarea value={description} onChange={e => setDescription(e.target.value)} /></label>
        <div className="agent-checks">{AGENT_ROLES.map(role => <label key={role} title={ROLE_HINTS[role]}><input type="checkbox" checked={roles.includes(role)} onChange={e => setRoles(e.target.checked ? [...roles, role] : roles.filter(r => r !== role))} /> {role} role</label>)}<p className="field-help agent-roles-help">access: serves its own VPN clients. gateway: other nodes may leave to the internet through it (<code>via node:&lt;id&gt;</code>).</p></div>
        <label>Transport<select value={transport} onChange={e => setTransport(e.target.value)}><option value="tcp">TCP only</option><option value="auto">Auto (DTLS when available)</option></select></label>
        <label>DPD (seconds)<input type="number" value={dpd} onChange={e => setDpd(Number(e.target.value))} /></label>
        <label>Keepalive (seconds)<input type="number" value={keepalive} onChange={e => setKeepalive(Number(e.target.value))} /></label>
        <label>New camouflage secret<input type="password" autoComplete="new-password" value={camouflage} disabled={clearSecret} onChange={e => setCamouflage(e.target.value)} /><small>Leave empty to keep. Currently {agent.transport.camouflage_set ? "configured" : "not configured"}.</small></label>
        <label className="agent-check"><input type="checkbox" checked={clearSecret} onChange={e => setClearSecret(e.target.checked)} /> Clear camouflage secret</label>
      </fieldset>
      <div className="panel-footer"><button className="action-button primary" disabled={busy || agent.state === "revoked"} data-capability="agent.update">Save agent settings</button></div>
    </form>
    <div className="panel-footer">
      <button className="action-button" type="button" disabled={busy || agent.state !== "pending"} data-capability="agent.token" onClick={() => void mutate("/token", "POST", {})}>Issue enrollment token</button>
      <button className="action-button" type="button" disabled={busy || agent.state !== "pending"} data-capability="agent.token.revoke" onClick={() => void mutate("/token", "DELETE", undefined, `Revoke the pending enrollment token for ${agent.name}?`)}>Revoke token</button>
      <button type="button" className="action-button danger" disabled={busy} data-capability="agent.revoke" onClick={() => void mutate("/revoke", "POST", {}, `Revoke ${agent.name} and disconnect its VPN session?`)}>Revoke agent</button>
      <button type="button" className="action-button danger" disabled={busy} data-capability="agent.delete" onClick={() => void mutate("", "DELETE", {}, `Revoke and delete ${agent.name}? Its ID will be quarantined for 30 days.`)}>Delete agent</button>
    </div>
  </section>;
}
