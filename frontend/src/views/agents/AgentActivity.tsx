import { useState } from "react";
import type { AgentCommand, BundleVersion, JsonObject, Mutate } from "../../agentsApi";

export function AgentActivity({ reports, commands, bundles, busy, mutate, read, download, name }: {
  reports: JsonObject[]; commands: AgentCommand[]; bundles: BundleVersion[]; busy: boolean;
  mutate: Mutate; read: (suffix: string) => Promise<JsonObject | null>;
  download: (id: string) => Promise<void>; name: string;
}) {
  const [kind, setKind] = useState("reconnect"); const [tunnel, setTunnel] = useState("interlink");
  const [src, setSrc] = useState("host"), [dst, setDst] = useState("");
  const [proto, setProto] = useState("tcp"), [port, setPort] = useState("");
  const [rollback, setRollback] = useState("");
  const [first, setFirst] = useState(""), [second, setSecond] = useState("");
  const [preview, setPreview] = useState<unknown>(null);
  return <>
    <section className="panel" data-capability="agent.reports"><h2>Latest report</h2><p className="field-help">Reported state, not an active connectivity probe. Reports update while this section is open.</p>{reports.length ? <pre className="agent-code">{JSON.stringify(reports[0], null, 2)}</pre> : <p>No report received yet.</p>}</section>
    <section className="panel"><h2>Remote commands</h2><p className="field-help">Commands expire after 10 minutes undelivered. Queued/delivered does not mean completed.</p>
      <form onSubmit={e => {
        e.preventDefault(); const args: JsonObject = {};
        if (kind === "reconnect" && tunnel) args.tunnel = tunnel;
        if (kind === "explain") { args.src = src; args.dst = dst; args.proto = proto; if (port) args.port = Number(port); }
        if (kind === "rollback") args.to_version = Number(rollback);
        const confirmation = ["reconnect", "restart", "rollback"].includes(kind) ? `Queue ${kind} for ${name}? This may interrupt its traffic.` : undefined;
        void mutate("/commands", "POST", { type: kind, args }, confirmation);
      }}><fieldset className="agent-fields" disabled={busy}>
        <label>Command<select value={kind} onChange={e => setKind(e.target.value)}><option value="reconnect">Reconnect tunnel</option><option value="explain">Explain route</option><option value="collect_diag">Collect diagnostics</option><option value="restart">Restart agent process</option><option value="rollback">Rollback bundle</option></select></label>
        {kind === "reconnect" && <label>Tunnel (blank = all)<input value={tunnel} onChange={e => setTunnel(e.target.value)} /></label>}
        {kind === "explain" && <><label>Source IP or host<input value={src} onChange={e => setSrc(e.target.value)} required /></label><label>Destination IP<input value={dst} onChange={e => setDst(e.target.value)} required /></label><label>Protocol<select value={proto} onChange={e => setProto(e.target.value)}><option>tcp</option><option>udp</option><option>icmp</option><option>icmpv6</option></select></label><label>Destination port<input type="number" value={port} onChange={e => setPort(e.target.value)} /></label></>}
        {kind === "rollback" && <label>Confirmed cached version<input type="number" value={rollback} onChange={e => setRollback(e.target.value)} required /></label>}
      </fieldset><div className="panel-footer"><button className="action-button primary" disabled={busy} data-capability="agent.command.enqueue">Queue command</button></div></form>
      <ul className="agent-items" data-capability="agent.command.list">{commands.map(command => <li key={command.id}><span>{command.type} · {command.state}<small>{command.created_at}</small></span><div className="row-actions"><button className="action-button" type="button" data-capability="agent.command.result" onClick={() => void read(`/commands/${encodeURIComponent(command.id)}`).then(value => value && setPreview(value))}>Result</button>{command.result?.artefact_available && <button className="action-button" type="button" disabled={busy} data-capability="agent.command.artifact" onClick={() => void download(command.id)}>Download diagnostic archive</button>}</div></li>)}</ul>
      {!commands.length && <p>No commands queued.</p>}
    </section>
    <section className="panel"><h2>Bundle history</h2><ul className="agent-items" data-capability="agent.bundle.list">{bundles.map(bundle => <li key={bundle.version}><span>v{bundle.version} · {bundle.reason}<small>{bundle.created_at} · signer {bundle.key_id}</small></span><button className="action-button" type="button" data-capability="agent.bundle.show" onClick={() => void read(`/bundles/${bundle.version}`).then(value => value && setPreview(value))}>Show redacted bundle</button></li>)}</ul>
      {!bundles.length && <p>No compiled bundles yet.</p>}
      <form onSubmit={e => { e.preventDefault(); void read(`/bundles/diff?a=${encodeURIComponent(first)}&b=${encodeURIComponent(second)}`).then(value => value && setPreview(value)); }}>
        <fieldset className="agent-fields" disabled={busy || bundles.length < 2}><label>From version<select value={first} onChange={e => setFirst(e.target.value)} required><option value="">Choose version</option>{bundles.map(b => <option value={b.version} key={b.version}>{b.version}</option>)}</select></label><label>To version<select value={second} onChange={e => setSecond(e.target.value)} required><option value="">Choose version</option>{bundles.map(b => <option value={b.version} key={b.version}>{b.version}</option>)}</select></label></fieldset>
        <div className="panel-footer"><button className="action-button" disabled={busy || bundles.length < 2} data-capability="agent.bundle.diff">Compare redacted bundles</button></div>
      </form>
    </section>
    {preview !== null && <section className="panel"><div className="panel-header"><h2>Read-only result</h2><button className="action-button" type="button" onClick={() => setPreview(null)}>Close result</button></div><pre className="agent-code">{JSON.stringify(preview, null, 2)}</pre></section>}
  </>;
}
