import { useState } from "react";
import { ArrowDown, ArrowUp, GripVertical, Trash2 } from "lucide-react";
import type { JsonObject, Rule } from "../../agentsApi";
import { DestinationFields } from "./DestinationSets";
import type { NetExplainResult } from "../../api";
import "./egress.css";

export type DeadRule = { rule: number; shadowed_by: number };
export type ExplainState = { result: NetExplainResult; src: string; dst: string } | null;

type ToKind = "any" | "fabric" | "set" | "node" | "inline";
type ViaKind = "local" | "fabric" | "drop" | "node" | "upstream";

const TO_KINDS: ToKind[] = ["any", "fabric", "set", "node", "inline"];
const VIA_KINDS: ViaKind[] = ["local", "fabric", "drop", "node", "upstream"];
const ROUTE = /^[0-9a-fA-F:.]+(\/\d+)?$/;

export const NEW_RULE: Rule = { from: ["clients"], to: "any", via: "local" };

function toParts(to: unknown): { kind: ToKind; value: string } {
  if (to === "any" || to === "fabric") return { kind: to, value: "" };
  const item = (to ?? {}) as { set?: string; node?: number; routes?: string[]; domains?: string[] };
  if (item.set !== undefined) return { kind: "set", value: item.set };
  if (item.node !== undefined) return { kind: "node", value: String(item.node) };
  return { kind: "inline", value: [...(item.routes ?? []), ...(item.domains ?? [])].join(", ") };
}

function toValue(kind: ToKind, value: string): unknown {
  if (kind === "any" || kind === "fabric") return kind;
  if (kind === "set") return { set: value };
  if (kind === "node") return { node: Number(value) };
  const items = value.split(/[\s,]+/).filter(Boolean);
  const routes = items.filter(item => ROUTE.test(item));
  const domains = items.filter(item => !ROUTE.test(item));
  return { ...(routes.length ? { routes } : {}), ...(domains.length ? { domains } : {}) };
}

function viaParts(via: string): { kind: ViaKind; target: string } {
  const [raw, ...rest] = via.split(":");
  // `exit:<n>` is the spelling before D-84.
  const kind = raw === "exit" ? "node" : raw;
  return { kind: (VIA_KINDS as string[]).includes(kind) ? (kind as ViaKind) : "local", target: rest.join(":") };
}

const viaValue = (kind: ViaKind, target: string) => (kind === "node" || kind === "upstream" ? `${kind}:${target}` : kind);

export function moveRule(rules: Rule[], from: number, to: number): Rule[] {
  if (from === to || from < 0 || to < 0 || from >= rules.length || to >= rules.length) return rules;
  const next = [...rules];
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item);
  return next;
}

type Props = {
  rules: Rule[];
  disabled: boolean;
  classes: string[];
  deadRules: DeadRule[];
  explain: ExplainState;
  onChange: (rules: Rule[]) => void;
};

/** Ordered egress rules: first match wins, so order is the policy. Rows can be dragged or moved with the buttons. */
export function EgressRules({ rules, disabled, classes, deadRules, explain, onChange }: Props) {
  const [dragging, setDragging] = useState<number | null>(null);
  const update = (index: number, patch: Partial<Rule>) => onChange(rules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));
  const matched = explain?.result.matched_rule ? Number(explain.result.matched_rule.index) : null;
  return <ol className="egress-rules">
    {rules.map((rule, index) => {
      const dead = deadRules.find(item => item.rule === index);
      const to = toParts(rule.to);
      const via = viaParts(rule.via);
      const label = (name: string) => `Rule ${index + 1} ${name}`;
      return <li key={index} draggable={!disabled} className={`egress-rule${dead ? " dead" : ""}${matched === index ? " matched" : ""}`}
        data-testid={`egress-rule-${index}`}
        onDragStart={event => { setDragging(index); event.dataTransfer?.setData("text/plain", String(index)); }}
        onDragOver={event => event.preventDefault()}
        onDrop={event => { event.preventDefault(); if (dragging !== null) onChange(moveRule(rules, dragging, index)); setDragging(null); }}
        onDragEnd={() => setDragging(null)}>
        <div className="egress-rule-head">
          <GripVertical size={16} aria-hidden />
          <strong>#{index + 1}</strong>
          <input aria-label={label("id")} placeholder="id (optional)" value={rule.id ?? ""} onChange={e => update(index, { id: e.target.value || undefined })} />
          <span className="egress-rule-actions">
            <button type="button" className="icon-button" aria-label={`Move rule ${index + 1} up`} disabled={disabled || index === 0} onClick={() => onChange(moveRule(rules, index, index - 1))}><ArrowUp size={14} /></button>
            <button type="button" className="icon-button" aria-label={`Move rule ${index + 1} down`} disabled={disabled || index === rules.length - 1} onClick={() => onChange(moveRule(rules, index, index + 1))}><ArrowDown size={14} /></button>
            <button type="button" className="icon-button" aria-label={`Remove rule ${index + 1}`} disabled={disabled} onClick={() => onChange(rules.filter((_, i) => i !== index))}><Trash2 size={14} /></button>
          </span>
        </div>
        <div className="egress-rule-fields">
          <label>From<input list="egress-classes" aria-label={label("from")} value={rule.from.join(", ")} onChange={e => update(index, { from: e.target.value.split(/[\s,]+/).filter(Boolean) })} /></label>
          <label>To
            <span className="egress-pair">
              <select aria-label={label("to kind")} value={to.kind} onChange={e => update(index, { to: toValue(e.target.value as ToKind, "") })}>{TO_KINDS.map(k => <option key={k}>{k}</option>)}</select>
              {(to.kind === "set" || to.kind === "node") &&
                <input aria-label={label("to value")} placeholder={to.kind === "node" ? "node id" : "set name"} value={to.value} onChange={e => update(index, { to: toValue(to.kind, e.target.value) })} />}
            </span>
          </label>
          {to.kind === "inline" && <div className="egress-wide"><DestinationFields value={rule.to as JsonObject} label={`Rule ${index + 1} destination`} disabled={disabled} onChange={value => update(index, { to: value })} /></div>}
          <label>Via
            <span className="egress-pair">
              <select aria-label={label("via kind")} value={via.kind} onChange={e => update(index, { via: viaValue(e.target.value as ViaKind, via.target) })}>{VIA_KINDS.map(k => <option key={k}>{k}</option>)}</select>
              {(via.kind === "node" || via.kind === "upstream") &&
                <input aria-label={label("via target")} placeholder={via.kind === "node" ? "gateway node id" : "profile"} value={via.target} onChange={e => update(index, { via: viaValue(via.kind, e.target.value) })} />}
            </span>
          </label>
          <label>Kill switch
            <select aria-label={label("kill switch")} value={rule.kill_switch === undefined ? "default" : rule.kill_switch ? "on" : "off"}
              onChange={e => update(index, { kill_switch: e.target.value === "default" ? undefined : e.target.value === "on" })}>
              <option value="default">default</option><option value="on">on</option><option value="off">off</option>
            </select>
          </label>
          <label className="egress-wide">Description<input aria-label={label("description")} value={rule.description ?? ""} maxLength={200} onChange={e => update(index, { description: e.target.value || undefined })} /></label>
        </div>
        {dead && <p className="egress-dead" role="note">Dead rule: fully covered by rule #{dead.shadowed_by + 1}, it never matches.</p>}
        {matched === index && explain && <ExplainNote explain={explain} />}
      </li>;
    })}
    <datalist id="egress-classes">{classes.map(c => <option key={c} value={c} />)}</datalist>
  </ol>;
}

function ExplainNote({ explain }: { explain: NonNullable<ExplainState> }) {
  const { result } = explain;
  const parts = [`from class ${result.from_class}`, result.route && `route ${result.route}`, result.table !== null && `table ${result.table}`, result.nat && `NAT ${result.nat}`, result.mark && `mark ${result.mark}`];
  return <p className="egress-explain" role="status">{explain.src} → {explain.dst} matches here: {parts.filter(Boolean).join(" · ")}</p>;
}
