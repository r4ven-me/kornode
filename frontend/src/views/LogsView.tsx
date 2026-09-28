import { RefreshCw, Save, ScrollText } from "lucide-react";
import { type FormEvent, useMemo } from "react";
import { Table } from "../components/Table";
import { ActionButton, EmptyState, Pill } from "../components/ui";
import { formatBytes } from "../lib/format";
import { groupLogFiles } from "../lib/logs";
import type { IntervalUnit, LogFile, LogRotationSettings, LogTail } from "../api";

export function LogsView({
  files,
  request,
  live,
  logTail,
  busy,
  rotation,
  onRequestChange,
  onLiveChange,
  onFetch,
  onRotationChange,
  onSaveRotation,
  onRotateNow
}: {
  files: LogFile[];
  request: { name: string; lines: number };
  live: boolean;
  logTail: LogTail | null;
  busy: string | null;
  rotation: LogRotationSettings;
  onRequestChange: (value: { name: string; lines: number }) => void;
  onLiveChange: (value: boolean) => void;
  onFetch: (event: FormEvent<HTMLFormElement>) => void;
  onRotationChange: (value: LogRotationSettings) => void;
  onSaveRotation: () => void;
  onRotateNow: () => void;
}) {
  const families = useMemo(() => groupLogFiles(files), [files]);
  return (
    <div className="view-stack">
      <section className="panel">
        <div className="panel-header">
          <h2>Log files</h2>
        </div>
        <Table columns={["Log", "Size", "History"]} empty="No log files">
          {families.map((family) => (
            <tr key={family.key}>
              <td>
                <button
                  className={`log-family-name${family.current.name === request.name ? " active" : ""}`}
                  onClick={() => onRequestChange({ ...request, name: family.current.name })}
                  title={family.current.name}
                  type="button"
                >
                  {family.key}
                </button>
              </td>
              <td>{formatBytes(family.current.size)}</td>
              <td>
                {family.generations.length ? (
                  <div className="log-generation-list">
                    {family.generations.slice(0, 10).map(({ gen, file }) => (
                      <button
                        className={`log-generation-chip${file.name === request.name ? " active" : ""}`}
                        key={file.name}
                        onClick={() => onRequestChange({ ...request, name: file.name })}
                        title={`${file.name} · ${formatBytes(file.size)}`}
                        type="button"
                      >
                        {gen}
                      </button>
                    ))}
                    {family.generations.length > 10 && (
                      <span className="log-generation-more">
                        +{family.generations.length - 10} more
                      </span>
                    )}
                  </div>
                ) : (
                  <span className="muted-line">—</span>
                )}
              </td>
            </tr>
          ))}
        </Table>
        <form className="inline-form" onSubmit={onFetch}>
          <label>
            <span>Lines</span>
            <input
              min={1}
              max={1000}
              type="number"
              value={request.lines}
              onChange={(event) =>
                onRequestChange({ ...request, lines: Number(event.target.value) })
              }
              required
            />
          </label>
          <label className="switch" title="Refresh the selected log automatically">
            <input
              checked={live}
              onChange={(event) => onLiveChange(event.target.checked)}
              type="checkbox"
            />
            <span>Live</span>
          </label>
          <button className="primary-button" disabled={busy === "fetch-log"} type="submit">
            <ScrollText size={18} aria-hidden="true" />
            <span>Load</span>
          </button>
        </form>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Log rotation</h2>
          <Pill kind={rotation.enabled ? "ok" : "muted"}>
            {rotation.enabled ? "Enabled" : "Disabled"}
          </Pill>
        </div>
        <div className="settings-grid">
          <label className="switch" title="Rotate logs automatically by size and/or age">
            <input
              checked={rotation.enabled}
              onChange={(event) =>
                onRotationChange({ ...rotation, enabled: event.target.checked })
              }
              type="checkbox"
            />
            <span>Enabled</span>
          </label>
          <label
            className="compact-field"
            title="Rotate a log once it grows past this size; 0 disables the size trigger"
          >
            <span>Max size</span>
            <input
              min={0}
              disabled={!rotation.enabled}
              onChange={(event) =>
                onRotationChange({
                  ...rotation,
                  max_size_mb: Math.max(0, Number(event.target.value) || 0)
                })
              }
              type="number"
              value={rotation.max_size_mb}
            />
            <span>MB</span>
          </label>
          <label
            className="compact-field"
            title="Also rotate after this much time since the last rotation; 0 disables the time trigger"
          >
            <span>Every</span>
            <input
              min={0}
              disabled={!rotation.enabled}
              onChange={(event) =>
                onRotationChange({
                  ...rotation,
                  max_age: Math.max(0, Number(event.target.value) || 0)
                })
              }
              type="number"
              value={rotation.max_age}
            />
            <select
              disabled={!rotation.enabled}
              onChange={(event) =>
                onRotationChange({
                  ...rotation,
                  max_age_unit: event.target.value as IntervalUnit
                })
              }
              value={rotation.max_age_unit}
            >
              <option value="hours">hours</option>
              <option value="days">days</option>
              <option value="weeks">weeks</option>
              <option value="months">months</option>
            </select>
          </label>
          <label
            className="compact-field"
            title="Rotated copies kept per log (name.1 ... name.N); older copies are deleted"
          >
            <span>Keep</span>
            <input
              min={1}
              max={100}
              disabled={!rotation.enabled}
              onChange={(event) =>
                onRotationChange({
                  ...rotation,
                  keep_files: Math.min(100, Math.max(1, Number(event.target.value) || 1))
                })
              }
              type="number"
              value={rotation.keep_files}
            />
            <span>files</span>
          </label>
        </div>
        <div className="panel-footer">
          <ActionButton
            label="Rotate now"
            icon={RefreshCw}
            title="Rotate every non-empty log immediately, regardless of thresholds"
            busy={busy === "log-rotation-run"}
            onClick={onRotateNow}
          />
          <ActionButton
            label="Save"
            icon={Save}
            primary
            title="Save log rotation settings to persistent YAML"
            busy={busy === "log-rotation-save"}
            onClick={onSaveRotation}
          />
        </div>
      </section>
      <section className="panel">
        <h2>{logTail ? logTail.name : "Log"}</h2>
        {logTail?.content ? <pre>{logTail.content}</pre> : <EmptyState text="No log content" />}
      </section>
    </div>
  );
}
