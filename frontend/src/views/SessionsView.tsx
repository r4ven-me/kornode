import { Ban } from "lucide-react";
import type { SessionRates } from "../app/types";
import { LastCommandPanel } from "../components/CommandOutput";
import { Table } from "../components/Table";
import { TrafficValue } from "../components/TrafficValue";
import { IconButton } from "../components/ui";
import { formatDuration, sessionKey } from "../lib/format";
import type { CommandResult, SessionRecord } from "../api";

export function SessionsView({
  sessions,
  sessionRates,
  busy,
  commandOutput,
  onClearCommand,
  onKick
}: {
  sessions: SessionRecord[];
  sessionRates: SessionRates;
  busy: string | null;
  commandOutput: CommandResult | CommandResult[] | null;
  onClearCommand: () => void;
  onKick: (username: string) => void;
}) {
  return (
    <div className="view-stack">
      <section className="panel">
        <Table
          columns={[
            "Username",
            "Internal IP",
            "External IP",
            "Device",
            "Duration",
            "Download",
            "Upload",
            "Actions"
          ]}
          empty="No sessions"
        >
          {sessions.map((session) => {
            const key = sessionKey(session);
            const rates = sessionRates[key];
            return (
              <tr key={key}>
                <td>{session.username || "-"}</td>
                <td>{session.vpn_ip ?? "-"}</td>
                <td>{session.real_ip ?? "-"}</td>
                <td>{session.device ?? "-"}</td>
                <td>{formatDuration(session.duration_seconds)}</td>
                <td>
                  <TrafficValue rate={rates?.download ?? null} value={session.tx} />
                </td>
                <td>
                  <TrafficValue rate={rates?.upload ?? null} value={session.rx} />
                </td>
                <td>
                  <IconButton
                    label="Kick session"
                    icon={Ban}
                    danger
                    busy={busy === `kick-${session.username}`}
                    onClick={() => onKick(session.username)}
                  />
                </td>
              </tr>
            );
          })}
        </Table>
      </section>
      {commandOutput && (
        <LastCommandPanel title="Last session command" result={commandOutput} onClose={onClearCommand} />
      )}
    </div>
  );
}
