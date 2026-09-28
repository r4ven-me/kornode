import { Eraser, FileSliders, Plus, Trash2, Users } from "lucide-react";
import type { CommandOutput } from "../../app/types";
import { LastCommandPanel } from "../../components/CommandOutput";
import { Table } from "../../components/Table";
import { IconButton, Pill } from "../../components/ui";
import type { GroupConfigRecord, UserRecord } from "../../api";

export function GroupsView({
  groups,
  users,
  name,
  busy,
  commandOutput,
  onClearCommand,
  onNameChange,
  onCreate,
  onOpenConfig,
  onDeleteConfig,
  onDeleteGroup,
  onOpenMembers
}: {
  groups: GroupConfigRecord[];
  users: UserRecord[];
  name: string;
  busy: string | null;
  commandOutput: CommandOutput;
  onClearCommand: () => void;
  onNameChange: (value: string) => void;
  onCreate: () => void;
  onOpenConfig: (name: string) => void;
  onDeleteConfig: (name: string) => void;
  onDeleteGroup: (name: string) => void;
  onOpenMembers: (name: string) => void;
}) {
  return (
    <div className="view-stack">
      <section className="panel user-create-panel">
        <div className="inline-form group-create-form">
          <label>
            <span>Group name</span>
            <input
              value={name}
              onChange={(event) => onNameChange(event.target.value)}
              placeholder="devops"
            />
          </label>
          <button className="primary-button" type="button" onClick={onCreate}>
            <Plus size={18} aria-hidden="true" />
            <span>Create config</span>
          </button>
        </div>
      </section>
      <section className="panel">
        <Table columns={["Group", "Members", "Config", "Actions"]} empty="No groups">
          {groups.map((group) => (
            <tr key={group.name}>
              <td className="strong-cell">{group.name}</td>
              <td>
                {users.filter((user) => (user.groups ?? []).includes(group.name)).length}
              </td>
              <td>
                <Pill kind={group.has_settings ? "ok" : "muted"}>
                  {group.has_settings ? "Configured" : "Empty"}
                </Pill>
              </td>
              <td>
                <div className="inline-tools">
                  <IconButton
                    label="Members"
                    icon={Users}
                    busy={busy === `group-members-load-${group.name}`}
                    onClick={() => onOpenMembers(group.name)}
                  />
                  <IconButton
                    label="Group config"
                    icon={FileSliders}
                    busy={busy === `group-config-load-${group.name}`}
                    onClick={() => onOpenConfig(group.name)}
                  />
                  <IconButton
                    label="Clear group config"
                    icon={Eraser}
                    disabled={!group.config_exists}
                    busy={busy === `group-config-delete-${group.name}`}
                    onClick={() => onDeleteConfig(group.name)}
                  />
                  <IconButton
                    label="Delete group"
                    icon={Trash2}
                    danger
                    busy={busy === `group-delete-${group.name}`}
                    onClick={() => onDeleteGroup(group.name)}
                  />
                </div>
              </td>
            </tr>
          ))}
        </Table>
      </section>
      {commandOutput && (
        <LastCommandPanel title="Last group command" result={commandOutput} onClose={onClearCommand} />
      )}
    </div>
  );
}
