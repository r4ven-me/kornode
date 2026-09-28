import { Save, Trash2, Users, X } from "lucide-react";
import type { UserGroupsModalState } from "../../app/types";
import { ActionButton, IconButton, Pill } from "../../components/ui";
import type { GroupConfigRecord } from "../../api";

export function UserGroupsDialog({
  state,
  availableGroups,
  busy,
  onChange,
  onClose,
  onCreateGroup,
  onSave
}: {
  state: UserGroupsModalState;
  availableGroups: GroupConfigRecord[];
  busy: string | null;
  onChange: (groups: string[]) => void;
  onClose: () => void;
  onCreateGroup: () => void;
  onSave: () => void;
}) {
  if (!state) {
    return null;
  }
  const selected = new Set(state.groups);
  const saving = busy === `user-groups-${state.username}`;
  const toggle = (group: string) => {
    const next = selected.has(group)
      ? state.groups.filter((item) => item !== group)
      : [...state.groups, group];
    onChange(next);
  };
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel group-dialog" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>{state.username} groups</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        {availableGroups.length === 0 ? (
          <div className="empty-state group-empty-state">
            <p>No groups yet.</p>
            <ActionButton label="Open Groups" icon={Users} onClick={onCreateGroup} />
          </div>
        ) : (
          <div className="group-choice-list">
            {availableGroups.map((group) => (
              <label className="group-choice" key={group.name}>
                <input
                  checked={selected.has(group.name)}
                  onChange={() => toggle(group.name)}
                  type="checkbox"
                />
                <span>{group.name}</span>
                <Pill kind={group.has_settings ? "ok" : "muted"}>
                  {group.has_settings ? "Configured" : "Empty"}
                </Pill>
              </label>
            ))}
          </div>
        )}
        <div className="modal-actions">
          <ActionButton label="Clear" icon={Trash2} danger onClick={() => onChange([])} />
          <button
            className="primary-button"
            disabled={saving || availableGroups.length === 0}
            onClick={onSave}
            type="button"
          >
            <Save size={18} aria-hidden="true" />
            <span>{saving ? "Working" : "Save"}</span>
          </button>
        </div>
      </section>
    </div>
  );
}
