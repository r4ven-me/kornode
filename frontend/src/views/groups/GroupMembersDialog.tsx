import { Save, Trash2, X } from "lucide-react";
import type { GroupMembersModalState } from "../../app/types";
import { ActionButton, EmptyState, IconButton, Pill } from "../../components/ui";
import type { UserRecord } from "../../api";

export function GroupMembersDialog({
  state,
  users,
  busy,
  onChange,
  onClose,
  onSave
}: {
  state: GroupMembersModalState;
  users: UserRecord[];
  busy: string | null;
  onChange: (users: string[]) => void;
  onClose: () => void;
  onSave: () => void;
}) {
  if (!state) {
    return null;
  }
  const selected = new Set(state.users);
  const saving = busy === `group-members-${state.name}`;
  const toggle = (username: string) => {
    const next = selected.has(username)
      ? state.users.filter((item) => item !== username)
      : [...state.users, username];
    onChange(next);
  };
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal-panel group-dialog" role="dialog" aria-modal="true">
        <div className="panel-header">
          <h2>{state.name} members</h2>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        {users.length === 0 ? (
          <EmptyState text="No users" />
        ) : (
          <div className="group-choice-list">
            {users.map((user) => (
              <label className="group-choice" key={user.username}>
                <input
                  checked={selected.has(user.username)}
                  onChange={() => toggle(user.username)}
                  type="checkbox"
                />
                <span>{user.username}</span>
                <Pill kind={user.disabled ? "muted" : "ok"}>
                  {user.disabled ? "Disabled" : "Enabled"}
                </Pill>
              </label>
            ))}
          </div>
        )}
        <div className="modal-actions">
          <ActionButton label="Clear" icon={Trash2} danger onClick={() => onChange([])} />
          <button
            className="primary-button"
            disabled={saving || users.length === 0}
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
