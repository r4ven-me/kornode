import { useState } from "react";
import {
  type CommandResult,
  deleteGroup,
  deleteGroupConfig,
  fetchGroupConfig,
  fetchGroups,
  fetchUsers,
  saveGroupConfig,
  saveUserGroups
} from "../../api";
import { confirmAction } from "../../lib/async";
import { syntheticCommand } from "../../lib/commands";
import { normalizeUserConfigDraft } from "../../lib/userConfig";
import type { PanelCore } from "../core";
import { emptyUserConfig } from "../state";
import type { GroupConfigModalState, GroupMembersModalState } from "../types";

export function useGroups(core: PanelCore) {
  const { authToken, recordCommand, runAction, setNotice, setState, state } = core;
  const [newGroupName, setNewGroupName] = useState("devops");
  const [groupConfigModal, setGroupConfigModal] = useState<GroupConfigModalState>(null);
  const [groupMembersModal, setGroupMembersModal] = useState<GroupMembersModalState>(null);

  const refreshGroups = async (token: string) => {
    const groups = await fetchGroups(token);
    setState((current) => ({ ...current, groups }));
  };

  const createGroup = () => {
    const name = newGroupName.trim();
    if (!name) {
      setNotice({ kind: "error", text: "group name is required" });
      return;
    }
    setGroupConfigModal({ name, draft: { ...emptyUserConfig } });
  };

  const openConfig = async (name: string) => {
    await runAction(
      `group-config-load-${name}`,
      `Loaded config for ${name}`,
      async (token) => {
        const draft = await fetchGroupConfig(token, name);
        setGroupConfigModal({ name, draft: { ...emptyUserConfig, ...draft } });
        return { status: "ok" };
      },
      { reload: false }
    );
  };

  // Returns whether the config was cleared (the dialog closes on success).
  const clearConfig = async (name: string): Promise<boolean> => {
    if (!confirmAction(`Clear config for group ${name}?`)) {
      return false;
    }
    const result = await runAction(
      `group-config-delete-${name}`,
      `Config cleared for ${name}`,
      (token) => deleteGroupConfig(token, name),
      { reload: false }
    );
    recordCommand("groups", result);
    return result !== null;
  };

  const deleteConfig = async (name: string) => {
    if ((await clearConfig(name)) && authToken) {
      await refreshGroups(authToken);
    }
  };

  const deleteDialogConfig = async () => {
    if (!groupConfigModal) {
      return;
    }
    if ((await clearConfig(groupConfigModal.name)) && authToken) {
      setGroupConfigModal(null);
      await refreshGroups(authToken);
    }
  };

  const saveDialogConfig = async () => {
    if (!groupConfigModal) {
      return;
    }
    const { name, draft } = groupConfigModal;
    const result = await runAction(
      `group-config-save-${name}`,
      `Config saved for ${name}`,
      (token) => saveGroupConfig(token, name, normalizeUserConfigDraft(draft)),
      { reload: false }
    );
    recordCommand("groups", result);
    if (result && authToken) {
      setGroupConfigModal(null);
      setNewGroupName(name);
      await refreshGroups(authToken);
    }
  };

  const deleteGroupAction = async (name: string) => {
    if (
      !confirmAction(
        `Delete group ${name}? This removes its config file, its group policy ` +
          "and clears it from every member's group list."
      )
    ) {
      return;
    }
    const result = await runAction(
      `group-delete-${name}`,
      `Group ${name} deleted`,
      (token) => deleteGroup(token, name),
      { reload: false }
    );
    recordCommand("groups", result);
    if (result !== null && authToken) {
      const [groups, users] = await Promise.all([fetchGroups(authToken), fetchUsers(authToken)]);
      setState((current) => ({ ...current, groups, users }));
    }
  };

  const openMembers = async (name: string) => {
    // Fetch fresh rather than trusting the in-memory state.users
    // snapshot: it only ever updates after an action taken through
    // this panel, so membership changed via the CLI, another admin
    // session, or just a stale tab would otherwise show here as
    // wrong until some unrelated reload happened to refresh it.
    await runAction(
      `group-members-load-${name}`,
      `Loaded members for ${name}`,
      async (token) => {
        const users = await fetchUsers(token);
        setState((current) => ({ ...current, users }));
        setGroupMembersModal({
          name,
          users: users
            .filter((user) => (user.groups ?? []).includes(name))
            .map((user) => user.username)
        });
        return { status: "ok" };
      },
      { reload: false }
    );
  };

  const saveMembers = async () => {
    if (!groupMembersModal) {
      return;
    }
    const { name, users } = groupMembersModal;
    const selected = new Set(users);
    const result = await runAction(
      `group-members-${name}`,
      `Members saved for ${name}`,
      async (token) => {
        // Sequential on purpose: each request rewrites the shared
        // passwd file server-side, so parallel updates can race and
        // drop each other's changes.
        const results: CommandResult[] = [];
        for (const user of state.users) {
          const currentGroups = user.groups ?? [];
          const hasGroup = currentGroups.includes(name);
          const shouldHaveGroup = selected.has(user.username);
          if (hasGroup === shouldHaveGroup) {
            continue;
          }
          const nextGroups = shouldHaveGroup
            ? [...currentGroups, name]
            : currentGroups.filter((group) => group !== name);
          results.push(await saveUserGroups(token, user.username, nextGroups));
        }
        return results[0] ?? syntheticCommand(["korctl", "user", "groups"], "unchanged");
      },
      { reload: false }
    );
    recordCommand("groups", result);
    if (result !== null && authToken) {
      const loadedUsers = await fetchUsers(authToken);
      setState((current) => ({ ...current, users: loadedUsers }));
      setGroupMembersModal(null);
    }
  };

  return {
    newGroupName,
    setNewGroupName,
    groupConfigModal,
    setGroupConfigModal,
    groupMembersModal,
    setGroupMembersModal,
    createGroup,
    openConfig,
    deleteConfig,
    deleteDialogConfig,
    saveDialogConfig,
    deleteGroup: deleteGroupAction,
    openMembers,
    saveMembers
  };
}
