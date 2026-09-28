import { type FormEvent, useState } from "react";
import {
  changePassword,
  createCertificate,
  createP12,
  createUser,
  deleteUser,
  deleteUserConfig,
  fetchOtpQr,
  fetchP12,
  fetchUserCert,
  fetchUserConfig,
  fetchUserKey,
  fetchUsers,
  revokeCertificate,
  saveUserConfig,
  saveUserGroups,
  setOtp,
  setUserEnabled
} from "../../api";
import { confirmAction } from "../../lib/async";
import { blobToBase64, saveBlob } from "../../lib/files";
import { normalizeUserConfigDraft, p12DraftFor } from "../../lib/userConfig";
import type { PanelCore } from "../core";
import { emptyUserConfig } from "../state";
import type {
  P12Base64ModalState,
  P12Draft,
  UserConfigModalState,
  UserGroupsModalState
} from "../types";

export function useUsers(core: PanelCore) {
  const { authToken, dryRun, recordCommand, runAction, runBusyTask, setNotice, setState } = core;
  const [newUser, setNewUser] = useState({ username: "", password: "" });
  const [passwordDrafts, setPasswordDrafts] = useState<Record<string, string>>({});
  const [p12Drafts, setP12Drafts] = useState<Record<string, P12Draft>>({});
  const [userConfigModal, setUserConfigModal] = useState<UserConfigModalState>(null);
  const [userGroupsModal, setUserGroupsModal] = useState<UserGroupsModalState>(null);
  const [p12Base64Modal, setP12Base64Modal] = useState<P12Base64ModalState>(null);

  const createUserAction = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const username = newUser.username.trim();
    const result = await runAction(
      "create-user",
      `User ${username} created`,
      (token) => createUser(token, username, newUser.password, dryRun),
      { dryRunAware: true }
    );
    recordCommand("users", result);
    if (result !== null && !dryRun) {
      setNewUser({ username: "", password: "" });
    }
  };

  const setPasswordDraft = (username: string, value: string) =>
    setPasswordDrafts((current) => ({ ...current, [username]: value }));

  const setP12Draft = (username: string, value: Partial<P12Draft>) =>
    setP12Drafts((current) => ({
      ...current,
      [username]: { ...p12DraftFor(current, username), ...value }
    }));

  const changePasswordAction = async (username: string) => {
    const password = passwordDrafts[username] ?? "";
    const result = await runAction(
      `password-${username}`,
      `Password changed for ${username}`,
      (token) => changePassword(token, username, password, dryRun),
      { dryRunAware: true }
    );
    recordCommand("users", result);
    if (result !== null && !dryRun) {
      setPasswordDrafts((current) => ({ ...current, [username]: "" }));
    }
  };

  const setEnabled = async (username: string, enabled: boolean) => {
    const result = await runAction(
      `${enabled ? "enable" : "disable"}-${username}`,
      `${username} ${enabled ? "enabled" : "disabled"}`,
      (token) => setUserEnabled(token, username, enabled, dryRun),
      { dryRunAware: true }
    );
    recordCommand("users", result);
  };

  const deleteUserAction = async (username: string) => {
    if (!confirmAction(`Delete user ${username}?`)) {
      return;
    }
    const result = await runAction(
      `delete-${username}`,
      `User ${username} deleted`,
      (token) => deleteUser(token, username)
    );
    recordCommand("users", result);
  };

  const setOtpEnabled = (username: string, enabled: boolean) =>
    void runAction(
      `${enabled ? "otp-on" : "otp-off"}-${username}`,
      `OTP ${enabled ? "enabled" : "disabled"} for ${username}`,
      (token) => setOtp(token, username, enabled)
    );

  const showOtpQr = async (username: string) => {
    const result = await runAction(
      `otp-qr-${username}`,
      `OTP QR generated for ${username}`,
      (token) => fetchOtpQr(token, username),
      { reload: false }
    );
    recordCommand("users", result);
  };

  const issueCertificate = async (username: string) => {
    const result = await runAction(
      `cert-${username}`,
      `Certificate issued for ${username}`,
      (token) => createCertificate(token, username, dryRun),
      { dryRunAware: true }
    );
    recordCommand("users", result?.results ?? null);
  };

  const revokeUserCertificate = async (username: string) => {
    if (!confirmAction(`Revoke the certificate for ${username}?`)) {
      return;
    }
    const result = await runAction(
      `revoke-cert-${username}`,
      `Certificate revoked for ${username}`,
      (token) => revokeCertificate(token, username, dryRun),
      { dryRunAware: true }
    );
    recordCommand("users", result);
  };

  const downloadFile = (
    kind: string,
    username: string,
    fetchFile: (token: string, username: string) => Promise<Blob>,
    extension: string
  ) =>
    runBusyTask(`download-${kind}-${username}`, async (token) => {
      const blob = await fetchFile(token, username);
      saveBlob(blob, `${username}.${extension}`);
      setNotice({ kind: "ok", text: `Downloaded ${username}.${extension}` });
    });

  const downloadP12 = (username: string) => downloadFile("p12", username, fetchP12, "p12");
  const downloadCert = (username: string) => downloadFile("cert", username, fetchUserCert, "crt");
  const downloadKey = (username: string) => downloadFile("key", username, fetchUserKey, "key");

  const viewP12Base64 = (username: string) =>
    runBusyTask(`view-p12-base64-${username}`, async (token) => {
      const blob = await fetchP12(token, username);
      const base64 = await blobToBase64(blob);
      setP12Base64Modal({ username, base64 });
    });

  const createP12Action = async (username: string) => {
    const draft = p12DraftFor(p12Drafts, username);
    const result = await runAction(
      `p12-${username}`,
      `PKCS#12 created for ${username}`,
      (token) => createP12(token, username, draft.passphrase, draft.appleCompatible, dryRun),
      { dryRunAware: true }
    );
    recordCommand("users", result);
    if (result !== null && result.returncode === 0 && !dryRun) {
      await downloadP12(username);
      setP12Drafts((current) => ({
        ...current,
        [username]: { ...p12DraftFor(current, username), passphrase: "" }
      }));
    }
  };

  const openConfig = async (username: string) => {
    await runAction(
      `user-config-load-${username}`,
      `Loaded config for ${username}`,
      async (token) => {
        const draft = await fetchUserConfig(token, username);
        setUserConfigModal({ username, draft: { ...emptyUserConfig, ...draft } });
        return { status: "ok" };
      },
      { reload: false }
    );
  };

  const openGroups = async (username: string) => {
    // Fetch fresh for the same reason as useGroups().openMembers: state.users
    // only updates after actions taken through this panel, so a stale tab or
    // an out-of-band change (CLI, another admin session) would otherwise
    // show wrong here.
    await runAction(
      `user-groups-load-${username}`,
      `Loaded groups for ${username}`,
      async (token) => {
        const users = await fetchUsers(token);
        setState((current) => ({ ...current, users }));
        const user = users.find((item) => item.username === username);
        setUserGroupsModal({ username, groups: user?.groups ?? [] });
        return { status: "ok" };
      },
      { reload: false }
    );
  };

  const deleteConfig = async () => {
    if (!userConfigModal) {
      return;
    }
    const username = userConfigModal.username;
    if (!confirmAction(`Clear per-user config for ${username}?`)) {
      return;
    }
    const result = await runAction(
      `user-config-delete-${username}`,
      `Config cleared for ${username}`,
      (token) => deleteUserConfig(token, username),
      { reload: false }
    );
    recordCommand("users", result);
    if (result) {
      setUserConfigModal(null);
    }
  };

  const saveConfig = async () => {
    if (!userConfigModal) {
      return;
    }
    const { username, draft } = userConfigModal;
    const result = await runAction(
      `user-config-save-${username}`,
      `Config saved for ${username}`,
      (token) => saveUserConfig(token, username, normalizeUserConfigDraft(draft)),
      { reload: false }
    );
    recordCommand("users", result);
    if (result) {
      setUserConfigModal(null);
    }
  };

  const saveGroups = async () => {
    if (!userGroupsModal) {
      return;
    }
    const { username, groups } = userGroupsModal;
    const result = await runAction(
      `user-groups-${username}`,
      `Groups saved for ${username}`,
      (token) => saveUserGroups(token, username, groups),
      { reload: false }
    );
    recordCommand("users", result);
    if (result !== null && authToken) {
      const users = await fetchUsers(authToken);
      setState((current) => ({ ...current, users }));
      setUserGroupsModal(null);
    }
  };

  return {
    newUser,
    setNewUser,
    passwordDrafts,
    p12Drafts,
    userConfigModal,
    setUserConfigModal,
    userGroupsModal,
    setUserGroupsModal,
    p12Base64Modal,
    setP12Base64Modal,
    setPasswordDraft,
    setP12Draft,
    createUser: createUserAction,
    changePassword: changePasswordAction,
    setEnabled,
    deleteUser: deleteUserAction,
    setOtpEnabled,
    showOtpQr,
    issueCertificate,
    revokeCertificate: revokeUserCertificate,
    createP12: createP12Action,
    downloadP12,
    downloadCert,
    downloadKey,
    viewP12Base64,
    openConfig,
    openGroups,
    deleteConfig,
    saveConfig,
    saveGroups
  };
}
