import { type FormEvent, useEffect, useState } from "react";
import {
  type UpstreamProfile,
  type UpstreamProfileDraft,
  connectUpstreamProfile,
  deleteUpstreamProfile,
  disconnectUpstreamProfile,
  fetchUpstreamProfiles,
  fetchUpstreamServerPin,
  fetchUpstreamStatus,
  saveUpstreamProfile,
  saveUpstreamSettings,
  setUpstreamProfileEnabled,
  switchUpstream,
  syncUpstreamProfile
} from "../../api";
import { confirmAction } from "../../lib/async";
import { syntheticCommand } from "../../lib/commands";
import { readBoolean, readNumber, readRecord } from "../../lib/read";
import type { PanelCore } from "../core";
import { emptyUpstreamProfileDraft, upstreamProfileToDraft } from "../state";
import type { ConfigSection, Tab } from "../types";

// `saveRoutingSettings` comes from useRouting(): the Upstream settings dialog
// also holds the server-side routing controls and saves them together.
export function useUpstream(
  core: PanelCore,
  tab: Tab,
  configSection: ConfigSection,
  saveRoutingSettings: () => Promise<void>
) {
  const { authInfo, authToken, dryRun, recordCommand, runAction, setState, state } = core;
  const [upstreamDraft, setUpstreamDraft] =
    useState<UpstreamProfileDraft>(emptyUpstreamProfileDraft);
  // Fixed at the moment the dialog opens (create vs. edit an existing
  // profile) -- must NOT be derived from draft.name, which changes on
  // every keystroke and would flip a brand-new profile into "edit mode"
  // (disabling the Name field, see UpstreamProfileDialog) after the very
  // first character typed.
  const [editingProfile, setEditingProfile] = useState(false);
  // Bumped each time the dialog opens (create or edit) so
  // UpstreamProfileDialog remounts with fresh local state (certMode,
  // keyMode, ...) when switching targets, WITHOUT remounting -- and
  // dropping input focus -- on every keystroke the way keying off the
  // live-typed draft.name did.
  const [profileDialogKey, setProfileDialogKey] = useState(0);
  const [profileModalOpen, setProfileModalOpen] = useState(false);
  const [settingsModalOpen, setSettingsModalOpen] = useState(false);
  // Upstream section: one client's own relay lists (route_clients_enabled/
  // routes/domains), edited separately from the Clients dialog.
  const [relayDraft, setRelayDraft] = useState<UpstreamProfileDraft | null>(null);
  const [upstreamInterface, setUpstreamInterface] = useState("oc-middle0");
  const [checkInterval, setCheckInterval] = useState(5);
  const [checkThreshold, setCheckThreshold] = useState(3);
  const [checkSettleSeconds, setCheckSettleSeconds] = useState(15);
  const [failover, setFailover] = useState(false);
  const [connectOnBoot, setConnectOnBoot] = useState(true);
  const [checkHost, setCheckHost] = useState("");

  core.registerHydrator("upstream", ({ config, upstream }) => {
    if (config) {
      const upstreamConfig = readRecord(config.upstream);
      setCheckInterval(readNumber(upstreamConfig.check_interval, 5));
      setCheckThreshold(readNumber(upstreamConfig.check_threshold, 3));
      setCheckSettleSeconds(readNumber(upstreamConfig.check_settle_seconds, 15));
      setFailover(readBoolean(upstreamConfig.failover, false));
      setConnectOnBoot(readBoolean(upstreamConfig.connect_on_boot, true));
    }
    if (upstream) {
      setUpstreamInterface(upstream.interface || "oc-middle0");
    }
  });

  useEffect(() => {
    if (
      tab !== "config" ||
      (configSection !== "clients" && configSection !== "upstream") ||
      !authToken ||
      !authInfo
    ) {
      return;
    }
    // The watchdog connects/reconnects in the background, so the
    // Connected/Connection state changes without any panel action --
    // keep it live while the section is open instead of showing whatever
    // was true at login.
    const refreshUpstream = () => {
      Promise.all([fetchUpstreamStatus(authToken), fetchUpstreamProfiles(authToken)])
        .then(([upstream, upstreamProfiles]) => {
          setState((current) => ({ ...current, upstream, upstreamProfiles }));
        })
        .catch(() => {
          // Transient polling failure: keep the last known state.
        });
    };
    const interval = window.setInterval(refreshUpstream, 5000);
    return () => window.clearInterval(interval);
  }, [authInfo, authToken, configSection, setState, tab]);

  const activeProfile = () =>
    state.upstreamProfiles.find((profile) => profile.name === state.upstream?.active_profile);

  const saveSettings = async (enabled: boolean) => {
    const result = await runAction(
      "upstream-settings",
      `Clients ${enabled ? "enabled" : "disabled"}`,
      (token) =>
        saveUpstreamSettings(token, {
          enabled,
          interface: upstreamInterface,
          active_profile: state.upstream?.active_profile ?? state.upstreamProfiles[0]?.name ?? null,
          check_interval: checkInterval,
          check_threshold: checkThreshold,
          check_settle_seconds: checkSettleSeconds,
          failover,
          connect_on_boot: connectOnBoot
        })
    );
    if (result !== null) {
      recordCommand("upstream", syntheticCommand(["korctl", "upstream", "settings"], "saved"));
    }
  };

  const saveCheckHost = async () => {
    const active = activeProfile();
    if (!active) {
      return;
    }
    const draft: UpstreamProfileDraft = {
      ...upstreamProfileToDraft(active, Boolean(state.upstream?.enabled)),
      check_host: checkHost
    };
    const result = await runAction("upstream-settings", "Check host saved", (token) =>
      saveUpstreamProfile(token, draft)
    );
    if (result !== null) {
      recordCommand("upstream", syntheticCommand(["korctl", "upstream", "profile"], "saved"));
    }
  };

  const saveProfile = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const result = await runAction("upstream-profile", "Client saved", (token) =>
      saveUpstreamProfile(token, upstreamDraft)
    );
    if (result !== null) {
      recordCommand("upstream", syntheticCommand(["korctl", "upstream", "profile"], "saved"));
      setProfileModalOpen(false);
    }
  };

  const deleteProfile = async (name: string) => {
    if (!confirmAction(`Delete client ${name}?`)) {
      return;
    }
    const result = await runAction(
      `upstream-profile-delete-${name}`,
      `Client ${name} deleted`,
      (token) => deleteUpstreamProfile(token, name)
    );
    if (result !== null) {
      recordCommand(
        "upstream",
        syntheticCommand(["korctl", "upstream", "profile", "delete", name], "deleted")
      );
    }
  };

  const setProfileEnabled = async (name: string, enabled: boolean) => {
    const result = await runAction(
      `upstream-profile-enabled-${name}`,
      `Client ${name} ${enabled ? "enabled" : "disabled"}`,
      (token) => setUpstreamProfileEnabled(token, name, enabled)
    );
    if (result !== null) {
      recordCommand(
        "upstream",
        syntheticCommand(
          ["korctl", "upstream", enabled ? "enable" : "disable", name],
          enabled ? "enabled" : "disabled"
        )
      );
    }
  };

  const switchProfile = (profile: string) => {
    const current = state.upstream?.active_profile;
    if (
      current &&
      current !== profile &&
      !confirmAction(
        `Make "${profile}" the default client? VPN-user/host traffic currently ` +
          `redirected via "${current}" will re-point to "${profile}" -- ` +
          "existing connections stay up."
      )
    ) {
      return;
    }
    void runAction(`switch-${profile}`, `Default client set to ${profile}`, (token) =>
      switchUpstream(token, profile)
    );
  };

  const openProfileDialog = (draft: UpstreamProfileDraft, isEdit: boolean) => {
    setUpstreamDraft(draft);
    setEditingProfile(isEdit);
    setProfileDialogKey((key) => key + 1);
    setProfileModalOpen(true);
  };

  const createProfile = () => openProfileDialog(emptyUpstreamProfileDraft, false);

  const editProfile = (profile: UpstreamProfile) =>
    openProfileDialog(upstreamProfileToDraft(profile, Boolean(state.upstream?.enabled)), true);

  const connectProfile = async (name: string) => {
    const result = await runAction(
      `upstream-profile-connect-${name}`,
      `Client ${name} connected`,
      (token) => connectUpstreamProfile(token, name, dryRun),
      { dryRunAware: true }
    );
    recordCommand("upstream", result);
  };

  const disconnectProfile = async (name: string) => {
    const result = await runAction(
      `upstream-profile-disconnect-${name}`,
      `Client ${name} disconnected`,
      (token) => disconnectUpstreamProfile(token, name, dryRun),
      { dryRunAware: true }
    );
    recordCommand("upstream", result);
  };

  // Reads the certificate the draft's server presents (unverified) and, once
  // the admin confirms it matches what that server shows for itself, pins it.
  const fetchDraftServerPin = async () => {
    const server = upstreamDraft.server.trim();
    const port = Number(upstreamDraft.port) || 443;
    if (!server) {
      core.setNotice({ kind: "error", text: "enter the server address first" });
      return;
    }
    const result = await runAction(
      "upstream-fetch-pin",
      `Certificate pin read from ${server}:${port}`,
      (token) => fetchUpstreamServerPin(token, server, port),
      { reload: false }
    );
    if (
      result &&
      confirmAction(
        `${server}:${port} presented this certificate:\n\n${result.pin}\n\n` +
          "Compare it with the pin that server shows for itself (on a kornode: " +
          "Config → Certificates → Show connection pin). Pin this certificate?"
      )
    ) {
      setUpstreamDraft((current) => ({ ...current, server_cert_pin: result.pin }));
    }
  };

  const syncProfile = async (name: string) => {
    const result = await runAction(
      `upstream-profile-sync-${name}`,
      `Server lists of ${name} synced`,
      (token) => syncUpstreamProfile(token, name)
    );
    if (result !== null) {
      const routing = result.server_routing;
      recordCommand(
        "upstream",
        syntheticCommand(
          ["korctl", "upstream", "sync", name],
          `${routing.routes.length} routes, ${routing.domains.length} split-DNS domains` +
            (routing.version ? ` (version ${routing.version})` : "")
        )
      );
    }
  };

  const editRelay = (profile: UpstreamProfile) =>
    setRelayDraft(upstreamProfileToDraft(profile, Boolean(state.upstream?.enabled)));

  const saveRelay = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!relayDraft) {
      return;
    }
    const draft = relayDraft;
    const result = await runAction("upstream-relay", `Relay lists of ${draft.name} saved`, (token) =>
      saveUpstreamProfile(token, draft)
    );
    if (result !== null) {
      recordCommand(
        "upstream",
        syntheticCommand(["korctl", "upstream", "profile", draft.name], "relay lists saved")
      );
      setRelayDraft(null);
    }
  };

  const openSettings = () => {
    setCheckHost(activeProfile()?.check_host ?? "");
    setSettingsModalOpen(true);
  };

  const submitSettings = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await saveSettings(Boolean(state.upstream?.enabled));
    await saveCheckHost();
    await saveRoutingSettings();
    setSettingsModalOpen(false);
  };

  return {
    upstreamDraft,
    setUpstreamDraft,
    editingProfile,
    profileDialogKey,
    profileModalOpen,
    closeProfileDialog: () => setProfileModalOpen(false),
    settingsModalOpen,
    closeSettings: () => setSettingsModalOpen(false),
    upstreamInterface,
    setUpstreamInterface,
    checkInterval,
    setCheckInterval,
    checkThreshold,
    setCheckThreshold,
    checkSettleSeconds,
    setCheckSettleSeconds,
    failover,
    setFailover,
    connectOnBoot,
    setConnectOnBoot,
    checkHost,
    setCheckHost,
    saveSettings,
    saveProfile,
    deleteProfile,
    setProfileEnabled,
    switchProfile,
    createProfile,
    editProfile,
    connectProfile,
    disconnectProfile,
    openSettings,
    submitSettings,
    fetchDraftServerPin,
    syncProfile,
    relayDraft,
    setRelayDraft,
    editRelay,
    saveRelay,
    closeRelay: () => setRelayDraft(null)
  };
}
