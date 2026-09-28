import { type FormEvent, useState } from "react";
import {
  type GroupPolicyDraft,
  type OidcProviderDraft,
  deleteGroupPolicy,
  deleteOidcProvider,
  saveGroupPolicy,
  saveIdentitySettings,
  saveOidcProvider,
  saveOidcSettings
} from "../../api";
import { syntheticCommand } from "../../lib/commands";
import { readOidcDraft } from "../../lib/drafts";
import type { PanelCore } from "../core";
import type { OidcDraft } from "../types";

export function useIdentity(core: PanelCore) {
  const { recordCommand, runAction } = core;
  const [oidcDraft, setOidcDraft] = useState<OidcDraft>({
    enabled: false,
    connector: "pam",
    pamService: "ocserv",
    pamGidMin: "1000",
    radiusConfigFile: "/etc/radiusclient/radiusclient.conf",
    radiusGroupconfig: true,
    radiusNasIdentifier: "",
    radiusGroupSeparator: "semicolon"
  });
  const [identitySettingsDraft, setIdentitySettingsDraft] = useState({
    selectGroupByUrl: false,
    defaultSelectGroup: "",
    defaultGroupConfig: ""
  });
  const [oidcProviderDraft, setOidcProviderDraft] = useState<OidcProviderDraft>({
    name: "keycloak",
    issuer_url: "",
    client_id: "",
    client_secret: "",
    scopes: ["openid", "profile", "email"],
    username_claim: "preferred_username",
    groups_claim: "groups",
    allowed_groups: []
  });
  const [groupPolicyDraft, setGroupPolicyDraft] = useState<GroupPolicyDraft>({
    name: "devops",
    display_name: "",
    routes: "",
    no_routes: "",
    dns: "",
    split_dns: "",
    tunnel_all_dns: false,
    max_same_clients: "",
    session_timeout: "",
    idle_timeout: "",
    no_udp: false
  });

  core.registerHydrator("identity", ({ identity }) => {
    if (!identity) {
      return;
    }
    setOidcDraft(readOidcDraft(identity));
    setIdentitySettingsDraft({
      selectGroupByUrl: identity.select_group_by_url,
      defaultSelectGroup: identity.default_select_group ?? "",
      defaultGroupConfig: identity.default_group_config ?? ""
    });
  });

  const saveOidcSettingsAction = async () => {
    const result = await runAction("oidc-settings", "OIDC connector settings saved", (token) =>
      saveOidcSettings(token, {
        enabled: oidcDraft.enabled,
        connector: oidcDraft.connector,
        pam_service: oidcDraft.pamService,
        pam_gid_min: oidcDraft.pamGidMin ? Number(oidcDraft.pamGidMin) : null,
        radius_config_file: oidcDraft.radiusConfigFile,
        radius_groupconfig: oidcDraft.radiusGroupconfig,
        radius_nas_identifier: oidcDraft.radiusNasIdentifier || null,
        radius_group_separator: oidcDraft.radiusGroupSeparator
      })
    );
    if (result !== null) {
      const saved = syntheticCommand(["korctl", "identity", "oidc", "settings"], "saved");
      recordCommand("identity", result.reload ? [saved, result.reload] : saved);
    }
  };

  const saveIdentitySettingsAction = async () => {
    const result = await runAction(
      "identity-settings",
      "Group routing settings saved",
      (token) =>
        saveIdentitySettings(token, {
          select_group_by_url: identitySettingsDraft.selectGroupByUrl,
          default_select_group: identitySettingsDraft.defaultSelectGroup.trim() || null,
          default_group_config: identitySettingsDraft.defaultGroupConfig.trim() || null
        }),
      { reload: false }
    );
    if (result !== null) {
      recordCommand("identity", syntheticCommand(["korctl", "identity", "settings"], "saved"));
    }
  };

  const saveProvider = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const result = await runAction("oidc-provider", "OIDC provider saved", (token) =>
      saveOidcProvider(token, oidcProviderDraft)
    );
    if (result !== null) {
      recordCommand(
        "identity",
        syntheticCommand(["korctl", "identity", "oidc", "provider-set"], "saved")
      );
      setOidcProviderDraft((current) => ({ ...current, client_secret: "" }));
    }
  };

  const saveGroup = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const result = await runAction("group-policy", "Group policy saved", (token) =>
      saveGroupPolicy(token, groupPolicyDraft)
    );
    if (result !== null) {
      recordCommand("identity", syntheticCommand(["korctl", "identity", "group", "set"], "saved"));
    }
  };

  const deleteProvider = (name: string) =>
    void runAction(`oidc-provider-delete-${name}`, `OIDC provider ${name} deleted`, (token) =>
      deleteOidcProvider(token, name)
    );

  const deleteGroup = (name: string) =>
    void runAction(`group-policy-delete-${name}`, `Group policy ${name} deleted`, (token) =>
      deleteGroupPolicy(token, name)
    );

  return {
    oidcDraft,
    setOidcDraft,
    identitySettingsDraft,
    setIdentitySettingsDraft,
    oidcProviderDraft,
    setOidcProviderDraft,
    groupPolicyDraft,
    setGroupPolicyDraft,
    saveOidcSettings: saveOidcSettingsAction,
    saveIdentitySettings: saveIdentitySettingsAction,
    saveProvider,
    saveGroup,
    deleteProvider,
    deleteGroup
  };
}
