import { useState } from "react";
import { saveRoutingSettings } from "../../api";
import { syntheticCommand } from "../../lib/commands";
import { type RoutingDraft, readRoutingDraft } from "../../lib/drafts";
import type { PanelCore } from "../core";

// Host DNS mode and the main (uplink) interface: the only routing.* settings
// left on `POST /api/routing/settings`. Egress policy lives in HubEgress.
export function useRouting(core: PanelCore) {
  const { recordCommand, runAction } = core;
  const [routingDraft, setRoutingDraft] = useState<RoutingDraft>({
    hostDns: "off",
    mainInterface: "auto"
  });

  core.registerHydrator("routing", (snapshot) => {
    if (snapshot.config) {
      setRoutingDraft(readRoutingDraft(snapshot.config));
    }
  });

  const saveRoutingSettingsAction = async () => {
    const result = await runAction("routing-settings", "Routing settings saved", (token) =>
      saveRoutingSettings(token, {
        host_dns: routingDraft.hostDns,
        main_interface: routingDraft.mainInterface
      })
    );
    if (result !== null) {
      recordCommand(
        "routing",
        syntheticCommand(
          ["korctl", "routing", "settings"],
          result.host_dns ? `saved\nhost DNS: ${result.host_dns.detail}` : "saved"
        )
      );
    }
  };

  return {
    routingDraft,
    setRoutingDraft,
    saveRoutingSettings: saveRoutingSettingsAction
  };
}
