import { useState } from "react";
import {
  refreshDomainsUrl,
  refreshHostDomainsUrl,
  refreshHostRoutesUrl,
  refreshRoutesUrl,
  saveRoutingSettings,
  setDomains,
  setHostDomains,
  setHostRoutes,
  setRoutes
} from "../../api";
import { type UrlRefreshResult, syntheticCommand, urlRefreshSample } from "../../lib/commands";
import { readRoutingDraft, splitLines } from "../../lib/drafts";
import type { RoutingDraft } from "../../views/upstream/RoutingListSourcesPanel";
import type { PanelCore } from "../core";

// One of the four split lists; `command` is its korctl subcommand.
type RoutingList = {
  command: "routes" | "domains" | "host-routes" | "host-domains";
  key: string;
  label: string;
  save: (token: string, items: string[]) => Promise<unknown>;
  refresh: (token: string, url: string, preview: boolean) => Promise<UrlRefreshResult>;
};

const routingLists = {
  routes: {
    command: "routes",
    key: "routes",
    label: "Route",
    save: setRoutes,
    refresh: refreshRoutesUrl
  },
  domains: {
    command: "domains",
    key: "domains",
    label: "Domain",
    save: setDomains,
    refresh: refreshDomainsUrl
  },
  hostRoutes: {
    command: "host-routes",
    key: "host-routes",
    label: "Host route",
    save: setHostRoutes,
    refresh: refreshHostRoutesUrl
  },
  hostDomains: {
    command: "host-domains",
    key: "host-domains",
    label: "Host domain",
    save: setHostDomains,
    refresh: refreshHostDomainsUrl
  }
} satisfies Record<string, RoutingList>;

export function useRouting(core: PanelCore) {
  const { recordCommand, runAction } = core;
  const [routingDraft, setRoutingDraft] = useState<RoutingDraft>({
    clientPolicy: "full",
    hostPolicy: "off",
    hostDns: "off",
    mainInterface: "auto",
    fwmark: "0x0c01",
    tableId: 1201,
    nftPrefix: "kornode",
    routesFilesText: "",
    routesUrlsText: "",
    domainsFilesText: "",
    domainsUrlsText: "",
    hostRoutesFilesText: "",
    hostRoutesUrlsText: "",
    hostDomainsFilesText: "",
    hostDomainsUrlsText: ""
  });

  core.registerHydrator("routing", (snapshot) => {
    if (snapshot.config) {
      setRoutingDraft(readRoutingDraft(snapshot.config));
    }
  });

  const saveList = async (list: RoutingList, items: string[]) => {
    // "Routes saved", "Host domains saved", ...
    const noun = `${list.label}s`;
    const result = await runAction(`save-${list.key}`, `${noun} saved`, (token) =>
      list.save(token, items)
    );
    if (result !== null) {
      recordCommand(
        "routing",
        syntheticCommand(["korctl", list.command, "set", ...items], "saved")
      );
    }
  };

  const refreshListUrl = async (list: RoutingList, url: string, preview: boolean) => {
    const result = await runAction(
      preview ? `${list.key}-preview-${url}` : `${list.key}-refresh-${url}`,
      preview ? `${list.label} URL validated` : `${list.label} list downloaded and applied`,
      (token) => list.refresh(token, url, preview)
    );
    if (result !== null) {
      const argv = ["korctl", list.command, "refresh", "--url", url];
      if (preview) argv.push("--preview");
      recordCommand(
        "routing",
        syntheticCommand(
          argv,
          [
            `url: ${result.url}`,
            `valid: ${result.valid}`,
            `skipped: ${result.skipped}`,
            urlRefreshSample(result)
          ].join("\n")
        )
      );
    }
  };

  const saveRoutingSettingsAction = async () => {
    const result = await runAction("routing-settings", "Routing settings saved", (token) =>
      saveRoutingSettings(token, {
        client_policy: routingDraft.clientPolicy,
        host_policy: routingDraft.hostPolicy,
        host_dns: routingDraft.hostDns,
        main_interface: routingDraft.mainInterface,
        fwmark: routingDraft.fwmark,
        table_id: routingDraft.tableId,
        nft_prefix: routingDraft.nftPrefix,
        routes_files: splitLines(routingDraft.routesFilesText),
        routes_urls: splitLines(routingDraft.routesUrlsText),
        domains_files: splitLines(routingDraft.domainsFilesText),
        domains_urls: splitLines(routingDraft.domainsUrlsText),
        host_routes_files: splitLines(routingDraft.hostRoutesFilesText),
        host_routes_urls: splitLines(routingDraft.hostRoutesUrlsText),
        host_domains_files: splitLines(routingDraft.hostDomainsFilesText),
        host_domains_urls: splitLines(routingDraft.hostDomainsUrlsText)
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
    saveRoutes: (items: string[]) => void saveList(routingLists.routes, items),
    saveDomains: (items: string[]) => void saveList(routingLists.domains, items),
    saveHostRoutes: (items: string[]) => void saveList(routingLists.hostRoutes, items),
    saveHostDomains: (items: string[]) => void saveList(routingLists.hostDomains, items),
    refreshRoutesUrl: (url: string, preview: boolean) =>
      void refreshListUrl(routingLists.routes, url, preview),
    refreshDomainsUrl: (url: string, preview: boolean) =>
      void refreshListUrl(routingLists.domains, url, preview),
    refreshHostRoutesUrl: (url: string, preview: boolean) =>
      void refreshListUrl(routingLists.hostRoutes, url, preview),
    refreshHostDomainsUrl: (url: string, preview: boolean) =>
      void refreshListUrl(routingLists.hostDomains, url, preview),
    saveRoutingSettings: saveRoutingSettingsAction
  };
}
