import { useState } from "react";
import { refreshInternalDnsBlocklist, saveInternalDnsSettings } from "../../api";
import { syntheticCommand, urlRefreshSample } from "../../lib/commands";
import { type ServerSettingsDraft, splitLines } from "../../lib/drafts";
import type { InternalDnsDraft } from "../../views/InternalDnsView";
import type { PanelCore } from "../core";

// The DNS page also edits the server's client DNS list, so saving it sends
// part of that draft along too.
export function useInternalDns(core: PanelCore, serverSettingsDraft: ServerSettingsDraft) {
  const { recordCommand, runAction, setNotice } = core;
  const [internalDnsDraft, setInternalDnsDraft] = useState<InternalDnsDraft>({
    listen: "10.10.10.1",
    port: 53,
    blocklistEnabled: false,
    localRecordsEnabled: false,
    upstreamsText: "",
    forwardUpstreamsText: "",
    forwardDomainsText: "",
    domainsText: "",
    filesText: "",
    urlsText: "",
    cacheSize: 150,
    logQueries: false,
    localRecordsText: ""
  });

  core.registerHydrator("internalDns", ({ internalDns }) => {
    if (!internalDns) {
      return;
    }
    setInternalDnsDraft({
      listen: internalDns.listen,
      port: internalDns.port,
      blocklistEnabled:
        internalDns.blocklist_enabled ??
        (internalDns.blocklist_domains.length > 0 ||
          internalDns.blocklist_files.length > 0 ||
          internalDns.blocklist_urls.length > 0),
      localRecordsEnabled:
        internalDns.local_records_enabled ?? internalDns.local_records.length > 0,
      upstreamsText: internalDns.upstreams.join("\n"),
      forwardUpstreamsText: internalDns.forward_upstreams.join("\n"),
      forwardDomainsText: internalDns.forward_domains.join("\n"),
      domainsText: internalDns.blocklist_domains.join("\n"),
      filesText: internalDns.blocklist_files.map((item) => item.path).join("\n"),
      urlsText: internalDns.blocklist_urls.map((item) => item.url).join("\n"),
      cacheSize: internalDns.cache_size,
      logQueries: internalDns.log_queries,
      localRecordsText: internalDns.local_records.join("\n")
    });
  });

  const save = async () => {
    const result = await runAction(
      "internal-dns-settings",
      "DNS settings saved and applied",
      (token) =>
        saveInternalDnsSettings(token, {
          listen: internalDnsDraft.listen,
          port: internalDnsDraft.port,
          blocklist_enabled: internalDnsDraft.blocklistEnabled,
          local_records_enabled: internalDnsDraft.localRecordsEnabled,
          server_dns: splitLines(serverSettingsDraft.dns),
          search_domains: splitLines(serverSettingsDraft.searchDomains),
          upstreams: splitLines(internalDnsDraft.upstreamsText),
          forward_upstreams: splitLines(internalDnsDraft.forwardUpstreamsText),
          forward_domains: splitLines(internalDnsDraft.forwardDomainsText),
          blocklist_domains: splitLines(internalDnsDraft.domainsText),
          blocklist_files: splitLines(internalDnsDraft.filesText),
          blocklist_urls: splitLines(internalDnsDraft.urlsText),
          cache_size: internalDnsDraft.cacheSize,
          log_queries: internalDnsDraft.logQueries,
          local_records: splitLines(internalDnsDraft.localRecordsText)
        }),
      { reload: false }
    );
    if (result !== null) {
      recordCommand("internal_dns", result.commands);
      setNotice({
        kind: result.reconnect_required ? "warning" : "ok",
        text: result.reconnect_required
          ? "DNS settings applied; client-facing DNS changed, so active VPN clients are reconnecting"
          : "DNS settings applied without disconnecting VPN clients"
      });
    }
  };

  const refreshBlocklist = async (url: string, preview: boolean) => {
    const result = await runAction(
      preview ? `internal-dns-preview-${url}` : `internal-dns-refresh-${url}`,
      preview ? "Blocklist URL validated" : "Blocklist downloaded and applied",
      (token) => refreshInternalDnsBlocklist(token, url, preview)
    );
    if (result !== null) {
      const argv = ["korctl", "internal-dns", "refresh", "--url", url];
      if (preview) {
        argv.push("--preview");
      }
      recordCommand(
        "internal_dns",
        syntheticCommand(
          argv,
          [
            `url: ${result.url}`,
            `valid domains: ${result.valid}`,
            `skipped lines: ${result.skipped}`,
            `applied: ${result.saved ? "yes" : "no (preview)"}`,
            urlRefreshSample(result)
          ].join("\n")
        )
      );
    }
  };

  return { internalDnsDraft, setInternalDnsDraft, save, refreshBlocklist };
}
