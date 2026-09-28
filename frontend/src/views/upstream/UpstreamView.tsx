import { ArrowRight, Pencil, Save } from "lucide-react";
import type { FormEvent } from "react";
import { BulkListEditor } from "../../components/BulkListEditor";
import { LastCommandPanel } from "../../components/CommandOutput";
import { Table } from "../../components/Table";
import { ActionButton, IconButton, Pill } from "../../components/ui";
import { type RoutingDraft, RoutingListSourcesPanel } from "./RoutingListSourcesPanel";
import type {
  CommandResult,
  RoutingListStatus,
  UpstreamProfile,
  UpstreamStatus
} from "../../api";

// Config → Upstream: relaying this server's VPN users' traffic through one
// of the Clients (middle-server mode). The connections themselves live in
// Config → Clients; this section only decides which VPN-user traffic goes
// through them, so it needs at least one client to do anything.
export function UpstreamView({
  status,
  profiles,
  serverEnabled,
  routingDraft,
  routes,
  domains,
  routesStatus,
  domainsStatus,
  busy,
  commandOutput,
  onClearCommand,
  onRoutingDraftChange,
  onSaveSettings,
  onSaveRoutes,
  onSaveDomains,
  onPreviewRoutesUrl,
  onRefreshRoutesUrl,
  onPreviewDomainsUrl,
  onRefreshDomainsUrl,
  onEditRelay,
  onOpenClients
}: {
  status: UpstreamStatus | null;
  profiles: UpstreamProfile[];
  serverEnabled: boolean;
  routingDraft: RoutingDraft;
  routes: string[];
  domains: string[];
  routesStatus: RoutingListStatus | null;
  domainsStatus: RoutingListStatus | null;
  busy: string | null;
  commandOutput: CommandResult | CommandResult[] | null;
  onClearCommand: () => void;
  onRoutingDraftChange: (value: RoutingDraft) => void;
  onSaveSettings: () => void;
  onSaveRoutes: (items: string[]) => void;
  onSaveDomains: (items: string[]) => void;
  onPreviewRoutesUrl: (url: string) => void;
  onRefreshRoutesUrl: (url: string) => void;
  onPreviewDomainsUrl: (url: string) => void;
  onRefreshDomainsUrl: (url: string) => void;
  onEditRelay: (profile: UpstreamProfile) => void;
  onOpenClients: () => void;
}) {
  const hasClients = profiles.length > 0;
  const clientsEnabled = Boolean(status?.enabled);
  const defaultClient = status?.active_profile ?? null;
  const inert = !clientsEnabled || !serverEnabled;
  const splitEnabled = routingDraft.mode === "split";
  const splitDnsEnabled = splitEnabled && routingDraft.tunnelDns;
  const relaying = hasClients && clientsEnabled && serverEnabled && routingDraft.clientTraffic;

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSaveSettings();
  };

  return (
    <>
      <section className="panel">
        <div className="panel-header">
          <h2>Upstream</h2>
          <div className="toolbar">
            <Pill kind={relaying ? "ok" : "muted"}>
              {relaying && defaultClient ? `Relaying via ${defaultClient}` : "Not relaying"}
            </Pill>
          </div>
        </div>
        <p className="muted-line">
          Sends the traffic of this server&rsquo;s VPN users onward through one of the
          Clients (middle-server mode). The connections themselves, failover and health
          checks are managed in Clients.
        </p>
        {!hasClients ? (
          <div className="upstream-empty">
            <p>
              Upstream needs at least one client: create the outbound connection it should
              relay through first.
            </p>
            <ActionButton label="Go to Clients" icon={ArrowRight} primary onClick={onOpenClients} />
          </div>
        ) : (
          <form className="upstream-settings-form" onSubmit={submit}>
            {!serverEnabled && (
              <p className="muted-line">
                <Pill kind="warning">VPN server disabled</Pill> There are no VPN users to relay
                while the server is off (Config → Server).
              </p>
            )}
            {!clientsEnabled && (
              <p className="muted-line">
                <Pill kind="warning">Clients disabled</Pill> Enable Clients to relay through them.
              </p>
            )}
            <p className="muted-line">
              {defaultClient
                ? `Default client: ${defaultClient} (change it in Clients). `
                : "No default client selected yet (pick one in Clients). "}
              A client&rsquo;s own relay lists below always win over this default.
            </p>
            <label className="switch">
              <input
                checked={routingDraft.clientTraffic}
                disabled={inert}
                onChange={(event) =>
                  onRoutingDraftChange({ ...routingDraft, clientTraffic: event.target.checked })
                }
                type="checkbox"
              />
              <span>Relay VPN users&rsquo; traffic through the default client</span>
            </label>
            {routingDraft.clientTraffic && (
              <label>
                <span>Mode</span>
                <select
                  disabled={inert}
                  value={routingDraft.mode}
                  onChange={(event) =>
                    onRoutingDraftChange({ ...routingDraft, mode: event.target.value })
                  }
                >
                  <option value="full">Full (all traffic via Upstream)</option>
                  <option value="split">Split (only listed traffic via Upstream)</option>
                </select>
              </label>
            )}
            {routingDraft.clientTraffic && splitEnabled && (
              <div className="routing-substep">
                <label
                  className="switch"
                  title="Push this server's dnsmasq as the DNS for VPN users and resolve the Domains list below into the split set. Distinct from the per-user/group 'Split DNS' setting. The dnsmasq listen address/port are configured in Config → DNS."
                >
                  <input
                    checked={routingDraft.tunnelDns}
                    disabled={inert}
                    onChange={(event) =>
                      onRoutingDraftChange({ ...routingDraft, tunnelDns: event.target.checked })
                    }
                    type="checkbox"
                  />
                  <span>Also split by domain (needs this server&rsquo;s own DNS)</span>
                </label>
                <section className="split">
                  <BulkListEditor
                    title="Routes"
                    items={routes}
                    placeholder={"10.20.0.0/16\n203.0.113.5"}
                    busy={busy === "save-routes"}
                    disabled={inert}
                    onSave={onSaveRoutes}
                  />
                  {splitDnsEnabled && (
                    <BulkListEditor
                      title="Domains"
                      items={domains}
                      placeholder={"internal.example\ncorp.example.com"}
                      busy={busy === "save-domains"}
                      disabled={inert}
                      onSave={onSaveDomains}
                    />
                  )}
                </section>
                <section className="split">
                  <RoutingListSourcesPanel
                    title="Route sources"
                    filesLabel="Route files (one path per line)"
                    filesPlaceholder={"/var/lib/kornode/extra-routes.txt"}
                    urlsLabel="Route URLs (one per line)"
                    urlsPlaceholder={"https://lists.example.com/routes.txt"}
                    disabled={inert}
                    filesText={routingDraft.routesFilesText}
                    urlsText={routingDraft.routesUrlsText}
                    status={routesStatus}
                    busy={busy}
                    busyKeyPrefix="routes"
                    onFilesTextChange={(value) =>
                      onRoutingDraftChange({ ...routingDraft, routesFilesText: value })
                    }
                    onUrlsTextChange={(value) =>
                      onRoutingDraftChange({ ...routingDraft, routesUrlsText: value })
                    }
                    onPreviewUrl={onPreviewRoutesUrl}
                    onRefreshUrl={onRefreshRoutesUrl}
                  />
                  {splitDnsEnabled && (
                    <RoutingListSourcesPanel
                      title="Domain sources"
                      filesLabel="Domain files (one path per line)"
                      filesPlaceholder={"/var/lib/kornode/extra-domains.txt"}
                      urlsLabel="Domain URLs (one per line)"
                      urlsPlaceholder={"https://lists.example.com/domains.txt"}
                      disabled={inert}
                      filesText={routingDraft.domainsFilesText}
                      urlsText={routingDraft.domainsUrlsText}
                      status={domainsStatus}
                      busy={busy}
                      busyKeyPrefix="domains"
                      onFilesTextChange={(value) =>
                        onRoutingDraftChange({ ...routingDraft, domainsFilesText: value })
                      }
                      onUrlsTextChange={(value) =>
                        onRoutingDraftChange({ ...routingDraft, domainsUrlsText: value })
                      }
                      onPreviewUrl={onPreviewDomainsUrl}
                      onRefreshUrl={onRefreshDomainsUrl}
                    />
                  )}
                </section>
                <p className="muted-line">
                  Route/domain sources are saved with the button below -- fill these in, click
                  Save, then validate/download each URL.
                </p>
              </div>
            )}
            <div className="modal-actions">
              <button
                className="primary-button"
                disabled={busy === "routing-settings"}
                type="submit"
              >
                <Save size={18} aria-hidden="true" />
                <span>Save</span>
              </button>
            </div>
          </form>
        )}
      </section>

      {hasClients && (
        <section className="panel">
          <div className="panel-header">
            <h2>Relay lists per client</h2>
          </div>
          <p className="muted-line">
            Send specific destinations of VPN users through a specific client, whichever
            client is the default.
          </p>
          <Table columns={["Client", "Relay lists", "Actions"]} empty="No clients yet">
            {profiles.map((profile) => {
              const relayOn = Boolean(profile.route_clients_enabled);
              const routeCount = profile.routes?.length ?? 0;
              const domainCount = profile.domains?.length ?? 0;
              return (
                <tr key={profile.name}>
                  <td className="strong-cell">
                    <div className="inline-tools">
                      <span>{profile.name}</span>
                      {profile.name === defaultClient && <Pill kind="ok">Default</Pill>}
                    </div>
                  </td>
                  <td>
                    {relayOn && routeCount + domainCount > 0 ? (
                      <span>{`${routeCount} routes / ${domainCount} domains`}</span>
                    ) : (
                      <span className="muted-line">none</span>
                    )}
                  </td>
                  <td>
                    <IconButton
                      label={`Edit relay lists of ${profile.name}`}
                      icon={Pencil}
                      onClick={() => onEditRelay(profile)}
                    />
                  </td>
                </tr>
              );
            })}
          </Table>
        </section>
      )}

      {commandOutput && (
        <LastCommandPanel
          title="Last upstream command"
          result={commandOutput}
          onClose={onClearCommand}
        />
      )}
    </>
  );
}
