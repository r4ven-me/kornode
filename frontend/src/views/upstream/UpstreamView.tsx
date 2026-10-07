import { ArrowRight, Pencil, Save } from "lucide-react";
import { type FormEvent, useState } from "react";
import { BulkListEditor } from "../../components/BulkListEditor";
import { LastCommandPanel } from "../../components/CommandOutput";
import { Table } from "../../components/Table";
import { ActionButton, IconButton, Pill } from "../../components/ui";
import { type RoutingDraft, RoutingListSourcesPanel } from "./RoutingListSourcesPanel";
import { UpstreamProfilesView } from "./UpstreamProfilesView";
import type {
  CommandResult,
  RoutingListStatus,
  UpstreamProfile,
  UpstreamStatus
} from "../../api";

type UpstreamTab = "profiles" | "routing";

// Config → Upstream: outbound OpenConnect connections this host dials as a
// client (Profiles tab -- what used to be the separate "Clients" section)
// and the policy that relays this server's VPN users' traffic through one
// of them (Routing tab -- what used to be this whole file). Merged into one
// section because both operate on the same upstream.* state, and "Clients"
// read backwards: Sessions (inbound VPN users) is the already-existing,
// correctly-named concept for "who connects to us".
export function UpstreamView({
  status,
  profiles,
  profilesBusy,
  profilesCommandOutput,
  onClearProfilesCommand,
  onSetEnabled,
  onSetProfileEnabled,
  onSwitch,
  onDeleteProfile,
  onCreateProfile,
  onEditProfile,
  onOpenSettings,
  onConnectProfile,
  onDisconnectProfile,
  onSyncProfile,
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
  onEditRelay
}: {
  status: UpstreamStatus | null;
  profiles: UpstreamProfile[];
  profilesBusy: string | null;
  profilesCommandOutput: CommandResult | CommandResult[] | null;
  onClearProfilesCommand: () => void;
  onSetEnabled: (enabled: boolean) => void;
  onSetProfileEnabled: (profile: string, enabled: boolean) => void;
  onSwitch: (profile: string) => void;
  onDeleteProfile: (profile: string) => void;
  onCreateProfile: () => void;
  onEditProfile: (profile: UpstreamProfile) => void;
  onOpenSettings: () => void;
  onConnectProfile: (profile: string) => void;
  onDisconnectProfile: (profile: string) => void;
  onSyncProfile: (profile: string) => void;
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
}) {
  const [activeTab, setActiveTab] = useState<UpstreamTab>("profiles");
  const hasProfiles = profiles.length > 0;
  const profilesEnabled = Boolean(status?.enabled);
  const defaultProfile = status?.active_profile ?? null;
  const inert = !profilesEnabled || !serverEnabled;
  const splitEnabled = routingDraft.clientPolicy === "split";
  const relaying =
    hasProfiles && profilesEnabled && serverEnabled && routingDraft.clientPolicy !== "off";

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSaveSettings();
  };

  return (
    <>
      <section className="panel">
        <div className="panel-header">
          <h2>Upstream</h2>
        </div>
        <div className="settings-tab-list" role="tablist" aria-label="Upstream">
          <button
            aria-selected={activeTab === "profiles"}
            className={activeTab === "profiles" ? "settings-tab active" : "settings-tab"}
            onClick={() => setActiveTab("profiles")}
            role="tab"
            type="button"
          >
            Profiles
          </button>
          <button
            aria-selected={activeTab === "routing"}
            className={activeTab === "routing" ? "settings-tab active" : "settings-tab"}
            onClick={() => setActiveTab("routing")}
            role="tab"
            type="button"
          >
            Routing
          </button>
        </div>
      </section>

      {activeTab === "profiles" && (
        <UpstreamProfilesView
          status={status}
          profiles={profiles}
          busy={profilesBusy}
          commandOutput={profilesCommandOutput}
          onClearCommand={onClearProfilesCommand}
          onSetEnabled={onSetEnabled}
          onSetProfileEnabled={onSetProfileEnabled}
          onSwitch={onSwitch}
          onDeleteProfile={onDeleteProfile}
          onCreateProfile={onCreateProfile}
          onEditProfile={onEditProfile}
          onOpenSettings={onOpenSettings}
          onConnectProfile={onConnectProfile}
          onDisconnectProfile={onDisconnectProfile}
          onSyncProfile={onSyncProfile}
        />
      )}

      {activeTab === "routing" && (
        <>
          <section className="panel">
            <div className="panel-header">
              <h2>Routing</h2>
              <div className="toolbar">
                <Pill kind={relaying ? "ok" : "muted"}>
                  {relaying && defaultProfile ? `Relaying via ${defaultProfile}` : "Not relaying"}
                </Pill>
              </div>
            </div>
            <p className="muted-line">
              Sends the traffic of this server&rsquo;s VPN users onward through one of the
              Upstream profiles. The connections themselves, failover and health checks are
              managed in the Profiles tab.
            </p>
            {!hasProfiles ? (
              <div className="upstream-empty">
                <p>
                  Upstream needs at least one profile: create the outbound connection it should
                  relay through first.
                </p>
                <ActionButton
                  label="Go to Profiles"
                  icon={ArrowRight}
                  primary
                  onClick={() => setActiveTab("profiles")}
                />
              </div>
            ) : (
              <form className="upstream-settings-form" onSubmit={submit}>
                {!serverEnabled && (
                  <p className="muted-line">
                    <Pill kind="warning">VPN server disabled</Pill> There are no VPN users to relay
                    while the server is off (Config → Server).
                  </p>
                )}
                {!profilesEnabled && (
                  <p className="muted-line">
                    <Pill kind="warning">Profiles disabled</Pill> Turn on upstream profiles to
                    relay through them.
                  </p>
                )}
                <p className="muted-line">
                  {defaultProfile
                    ? `Default profile: ${defaultProfile} (change it in the Profiles tab). `
                    : "No default profile selected yet (pick one in the Profiles tab). "}
                  A profile&rsquo;s own relay lists below always win over this default.
                </p>
                <label>
                  <span>Relay VPN users&rsquo; traffic through the default profile</span>
                  <select
                    disabled={inert}
                    value={routingDraft.clientPolicy}
                    onChange={(event) =>
                      onRoutingDraftChange({ ...routingDraft, clientPolicy: event.target.value })
                    }
                  >
                    <option value="off">Off (VPN users stay on plain NAT)</option>
                    <option value="full">Full (all traffic via Upstream)</option>
                    <option value="split">Split (only listed traffic via Upstream)</option>
                  </select>
                </label>
                {splitEnabled && (
                  <div className="routing-substep">
                    <p className="muted-line">
                      Domains below are resolved through this server&rsquo;s own DNS, pushed to
                      VPN users automatically (Config → DNS has the resolver&rsquo;s other
                      settings).
                    </p>
                    <section className="split">
                      <BulkListEditor
                        title="Routes"
                        items={routes}
                        placeholder={"10.20.0.0/16\n203.0.113.5"}
                        busy={busy === "save-routes"}
                        disabled={inert}
                        onSave={onSaveRoutes}
                      />
                      <BulkListEditor
                        title="Domains"
                        items={domains}
                        placeholder={"internal.example\ncorp.example.com"}
                        busy={busy === "save-domains"}
                        disabled={inert}
                        onSave={onSaveDomains}
                      />
                    </section>
                    <section className="split">
                      <RoutingListSourcesPanel
                        title="Route sources"
                        urlsLabel="Route URLs (one per line)"
                        urlsPlaceholder={"https://lists.example.com/routes.txt"}
                        disabled={inert}
                        urlsText={routingDraft.routesUrlsText}
                        status={routesStatus}
                        busy={busy}
                        busyKeyPrefix="routes"
                        onUrlsTextChange={(value) =>
                          onRoutingDraftChange({ ...routingDraft, routesUrlsText: value })
                        }
                        onPreviewUrl={onPreviewRoutesUrl}
                        onRefreshUrl={onRefreshRoutesUrl}
                      />
                      <RoutingListSourcesPanel
                        title="Domain sources"
                        urlsLabel="Domain URLs (one per line)"
                        urlsPlaceholder={"https://lists.example.com/domains.txt"}
                        disabled={inert}
                        urlsText={routingDraft.domainsUrlsText}
                        status={domainsStatus}
                        busy={busy}
                        busyKeyPrefix="domains"
                        onUrlsTextChange={(value) =>
                          onRoutingDraftChange({ ...routingDraft, domainsUrlsText: value })
                        }
                        onPreviewUrl={onPreviewDomainsUrl}
                        onRefreshUrl={onRefreshDomainsUrl}
                      />
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

          {hasProfiles && (
            <section className="panel">
              <div className="panel-header">
                <h2>Relay lists per profile</h2>
              </div>
              <p className="muted-line">
                Send specific destinations of VPN users through a specific profile, whichever
                profile is the default.
              </p>
              <Table columns={["Profile", "Relay lists", "Actions"]} empty="No profiles yet">
                {profiles.map((profile) => {
                  const relayOn = Boolean(profile.route_clients_enabled);
                  const routeCount = profile.routes?.length ?? 0;
                  const domainCount = profile.domains?.length ?? 0;
                  return (
                    <tr key={profile.name}>
                      <td className="strong-cell">
                        <div className="inline-tools">
                          <span>{profile.name}</span>
                          {profile.name === defaultProfile && <Pill kind="ok">Default</Pill>}
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
              title="Last routing command"
              result={commandOutput}
              onClose={onClearCommand}
            />
          )}
        </>
      )}
    </>
  );
}
