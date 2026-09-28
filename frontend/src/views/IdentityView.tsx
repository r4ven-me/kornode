import { Power, Save, Trash2 } from "lucide-react";
import type { FormEvent } from "react";
import type { CommandOutput, OidcDraft } from "../app/types";
import { LastCommandPanel } from "../components/CommandOutput";
import { KorclientHint } from "../components/KorclientHint";
import { SettingsTabs } from "../components/SettingsTabs";
import { Table } from "../components/Table";
import { ActionButton, IconButton, Pill } from "../components/ui";
import { splitLines } from "../lib/drafts";
import type { GroupPolicyDraft, IdentityStatus, OidcProviderDraft } from "../api";

export function IdentityView({
  identity,
  oidcDraft,
  providerDraft,
  groupDraft,
  identitySettingsDraft,
  busy,
  commandOutput,
  onClearCommand,
  onOidcDraftChange,
  onProviderDraftChange,
  onGroupDraftChange,
  onIdentitySettingsDraftChange,
  onSaveIdentitySettings,
  onSaveOidcSettings,
  onSaveProvider,
  onSaveGroup,
  onDeleteProvider,
  onDeleteGroup
}: {
  identity: IdentityStatus | null;
  oidcDraft: OidcDraft;
  providerDraft: OidcProviderDraft;
  groupDraft: GroupPolicyDraft;
  identitySettingsDraft: {
    selectGroupByUrl: boolean;
    defaultSelectGroup: string;
    defaultGroupConfig: string;
  };
  busy: string | null;
  commandOutput: CommandOutput;
  onClearCommand: () => void;
  onOidcDraftChange: (value: OidcDraft) => void;
  onProviderDraftChange: (value: OidcProviderDraft) => void;
  onGroupDraftChange: (value: GroupPolicyDraft) => void;
  onIdentitySettingsDraftChange: (value: {
    selectGroupByUrl: boolean;
    defaultSelectGroup: string;
    defaultGroupConfig: string;
  }) => void;
  onSaveIdentitySettings: () => void;
  onSaveOidcSettings: () => void;
  onSaveProvider: (event: FormEvent<HTMLFormElement>) => void;
  onSaveGroup: (event: FormEvent<HTMLFormElement>) => void;
  onDeleteProvider: (name: string) => void;
  onDeleteGroup: (name: string) => void;
}) {
  return (
    <div className="view-stack">
      <section className="panel experimental-notice" role="note">
        <div>
          <strong>Experimental feature</strong>
          <p className="muted-line">
            Identity, OIDC connectors and group-policy integration have not been validated in a
            production environment yet. Test the complete authentication flow before relying on
            this section for access control.
          </p>
        </div>
        <Pill kind="warning">Experimental</Pill>
      </section>

      <SettingsTabs ariaLabel="Identity settings">
        <details>
          <summary>Group selection</summary>
      <section className="panel">
        <div className="panel-header">
          <h2>Group routing</h2>
          <div className="toolbar">
            <Pill kind={identity?.auth.enabled ? "ok" : "muted"}>
              {identity?.auth.enabled ? `OIDC via ${identity.auth.connector}` : "OIDC disabled"}
            </Pill>
            <Pill kind="muted">
              {identity?.oidc_providers.length ?? 0} provider
              {identity?.oidc_providers.length === 1 ? "" : "s"}
            </Pill>
            <Pill kind="muted">
              {identity?.group_policies.length ?? 0} group
              {identity?.group_policies.length === 1 ? "" : "s"}
            </Pill>
          </div>
        </div>
        <div className="settings-grid">
          <label className="switch" title="Select a group policy from the connection URL path">
            <input
              checked={identitySettingsDraft.selectGroupByUrl}
              onChange={(event) =>
                onIdentitySettingsDraftChange({
                  ...identitySettingsDraft,
                  selectGroupByUrl: event.target.checked
                })
              }
              type="checkbox"
            />
            <span>Select group by URL</span>
          </label>
          <label>
            <span>Default select group</span>
            <input
              value={identitySettingsDraft.defaultSelectGroup}
              onChange={(event) =>
                onIdentitySettingsDraftChange({
                  ...identitySettingsDraft,
                  defaultSelectGroup: event.target.value
                })
              }
            />
          </label>
          <label>
            <span>Default group config</span>
            <input
              value={identitySettingsDraft.defaultGroupConfig}
              onChange={(event) =>
                onIdentitySettingsDraftChange({
                  ...identitySettingsDraft,
                  defaultGroupConfig: event.target.value
                })
              }
              placeholder="/var/lib/kornode/generated/config-per-group/default"
            />
          </label>
        </div>
        <div className="panel-footer">
          <ActionButton
            label="Save"
            icon={Save}
            primary
            busy={busy === "identity-settings"}
            onClick={onSaveIdentitySettings}
          />
        </div>
      </section>
        </details>

        <details>
          <summary>OIDC connector</summary>
      <section className="panel">
        <div className="panel-header">
          <h2>OIDC connector</h2>
        </div>
        <div className="settings-grid">
          <button
            className={`toggle-action${oidcDraft.enabled ? " active" : ""}`}
            onClick={() => onOidcDraftChange({ ...oidcDraft, enabled: !oidcDraft.enabled })}
            title="Enable external identity authentication for VPN clients"
            type="button"
          >
            <Power size={17} aria-hidden="true" />
            <span>{oidcDraft.enabled ? "Disable OIDC" : "Enable OIDC"}</span>
          </button>
          <label>
            <span>Mode</span>
            <select
              value={oidcDraft.connector}
              onChange={(event) =>
                onOidcDraftChange({
                  ...oidcDraft,
                  connector: event.target.value as typeof oidcDraft.connector
                })
              }
            >
              <option value="pam">PAM bridge</option>
              <option value="radius">RADIUS bridge</option>
            </select>
          </label>
          <label>
            <span>PAM service</span>
            <input
              value={oidcDraft.pamService}
              onChange={(event) => onOidcDraftChange({ ...oidcDraft, pamService: event.target.value })}
            />
          </label>
          <label>
            <span>PAM gid min</span>
            <input
              value={oidcDraft.pamGidMin}
              onChange={(event) => onOidcDraftChange({ ...oidcDraft, pamGidMin: event.target.value })}
            />
          </label>
          <label>
            <span>RADIUS config</span>
            <input
              value={oidcDraft.radiusConfigFile}
              onChange={(event) =>
                onOidcDraftChange({ ...oidcDraft, radiusConfigFile: event.target.value })
              }
            />
          </label>
          <label>
            <span>NAS id</span>
            <input
              value={oidcDraft.radiusNasIdentifier}
              onChange={(event) =>
                onOidcDraftChange({ ...oidcDraft, radiusNasIdentifier: event.target.value })
              }
            />
          </label>
          <label>
            <span>Group separator</span>
            <select
              value={oidcDraft.radiusGroupSeparator}
              onChange={(event) =>
                onOidcDraftChange({
                  ...oidcDraft,
                  radiusGroupSeparator: event.target.value as typeof oidcDraft.radiusGroupSeparator
                })
              }
            >
              <option value="semicolon">Semicolon</option>
              <option value="comma">Comma</option>
            </select>
          </label>
          <label className="switch" title="Pass RADIUS group attributes to ocserv as groupconfig">
            <input
              checked={oidcDraft.radiusGroupconfig}
              onChange={(event) =>
                onOidcDraftChange({ ...oidcDraft, radiusGroupconfig: event.target.checked })
              }
              type="checkbox"
            />
            <span>RADIUS groupconfig</span>
          </label>
        </div>
        <div className="panel-footer">
          <ActionButton
            label="Save"
            icon={Save}
            primary
            busy={busy === "oidc-settings"}
            onClick={onSaveOidcSettings}
          />
        </div>
      </section>
        </details>

        <details>
          <summary>Providers &amp; group policies</summary>
          <div className="view-stack">
      <section className="split">
        <section className="panel">
          <div className="panel-header">
            <h2>OIDC provider</h2>
          </div>
          <form onSubmit={onSaveProvider}>
          <div className="settings-grid">
            <label>
              <span>Name</span>
              <input
                value={providerDraft.name}
                onChange={(event) => onProviderDraftChange({ ...providerDraft, name: event.target.value })}
                required
              />
            </label>
            <label>
              <span>Issuer URL</span>
              <input
                value={providerDraft.issuer_url}
                onChange={(event) =>
                  onProviderDraftChange({ ...providerDraft, issuer_url: event.target.value })
                }
                placeholder="https://sso.example.com/realms/vpn"
                required
              />
            </label>
            <label>
              <span>Client ID</span>
              <input
                value={providerDraft.client_id}
                onChange={(event) =>
                  onProviderDraftChange({ ...providerDraft, client_id: event.target.value })
                }
                required
              />
            </label>
            <label>
              <span>Client secret</span>
              <input
                type="password"
                value={providerDraft.client_secret}
                onChange={(event) =>
                  onProviderDraftChange({ ...providerDraft, client_secret: event.target.value })
                }
              />
            </label>
            <label>
              <span>Scopes</span>
              <input
                value={providerDraft.scopes.join(" ")}
                onChange={(event) =>
                  onProviderDraftChange({
                    ...providerDraft,
                    scopes: event.target.value.split(/\s+/).filter(Boolean)
                  })
                }
              />
            </label>
            <label>
              <span>Username claim</span>
              <input
                value={providerDraft.username_claim}
                onChange={(event) =>
                  onProviderDraftChange({ ...providerDraft, username_claim: event.target.value })
                }
              />
            </label>
            <label>
              <span>Groups claim</span>
              <input
                value={providerDraft.groups_claim}
                onChange={(event) =>
                  onProviderDraftChange({ ...providerDraft, groups_claim: event.target.value })
                }
              />
            </label>
            <label>
              <span>Allowed groups</span>
              <input
                value={providerDraft.allowed_groups.join(", ")}
                onChange={(event) =>
                  onProviderDraftChange({
                    ...providerDraft,
                    allowed_groups: splitLines(event.target.value)
                  })
                }
              />
            </label>
          </div>
            <div className="panel-footer">
              <button className="primary-button" disabled={busy === "oidc-provider"} type="submit">
                <Save size={18} aria-hidden="true" />
                <span>Save</span>
              </button>
            </div>
          </form>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>
              Group policy
              <KorclientHint text="Routes and Split DNS below reach any client over the standard AnyConnect handshake, and are also synced live to connected Korvus clients (Config → Clients on the other server: “Use routes and domains pushed by the server” with a sync URL) via GET /api/client/routing — changes apply without reconnecting." />
            </h2>
          </div>
          <form onSubmit={onSaveGroup}>
          <div className="settings-grid">
            <label>
              <span>Name</span>
              <input
                value={groupDraft.name}
                onChange={(event) => onGroupDraftChange({ ...groupDraft, name: event.target.value })}
                required
              />
            </label>
            <label>
              <span>Display name</span>
              <input
                value={groupDraft.display_name}
                onChange={(event) =>
                  onGroupDraftChange({ ...groupDraft, display_name: event.target.value })
                }
              />
            </label>
            <label>
              <span>
                Routes
                <KorclientHint text="A Korvus client applies this as an nftables policy-route (kept out of the OS routing table). A stock OpenConnect client gets it as a plain pushed route instead." />
              </span>
              <textarea
                value={groupDraft.routes}
                onChange={(event) => onGroupDraftChange({ ...groupDraft, routes: event.target.value })}
                rows={3}
              />
            </label>
            <label>
              <span>No routes</span>
              <textarea
                value={groupDraft.no_routes}
                onChange={(event) =>
                  onGroupDraftChange({ ...groupDraft, no_routes: event.target.value })
                }
                rows={3}
              />
            </label>
            <label>
              <span>DNS</span>
              <textarea
                value={groupDraft.dns}
                onChange={(event) => onGroupDraftChange({ ...groupDraft, dns: event.target.value })}
                rows={2}
              />
            </label>
            <label>
              <span>
                Split DNS
                <KorclientHint text="A Korvus client resolves these through its own dnsmasq and routes the results through the tunnel automatically. A stock OpenConnect client only gets DNS-suffix scoping, with no real traffic routing." />
              </span>
              <textarea
                value={groupDraft.split_dns}
                onChange={(event) =>
                  onGroupDraftChange({ ...groupDraft, split_dns: event.target.value })
                }
                rows={2}
              />
            </label>
            <label>
              <span>Max same clients</span>
              <input
                value={groupDraft.max_same_clients}
                onChange={(event) =>
                  onGroupDraftChange({ ...groupDraft, max_same_clients: event.target.value })
                }
              />
            </label>
            <label>
              <span>Session timeout</span>
              <input
                value={groupDraft.session_timeout}
                onChange={(event) =>
                  onGroupDraftChange({ ...groupDraft, session_timeout: event.target.value })
                }
              />
            </label>
            <label>
              <span>Idle timeout</span>
              <input
                value={groupDraft.idle_timeout}
                onChange={(event) =>
                  onGroupDraftChange({ ...groupDraft, idle_timeout: event.target.value })
                }
              />
            </label>
            <label className="switch" title="Route all DNS traffic through the tunnel for this group">
              <input
                checked={groupDraft.tunnel_all_dns}
                onChange={(event) =>
                  onGroupDraftChange({ ...groupDraft, tunnel_all_dns: event.target.checked })
                }
                type="checkbox"
              />
              <span>Tunnel all DNS</span>
            </label>
            <label className="switch" title="Disable UDP/DTLS for clients in this group">
              <input
                checked={groupDraft.no_udp}
                onChange={(event) => onGroupDraftChange({ ...groupDraft, no_udp: event.target.checked })}
                type="checkbox"
              />
              <span>No UDP</span>
            </label>
          </div>
            <div className="panel-footer">
              <button className="primary-button" disabled={busy === "group-policy"} type="submit">
                <Save size={18} aria-hidden="true" />
                <span>Save</span>
              </button>
            </div>
          </form>
        </section>
      </section>

      <section className="split">
        <section className="panel">
          <Table columns={["Provider", "Issuer", "Client", "Groups", "Actions"]} empty="No providers">
            {(identity?.oidc_providers ?? []).map((provider) => (
              <tr key={provider.name}>
                <td>{provider.name}</td>
                <td>{provider.issuer_url}</td>
                <td>{provider.client_id}</td>
                <td>{provider.allowed_groups.join(", ")}</td>
                <td>
                  <IconButton
                    label="Delete provider"
                    icon={Trash2}
                    danger
                    busy={busy === `oidc-provider-delete-${provider.name}`}
                    onClick={() => onDeleteProvider(provider.name)}
                  />
                </td>
              </tr>
            ))}
          </Table>
        </section>
        <section className="panel">
          <Table columns={["Group", "Routes", "DNS", "Actions"]} empty="No group policies">
            {(identity?.group_policies ?? []).map((group) => (
              <tr key={group.name}>
                <td>{group.display_name ?? group.name}</td>
                <td>{group.routes.join(", ")}</td>
                <td>{[...group.dns, ...group.split_dns].join(", ")}</td>
                <td>
                  <IconButton
                    label="Delete group"
                    icon={Trash2}
                    danger
                    busy={busy === `group-policy-delete-${group.name}`}
                    onClick={() => onDeleteGroup(group.name)}
                  />
                </td>
              </tr>
            ))}
          </Table>
        </section>
      </section>
          </div>
        </details>
      </SettingsTabs>

      {commandOutput && (
        <LastCommandPanel title="Last identity command" result={commandOutput} onClose={onClearCommand} />
      )}
    </div>
  );
}
