import {
  CheckCircle2,
  Pencil,
  Plus,
  Power,
  RadioTower,
  RefreshCw,
  Settings,
  Star,
  Trash2,
  Unplug
} from "lucide-react";
import { LastCommandPanel } from "../../components/CommandOutput";
import { Table } from "../../components/Table";
import { ActionButton, IconButton, Pill } from "../../components/ui";
import { formatDuration } from "../../lib/format";
import type { CommandResult, ServerRouting, UpstreamProfile, UpstreamStatus } from "../../api";

// Config → Clients: the outbound OpenConnect connections themselves (what
// used to be "upstream profiles", config key upstream.profiles) and the
// host's own traffic through them. Relaying VPN users' traffic through a
// client is the separate Upstream section.
export function ClientsView({
  status,
  profiles,
  busy,
  commandOutput,
  onClearCommand,
  onSetEnabled,
  onSetProfileEnabled,
  onSwitch,
  onDeleteProfile,
  onCreateProfile,
  onEditProfile,
  onOpenSettings,
  onConnectProfile,
  onDisconnectProfile,
  onSyncProfile
}: {
  status: UpstreamStatus | null;
  profiles: UpstreamProfile[];
  busy: string | null;
  commandOutput: CommandResult | CommandResult[] | null;
  onClearCommand: () => void;
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
}) {
  const enabled = Boolean(status?.enabled);
  const hasProfile = profiles.length > 0;
  const activeProfile = status?.active_profile ?? null;
  const connectionFor = (name: string) =>
    status?.connections.find((connection) => connection.profile === name);
  const connectedNames = new Set(
    (status?.connections ?? [])
      .filter((connection) => connection.connected)
      .map((connection) => connection.profile)
  );
  // Default profile first, then whatever else is currently connected, then
  // the rest in the order they were added -- Array.sort is stable, so a
  // rank-only comparator preserves each group's original relative order.
  const rank = (profile: UpstreamProfile) => {
    if (profile.name === activeProfile) {
      return 0;
    }
    return connectedNames.has(profile.name) ? 1 : 2;
  };
  const sortedProfiles = [...profiles].sort((a, b) => rank(a) - rank(b));

  return (
    <section className="panel upstream-profiles-panel">
      <div className="panel-header">
        <h2>Clients</h2>
        <div className="toolbar">
          <Pill kind={enabled ? "ok" : "muted"}>{enabled ? "Clients enabled" : "Clients disabled"}</Pill>
          <ActionButton label="Settings" icon={Settings} onClick={onOpenSettings} />
          <ActionButton
            label={enabled ? "Disable" : "Enable"}
            icon={Power}
            primary={!enabled}
            danger={enabled}
            disabled={!enabled && !hasProfile}
            busy={busy === "upstream-settings"}
            onClick={() => onSetEnabled(!enabled)}
          />
          <ActionButton label="Create client" icon={Plus} onClick={onCreateProfile} />
        </div>
      </div>
      <p className="muted-line">
        Outbound OpenConnect connections from this host to other VPN servers. A client can
        carry this host&rsquo;s own traffic (host routing, optionally with the routes and
        split-DNS domains the server pushes) and serve as the Upstream for this
        server&rsquo;s VPN users.
      </p>
      <Table
        columns={["Name", "Server", "Interface", "Status", "Server lists", "Actions"]}
        empty="No clients yet"
      >
        {sortedProfiles.map((profile) => {
          const connection = connectionFor(profile.name);
          const profileConnected = Boolean(connection?.connected);
          const isDefault = profile.name === activeProfile;
          return (
            <tr key={profile.name}>
              <td className="strong-cell">
                <div className="inline-tools">
                  <span>{profile.name}</span>
                  {isDefault && <Pill kind="ok">Default</Pill>}
                </div>
              </td>
              <td>{`${profile.server}:${profile.port}`}</td>
              <td>{connection?.interface ?? profile.interface ?? "auto"}</td>
              <td>
                <div className="upstream-status-cell">
                  {!profile.enabled ? (
                    <Pill kind="muted">disabled</Pill>
                  ) : profileConnected ? (
                    <Pill kind="ok">connected</Pill>
                  ) : (
                    <Pill kind="muted">down</Pill>
                  )}
                  {profileConnected && (
                    <>
                      <span className="muted-line">
                        {`Internal ${connection?.local_ip ?? "-"} / External ${connection?.remote ?? "-"}`}
                      </span>
                      <span className="muted-line">
                        {`Connected for ${formatDuration(connection?.connected_for_seconds ?? null)}`}
                      </span>
                      {connection?.connected_since && (
                        <span
                          className="muted-line"
                          title="This timestamp resets when the OpenConnect process reconnects or restarts."
                        >
                          {`Since ${new Date(connection.connected_since).toLocaleString()}`}
                        </span>
                      )}
                    </>
                  )}
                </div>
              </td>
              <td>
                <ServerRoutingCell
                  routing={connection?.server_routing}
                  canSync={Boolean(profile.sync_url) && profileConnected}
                  busy={busy === `upstream-profile-sync-${profile.name}`}
                  onSync={() => onSyncProfile(profile.name)}
                />
              </td>
              <td>
                <div className="toolbar">
                  {profileConnected ? (
                    <IconButton
                      label="Disconnect"
                      icon={Unplug}
                      busy={busy === `upstream-profile-disconnect-${profile.name}`}
                      onClick={() => onDisconnectProfile(profile.name)}
                    />
                  ) : (
                    <IconButton
                      label="Connect"
                      icon={RadioTower}
                      disabled={!profile.enabled}
                      busy={busy === `upstream-profile-connect-${profile.name}`}
                      onClick={() => onConnectProfile(profile.name)}
                    />
                  )}
                  <IconButton
                    label={isDefault ? "Default client" : "Make default client"}
                    icon={isDefault ? CheckCircle2 : Star}
                    disabled={isDefault || !profile.enabled}
                    busy={busy === `switch-${profile.name}`}
                    onClick={() => onSwitch(profile.name)}
                  />
                  <IconButton
                    label={
                      profile.enabled
                        ? "Disable client (stop watchdog, disconnect)"
                        : "Enable client (let watchdog dial it)"
                    }
                    icon={Power}
                    danger={profile.enabled}
                    busy={busy === `upstream-profile-enabled-${profile.name}`}
                    onClick={() => onSetProfileEnabled(profile.name, !profile.enabled)}
                  />
                  <IconButton
                    label="Edit client"
                    icon={Pencil}
                    onClick={() => onEditProfile(profile)}
                  />
                  <IconButton
                    label="Delete client"
                    icon={Trash2}
                    danger
                    busy={busy === `upstream-profile-delete-${profile.name}`}
                    onClick={() => onDeleteProfile(profile.name)}
                  />
                </div>
              </td>
            </tr>
          );
        })}
      </Table>
      {commandOutput && (
        <LastCommandPanel title="Last clients command" result={commandOutput} onClose={onClearCommand} />
      )}
    </section>
  );
}

function ServerRoutingCell({
  routing,
  canSync,
  busy,
  onSync
}: {
  routing: ServerRouting | undefined;
  canSync: boolean;
  busy: boolean;
  onSync: () => void;
}) {
  if (!routing?.accept) {
    return <span className="muted-line">not used</span>;
  }
  const received = routing.routes.length + routing.domains.length > 0;
  return (
    <div className="upstream-status-cell">
      {!routing.active ? (
        <Pill kind="warning">host routing off</Pill>
      ) : received ? (
        <Pill kind="ok">{routing.source === "sync" ? "synced" : "received"}</Pill>
      ) : (
        <Pill kind="muted">nothing received</Pill>
      )}
      <span
        className="muted-line"
        title={[...routing.routes, ...routing.domains].join("\n") || undefined}
      >
        {`${routing.routes.length} routes / ${routing.domains.length} domains`}
      </span>
      {routing.sync_error && (
        <span className="muted-line" title={routing.sync_error}>
          sync failed
        </span>
      )}
      {routing.warnings.map((warning) => (
        <span key={warning} className="muted-line" title={warning}>
          {`⚠ ${warning}`}
        </span>
      ))}
      {canSync && (
        <IconButton label="Sync server lists now" icon={RefreshCw} busy={busy} onClick={onSync} />
      )}
    </div>
  );
}
