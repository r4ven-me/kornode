import {
  CheckCircle2,
  Pencil,
  Plus,
  Power,
  RadioTower,
  Settings,
  Star,
  Trash2,
  Unplug
} from "lucide-react";
import { LastCommandPanel } from "../../components/CommandOutput";
import { Table } from "../../components/Table";
import { ActionButton, IconButton, Pill } from "../../components/ui";
import { formatDuration } from "../../lib/format";
import type { CommandResult, UpstreamProfile, UpstreamStatus } from "../../api";

// Config → Upstream → Profiles: the outbound OpenConnect connections
// themselves (config key upstream.profiles). Which traffic leaves through a
// profile is declared as egress, see views/network/HubEgress.tsx.
export function UpstreamProfilesView({
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
  onDisconnectProfile
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
    <section className="panel upstream-profiles-panel" data-capability="upstream.status">
      <div className="panel-header">
        <h2>Upstream profiles</h2>
        <div className="toolbar">
          <Pill kind={enabled ? "ok" : "muted"}>{enabled ? "Profiles enabled" : "Profiles disabled"}</Pill>
          <ActionButton label="Settings" icon={Settings} onClick={onOpenSettings} data-capability="upstream.settings" />
          <ActionButton
            label={enabled ? "Disable" : "Enable"}
            icon={Power}
            primary={!enabled}
            danger={enabled}
            disabled={!enabled && !hasProfile}
            busy={busy === "upstream-settings"}
            onClick={() => onSetEnabled(!enabled)}
            data-capability={enabled ? "upstream.disconnect" : "upstream.connect"}
          />
          <ActionButton label="Add profile" icon={Plus} onClick={onCreateProfile} data-capability="upstream.profile.save" />
        </div>
      </div>
      <p className="muted-line">
        Outbound OpenConnect connections from this host to other VPN servers. Which traffic
        leaves through a profile is set under Network → Hub egress.
      </p>
      <div data-capability="upstream.list">
      <Table
        columns={["Name", "Server", "Interface", "Status", "Actions"]}
        empty="No profiles yet"
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
              <td>
                {profile.kind === "external_interface"
                  ? "externally managed"
                  : `${profile.server}:${profile.port}`}
              </td>
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
                <div className="toolbar">
                  {profileConnected ? (
                    <IconButton
                      label={
                        profile.kind === "external_interface"
                          ? "Tear down routing (interface stays untouched)"
                          : "Disconnect"
                      }
                      icon={profile.kind === "external_interface" ? RadioTower : Unplug}
                      busy={busy === `upstream-profile-disconnect-${profile.name}`}
                      onClick={() => onDisconnectProfile(profile.name)}
                      data-capability="upstream.profile.disconnect"
                    />
                  ) : (
                    <IconButton
                      label={
                        profile.kind === "external_interface"
                          ? "Apply routing (interface stays untouched)"
                          : "Connect"
                      }
                      icon={RadioTower}
                      disabled={!profile.enabled}
                      busy={busy === `upstream-profile-connect-${profile.name}`}
                      onClick={() => onConnectProfile(profile.name)}
                      data-capability="upstream.profile.connect"
                    />
                  )}
                  <IconButton
                    label={isDefault ? "Default profile" : "Make default profile"}
                    icon={isDefault ? CheckCircle2 : Star}
                    disabled={isDefault || !profile.enabled}
                    busy={busy === `switch-${profile.name}`}
                    onClick={() => onSwitch(profile.name)}
                    data-capability="upstream.switch"
                  />
                  <span data-capability="upstream.profile.enable">
                  <span data-capability="upstream.profile.disable">
                  <IconButton
                    label={
                      profile.enabled
                        ? "Disable profile (stop watchdog, disconnect)"
                        : "Enable profile (let watchdog dial it)"
                    }
                    icon={Power}
                    danger={profile.enabled}
                    busy={busy === `upstream-profile-enabled-${profile.name}`}
                    onClick={() => onSetProfileEnabled(profile.name, !profile.enabled)}
                    data-capability={profile.enabled ? "upstream.profile.disable" : "upstream.profile.enable"}
                  />
                  </span>
                  </span>
                  <IconButton
                    label="Edit profile"
                    icon={Pencil}
                    onClick={() => onEditProfile(profile)}
                  />
                  <IconButton
                    label="Delete profile"
                    icon={Trash2}
                    danger
                    busy={busy === `upstream-profile-delete-${profile.name}`}
                    onClick={() => onDeleteProfile(profile.name)}
                    data-capability="upstream.profile.delete"
                  />
                </div>
              </td>
            </tr>
          );
        })}
      </Table>
      </div>
      {commandOutput && (
        <LastCommandPanel
          title="Last upstream profile command"
          result={commandOutput}
          onClose={onClearCommand}
        />
      )}
    </section>
  );
}
