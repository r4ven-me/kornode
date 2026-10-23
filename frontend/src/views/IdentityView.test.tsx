import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ComponentProps, useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { IdentityView } from "./IdentityView";
import inventory from "../configFieldInventory.json";
import type { GroupPolicyDraft, OidcProviderDraft, IdentityStatus } from "../api";
import { readOidcDraft } from "../lib/drafts";

afterEach(cleanup);
const identity: IdentityStatus = {
  auth: { enabled: false, connector: "pam", pam: { service: "ocserv", gid_min: 1000 }, radius: { config_file: "/etc/radius.conf", groupconfig: true, nas_identifier: null, group_separator: "semicolon" } },
  oidc_providers: [{ name: "sso", issuer_url: "https://sso.example.com", client_id: "vpn", scopes: ["openid"], username_claim: "email", groups_claim: "groups", allowed_groups: [] }],
  group_policies: [{ name: "devops", display_name: null, routes: [], no_routes: [], dns: [], split_dns: [], tunnel_all_dns: null, no_udp: false, max_same_clients: null, session_timeout: null, idle_timeout: null }],
  config_per_group_dir: null, select_group_by_url: false, default_select_group: null, default_group_config: null
};
const group: GroupPolicyDraft = { name: "new", display_name: "", routes: "", no_routes: "", dns: "", split_dns: "", tunnel_all_dns: null, no_udp: null, max_same_clients: "", session_timeout: "", idle_timeout: "" };

function Editor() {
  const [groupDraft, setGroup] = useState(group);
  const [providerDraft, setProvider] = useState<OidcProviderDraft>({ ...identity.oidc_providers[0], client_secret: "" });
  const props: ComponentProps<typeof IdentityView> = {
    identity, groupDraft, providerDraft, onGroupDraftChange: setGroup, onProviderDraftChange: setProvider,
    oidcDraft: readOidcDraft(identity), identitySettingsDraft: { selectGroupByUrl: false, defaultSelectGroup: "", defaultGroupConfig: "" },
    busy: null, commandOutput: null, onClearCommand: vi.fn(), onOidcDraftChange: vi.fn(), onIdentitySettingsDraftChange: vi.fn(), onSaveIdentitySettings: vi.fn(), onSaveOidcSettings: vi.fn(), onSaveProvider: event => event.preventDefault(), onSaveGroup: event => event.preventDefault(), onDeleteProvider: vi.fn(), onDeleteGroup: vi.fn()
  };
  return <IdentityView {...props} />;
}

it("offers inherit/yes/no group booleans and loads existing null/false without coercion", async () => {
  render(<Editor />);
  await userEvent.click(screen.getByRole("tab", { name: "Providers & group policies" }));
  const dns = screen.getByLabelText("Tunnel all DNS") as HTMLSelectElement;
  const udp = screen.getByLabelText("No UDP") as HTMLSelectElement;
  expect(dns.value).toBe("inherit"); expect(udp.value).toBe("inherit");
  await userEvent.selectOptions(dns, "true"); expect(dns.value).toBe("true");
  await userEvent.selectOptions(dns, "false"); expect(dns.value).toBe("false");
  await userEvent.selectOptions(dns, "inherit"); expect(dns.value).toBe("inherit");
  await userEvent.click(screen.getByRole("button", { name: "Edit group devops" }));
  expect(dns.value).toBe("inherit"); expect(udp.value).toBe("false");
});

it("matches the scoped nullable-group inventory and exact save marker", async () => {
  const { container } = render(<Editor />);
  await userEvent.click(screen.getByRole("tab", { name: "Providers & group policies" }));
  const model = inventory.models.find(item => item.name === "GroupPolicyConfig")! as unknown as {
    surfaces: Array<{ marker: string }>;
    fields: Record<string, { binding: string; label: string; states: Array<{ value: string; label: string; model_value: boolean | null }> }>;
  };
  const form = container.querySelector(`form[data-capability="${model.surfaces[0].marker}"]`)!;
  expect(form).toBeTruthy();
  expect(form.querySelector(`button[data-capability="${model.surfaces[0].marker}"]`)).toBeTruthy();
  for (const field of Object.values(model.fields)) {
    if (!field || !("states" in field)) continue;
    const select = screen.getByLabelText(field.label!) as HTMLSelectElement;
    expect(form.contains(select)).toBe(true);
    expect(select.dataset.configField).toBe(field.binding);
    expect(Array.from(select.options, option => ({ value: option.value, label: option.label })))
      .toEqual(field.states!.map(state => ({ value: state.value, label: state.label })));
    for (const state of field.states!) {
      await userEvent.selectOptions(select, state.value);
      expect(select.value).toBe(state.value);
    }
  }
});

it("makes OIDC secret removal explicit and resets removal when editing a provider", async () => {
  render(<Editor />);
  await userEvent.click(screen.getByRole("tab", { name: "Providers & group policies" }));
  const secret = screen.getByLabelText("Client secret") as HTMLInputElement;
  expect(secret.placeholder).toBe("Blank preserves saved secret");
  await userEvent.click(screen.getByLabelText("Remove saved client secret"));
  expect(secret.disabled).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Edit provider sso" }));
  expect(secret.disabled).toBe(false); expect(secret.value).toBe("");
});
