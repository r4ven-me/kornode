import { afterEach, expect, it, vi } from "vitest";
import { saveGroupPolicy, saveOidcProvider, type GroupPolicyDraft, type OidcProviderDraft } from "./api";

const provider: OidcProviderDraft = { name: "sso", issuer_url: "https://sso.example.com", client_id: "vpn", client_secret: "", scopes: ["openid"], username_claim: "email", groups_claim: "groups", allowed_groups: [] };
function mockFetch() {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response("{}", { status: 200 })));
  vi.stubGlobal("fetch", fetch); return fetch;
}
afterEach(() => vi.unstubAllGlobals());

it("omits untouched OIDC secrets rather than clearing them", async () => {
  const fetch = mockFetch();
  await saveOidcProvider("session", provider);
  const sent = JSON.parse(fetch.mock.calls[0][1].body);
  expect(sent).not.toHaveProperty("client_secret");
  expect(sent).not.toHaveProperty("remove_client_secret");
});

it("sends explicit null only for OIDC removal, or a new secret for replacement", async () => {
  const fetch = mockFetch();
  await saveOidcProvider("session", { ...provider, remove_client_secret: true });
  expect(JSON.parse(fetch.mock.calls[0][1].body).client_secret).toBeNull();
  await saveOidcProvider("session", { ...provider, client_secret: "new-secret" });
  expect(JSON.parse(fetch.mock.calls[1][1].body).client_secret).toBe("new-secret");
});

it.each([null, true, false])("sends group boolean state %s without collapsing inheritance", async value => {
  const fetch = mockFetch();
  const draft: GroupPolicyDraft = { name: "devops", display_name: "", routes: "", no_routes: "", dns: "", split_dns: "", tunnel_all_dns: value, no_udp: value, max_same_clients: "", session_timeout: "", idle_timeout: "" };
  await saveGroupPolicy("session", draft);
  const sent = JSON.parse(fetch.mock.calls[0][1].body);
  expect(sent.tunnel_all_dns).toBe(value); expect(sent.no_udp).toBe(value);
});
