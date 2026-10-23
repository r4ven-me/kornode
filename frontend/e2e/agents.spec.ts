import { expect, test } from "@playwright/test";
import { mockApi, signIn } from "./fixtures";

const agent = { id: 2, name: "branch-with-a-long-name", description: "Branch office", roles: ["access"], state: "active", online: true, desired_version: 8, applied_version: 7, last_seen: "2026-10-16T10:00:00Z", cert_not_after: "2027-01-01T00:00:00Z", transport: { transport: "tcp", dpd: 20, keepalive: 25, camouflage_set: true } };

for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
  for (const theme of ["light", "dark"]) {
    test(`Nodes agent detail ${viewport.width}px ${theme}: controls, overflow, focus and contrast`, async ({ page }, info) => {
      const pageErrors: string[] = [];
      page.on("pageerror", error => pageErrors.push(error.message));
      await page.setViewportSize(viewport);
      await page.addInitScript(value => localStorage.setItem("kornode.theme", value), theme);
      await mockApi(page);
      await page.route("**/api/control", route => route.fulfill({ json: { enabled: true, interlink_enabled: true, agents: 1, active: 1, signing_key_id: "public-key-id", rotation: null } }));
      await page.route("**/api/interlink", route => route.fulfill({ json: {
        interlink: { cidr: "10.99.0.0/24" },
        hub: { interlink_address: "10.99.0.1", server_name: "interlink.kornode.lan", prefixes: [] },
        nodes: [{ ...agent, interlink_address: "10.99.0.2", prefixes: [{ prefix: "10.100.2.0/24", kind: "pool", export: true }] }], sources: []
      } }));
      await page.route("**/api/agents**", route => {
        const path = new URL(route.request().url()).pathname;
        const base = "/api/agents/" + agent.name;
        const data: Record<string, unknown> = {
          "/api/agents": { agents: [agent] }, [base]: agent,
          [base + "/prefixes"]: { prefixes: [{ prefix: "10.100.2.0/24", kind: "pool", export: true }] },
          [base + "/policy"]: { policy: { sources: [], sets: {}, egress: [] } },
          [base + "/upstreams"]: { upstreams: [{ name: "office", server: "vpn.example.org", interface: "oc-office", port: 443, auth_type: "password", username: "operator", credentials_set: true }] },
          [base + "/users"]: { users: [] }, [base + "/bundles"]: { bundles: [] },
          [base + "/reports"]: { reports: [] }, [base + "/commands"]: { commands: [] }
        };
        return route.fulfill({ json: data[path] ?? {} });
      });
      await signIn(page);
      if (viewport.width < 760) await page.getByRole("button", { name: "Menu", exact: true }).click();
      await page.getByRole("button", { name: "Nodes", exact: true }).click();
      await page.getByRole("button", { name: new RegExp(agent.name + " · node 2") }).click();
      await page.getByLabel("Agent section").selectOption("upstreams");
      await expect(page.getByRole("heading", { name: "External upstreams" })).toBeVisible();
      await expect(page.getByLabel("Password", { exact: true })).toHaveAttribute("type", "password");
      const dimensions = await page.evaluate(() => ({ scroll: document.body.scrollWidth, client: document.body.clientWidth }));
      expect(dimensions.scroll).toBe(dimensions.client);
      const heights = await page.locator(".agents-view button:visible").evaluateAll(elements => elements.map(e => e.getBoundingClientRect().height));
      expect(heights.length).toBeGreaterThan(4);
      expect(Math.min(...heights)).toBeGreaterThanOrEqual(viewport.width < 760 ? 44 : 40);
      const contrast = await page.getByRole("button", { name: "Save upstream", exact: true }).evaluate(element => {
        const style = getComputedStyle(element);
        function luminance(color: string) {
          const rgb = (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map(v => { const x = v / 255; return x <= 0.04045 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); });
          return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
        }
        const a = luminance(style.color), b = luminance(style.backgroundColor);
        return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      });
      expect(contrast).toBeGreaterThanOrEqual(4.5);
      await page.getByLabel("Server", { exact: true }).focus();
      await expect(page.getByLabel("Server", { exact: true })).toBeFocused();
      await page.screenshot({ path: info.outputPath("agents-upstreams.png"), fullPage: true });
      await page.getByLabel("Agent section").selectOption("users");
      await expect(page.getByText(/Users reach the agent as password hashes/)).toBeVisible();
      await expect(page.getByRole("alert")).toHaveCount(0);
      expect(pageErrors).toEqual([]);
      await page.screenshot({ path: info.outputPath("agents-users.png"), fullPage: true });
    });
  }
}
