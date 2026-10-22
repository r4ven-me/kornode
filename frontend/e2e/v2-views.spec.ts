import { expect, type Page, test } from "@playwright/test";
import { mockApi, signIn } from "./fixtures";

const agent = { id: 2, name: "branch", description: "Branch office", roles: ["access", "exit"], state: "active", online: true, desired_version: 8, applied_version: 8, last_seen: "2026-10-16T10:00:00Z", cert_not_after: "2027-01-01T00:00:00Z", transport: { transport: "tcp" } };
const source = { name: "wg", interface: "wg0", cidr: "10.8.1.0/24", export: true };
const policy = { sources: [source], sets: {}, egress: [{ id: "default", from: ["clients", "wg"], to: "any", via: "local" }] };
const prefixes = [{ prefix: "10.100.1.0/24", kind: "pool", export: true }];

async function mockV2(page: Page) {
  await mockApi(page);
  await page.route("**/api/control", route => route.fulfill({ json: { enabled: true, agents: 1, active: 1, signing_key_id: "key-id", rotation: null } }));
  await page.route("**/api/agents**", route => route.fulfill({ json: { agents: [agent] } }));
  await page.route("**/api/fabric", route => route.fulfill({ json: {
    fabric: { node_id: 1, cidr: "10.99.0.0/24", client_pool: "10.100.{id}.0/24", source_pool: "10.8.{id}.0/24", enroll_pool: "10.99.255.240/28", domain: "kornode.internal", reserved: [] },
    hub: { fabric_address: "10.99.0.1", server_name: "fabric.kornode.internal", prefixes },
    nodes: [{ id: 2, name: "branch", roles: ["access", "exit"], state: "active", online: true, fabric_address: "10.99.0.2", prefixes: [{ prefix: "10.100.2.0/24", kind: "pool", export: true }] }],
    sources: [source]
  } }));
  await page.route("**/api/dns/records", route => route.fulfill({ json: { domain: "kornode.internal", records: [{ fqdn: "hub.kornode.internal", type: "A", value: "10.99.0.1", node: null, generated: true }] } }));
  await page.route("**/api/egress", route => route.fulfill({ json: { policy, warnings: [], dead_rules: [] } }));
}

async function open(page: Page, section: string, mobile: boolean) {
  if (mobile) await page.getByRole("button", { name: "Menu", exact: true }).click();
  await page.getByRole("button", { name: section, exact: true }).click();
  await expect(page.getByRole("heading", { name: section, exact: true, level: 1 })).toBeVisible();
}

/** The v2 views share the panel look: no browser-default fieldset frames, list bullets or native checkboxes. */
async function expectPanelLook(page: Page) {
  const frames = await page.locator("main fieldset").evaluateAll(els => els.map(e => getComputedStyle(e).borderTopStyle));
  expect(frames.every(style => style === "none")).toBe(true);
  const bullets = await page.locator(".agent-items, .agent-list").evaluateAll(els => els.map(e => getComputedStyle(e).listStyleType));
  expect(bullets.every(style => style === "none")).toBe(true);
  const checks = await page.locator("main input[type=checkbox]").evaluateAll(els => els.map(e => getComputedStyle(e).appearance));
  expect(checks.every(value => value === "none")).toBe(true);
  const dimensions = await page.evaluate(() => ({ scroll: document.body.scrollWidth, client: document.body.clientWidth }));
  expect(dimensions.scroll).toBe(dimensions.client);
  // The workspace clips horizontal overflow, so check that nothing sticks out of its panel (tables scroll inside .table-wrap).
  const outside = await page.evaluate(() => Array.from(document.querySelectorAll(".view-stack > .panel")).flatMap(panel => {
    const right = panel.getBoundingClientRect().right;
    return Array.from(panel.querySelectorAll("*")).filter(e => !e.closest(".table-wrap") && e.getBoundingClientRect().right > right + 1).map(e => `${e.tagName}.${e.className}`);
  }));
  expect(outside).toEqual([]);
}

for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
  for (const theme of ["light", "dark"]) {
    test(`Network, Fabric and Agents ${viewport.width}px ${theme} match the panel look`, async ({ page }, info) => {
      const pageErrors: string[] = [];
      page.on("pageerror", error => pageErrors.push(error.message));
      await page.setViewportSize(viewport);
      await page.addInitScript(value => localStorage.setItem("kornode.theme", value), theme);
      await mockV2(page);
      await signIn(page);
      const mobile = viewport.width < 760;
      for (const section of ["Network", "Fabric", "Agents"]) {
        await open(page, section, mobile);
        if (section === "Agents") await page.getByText("Add agent").click();
        await page.screenshot({ path: info.outputPath(`${section.toLowerCase()}.png`), fullPage: true });
        await expectPanelLook(page);
      }
      expect(pageErrors).toEqual([]);
    });
  }
}

test("the sidebar groups sections by task and explains the open one", async ({ page }) => {
  await mockV2(page);
  await signIn(page);
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav.locator(".nav-group-label")).toHaveText(["Access", "Routing", "System"]);
  await expect(nav.getByRole("button")).toHaveText(["Dashboard", "Users", "Groups", "Sessions", "Network", "Agents", "Fabric", "Config", "Diagnostics", "Logs"]);
  const icons = await nav.locator("button svg").evaluateAll(els => els.map(e => e.getAttribute("class")));
  expect(new Set(icons).size).toBe(icons.length);
  await nav.getByRole("button", { name: "Network", exact: true }).click();
  await expect(page.locator(".topbar p")).toHaveText(/Where client traffic goes/);
  await expect(page.locator(".view-stack > .panel h2").first()).toHaveText("Egress rules");
});
