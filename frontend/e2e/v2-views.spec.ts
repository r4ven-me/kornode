import { expect, type Page, test } from "@playwright/test";
import { mockApi, signIn } from "./fixtures";

const agent = { id: 2, name: "branch", description: "Branch office", roles: ["access", "gateway"], state: "active", online: true, desired_version: 8, applied_version: 8, last_seen: "2026-10-16T10:00:00Z", cert_not_after: "2027-01-01T00:00:00Z", transport: { transport: "tcp" } };
const source = { name: "wg", interface: "wg0", cidr: "10.8.1.0/24", export: true };
const policy = { sources: [source], sets: {}, egress: [{ id: "default", from: ["clients", "wg"], to: "any", via: "local" }] };
const prefixes = [{ prefix: "10.100.1.0/24", kind: "pool", export: true }];

async function mockV2(page: Page) {
  await mockApi(page);
  await page.route("**/api/control", route => route.fulfill({ json: { enabled: true, agents: 1, active: 1, signing_key_id: "key-id", rotation: null } }));
  await page.route("**/api/agents**", route => route.fulfill({ json: { agents: [agent] } }));
  await page.route("**/api/interlink", route => route.fulfill({ json: {
    interlink: { node_id: 1, cidr: "10.99.0.0/24", client_pool: "10.100.{id}.0/24", source_pool: "10.8.{id}.0/24", enroll_pool: "10.99.255.240/28", domain: "kornode.lan", reserved: [] },
    hub: { interlink_address: "10.99.0.1", server_name: "interlink.kornode.lan", prefixes },
    nodes: [{ id: 2, name: "branch", roles: ["access", "gateway"], state: "active", online: true, interlink_address: "10.99.0.2", prefixes: [{ prefix: "10.100.2.0/24", kind: "pool", export: true }] }],
    sources: [source]
  } }));
  await page.route("**/api/dns/records", route => route.fulfill({ json: { domain: "kornode.lan", records: [{ fqdn: "hub.kornode.lan", type: "A", value: "10.99.0.1", node: null, generated: true }] } }));
  await page.route("**/api/egress", route => route.fulfill({ json: { policy, warnings: [], dead_rules: [] } }));
}

async function open(page: Page, section: string, mobile: boolean) {
  if (mobile) await page.getByRole("button", { name: "Menu", exact: true }).click();
  await page.getByRole("button", { name: section, exact: true }).click();
  await expect(page.getByRole("heading", { name: section, exact: true, level: 1 })).toBeVisible();
}

async function selectNodesSection(page: Page, section: "overview" | "settings" | "dns", mobile: boolean) {
  if (mobile) await page.getByRole("combobox", { name: "Nodes section", exact: true }).selectOption(section);
  else await page.getByRole("navigation", { name: "Nodes sections" }).getByRole("button", { name: { overview: "Overview", settings: "Settings", dns: "DNS" }[section], exact: true }).click();
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
    test(`Network and Nodes ${viewport.width}px ${theme} match the panel look`, async ({ page }, info) => {
      const pageErrors: string[] = [];
      page.on("pageerror", error => pageErrors.push(error.message));
      await page.setViewportSize(viewport);
      await page.addInitScript(value => localStorage.setItem("kornode.theme", value), theme);
      await mockV2(page);
      await signIn(page);
      const mobile = viewport.width < 760;
      await page.screenshot({ path: info.outputPath("dashboard.png"), fullPage: true });
      for (const section of ["Network", "Nodes"]) {
        await open(page, section, mobile);
        if (section === "Nodes") await page.getByText("Add agent", { exact: true }).click();
        await page.screenshot({ path: info.outputPath(`${section.toLowerCase()}.png`), fullPage: true });
        await expectPanelLook(page);
      }
      for (const section of ["settings", "dns", "overview"] as const) {
        await selectNodesSection(page, section, mobile);
        await expectPanelLook(page);
        const heights = await page.locator(".nodes-view :is(button, input:not([type=checkbox]), select):visible").evaluateAll(els => els.map(e => e.getBoundingClientRect().height));
        expect(Math.min(...heights)).toBeGreaterThanOrEqual(mobile ? 44 : 40);
        await page.screenshot({ path: info.outputPath(`nodes-${section}.png`), fullPage: true });
      }
      if (mobile) {
        await page.getByRole("button", { name: "Menu", exact: true }).click();
        await expect.poll(() => page.locator(".sidebar").evaluate(el => Math.round(el.getBoundingClientRect().x))).toBe(0);
        await page.screenshot({ path: info.outputPath("mobile-navigation.png"), fullPage: true });
        await page.getByRole("button", { name: "Close menu", exact: true }).click({ position: { x: viewport.width - 10, y: 20 } });
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
  await expect(nav.getByRole("button")).toHaveText(["Dashboard", "Users", "Groups", "Sessions", "Network", "Nodes", "Config", "Diagnostics", "Logs"]);
  const icons = await nav.locator("button svg").evaluateAll(els => els.map(e => e.getAttribute("class")));
  expect(new Set(icons).size).toBe(icons.length);
  await nav.getByRole("button", { name: "Network", exact: true }).click();
  await expect(page.locator(".topbar p")).toHaveText(/Where client traffic goes/);
  await expect(page.locator(".view-stack > .panel h2").first()).toHaveText("Egress rules");
});

for (const mobile of [false, true]) {
  test(`Nodes settings use the shared save hook and keep all addressing controls (${mobile ? "mobile" : "desktop"})`, async ({ page }) => {
    if (mobile) await page.setViewportSize({ width: 390, height: 844 });
    await mockV2(page);
    let settings = { node_id: 1, cidr: "10.99.0.0/24", client_pool: "10.100.{id}.0/24", source_pool: "10.8.{id}.0/24", enroll_pool: "10.99.255.240/28", domain: "kornode.lan", reserved: [] as string[] };
    const saves: Array<{ csrf: string | undefined; body: unknown }> = [];
    await page.route("**/api/config", route => route.fulfill({ json: { node: { id: settings.node_id }, interlink: settings } }));
    await page.route("**/api/interlink", route => {
      if (route.request().method() !== "PATCH") return route.fallback();
      saves.push({ csrf: route.request().headers()["x-kornode-csrf"], body: route.request().postDataJSON() });
      settings = route.request().postDataJSON();
      return route.fulfill({ json: { status: "saved" } });
    });
    await signIn(page);
    await open(page, "Nodes", mobile);
    await selectNodesSection(page, "settings", mobile);
    await page.getByLabel("Hub node ID", { exact: true }).fill("3");
    await page.getByLabel("Interlink CIDR", { exact: true }).fill("10.90.0.0/24");
    await page.getByLabel("Client pool template", { exact: true }).fill("10.101.{id}.0/24");
    await page.getByLabel("Source pool template", { exact: true }).fill("10.9.{id}.0/24");
    await page.getByLabel("Enroll pool", { exact: true }).fill("10.90.255.240/28");
    await page.getByLabel("Interlink domain", { exact: true }).fill("mesh.example");
    await page.getByLabel("Reserved CIDRs (one per line)", { exact: true }).fill("192.168.0.0/16\n172.16.0.0/12");
    await selectNodesSection(page, "overview", mobile);
    await selectNodesSection(page, "settings", mobile);
    await expect(page.getByLabel("Interlink domain", { exact: true })).toHaveValue("mesh.example");
    await page.getByRole("button", { name: "Save interlink settings", exact: true }).click();
    await expect(page.getByText("Interlink settings saved", { exact: true })).toBeVisible();
    expect(saves).toEqual([{ csrf: "csrf", body: { node_id: 3, cidr: "10.90.0.0/24", client_pool: "10.101.{id}.0/24", source_pool: "10.9.{id}.0/24", enroll_pool: "10.90.255.240/28", domain: "mesh.example", reserved: ["192.168.0.0/16", "172.16.0.0/12"] } }]);
    await expect(page.getByLabel("Hub node ID", { exact: true })).toHaveValue("3");
    await open(page, "Config", mobile);
    if (mobile) await expect(page.getByRole("combobox", { name: /^Config section/ }).getByRole("option", { name: "Interlink", exact: true })).toHaveCount(0);
    else await expect(page.getByRole("navigation", { name: "Config sections" }).getByRole("button", { name: "Interlink", exact: true })).toHaveCount(0);
  });
}

test("Nodes settings preserve the draft and display backend refusals", async ({ page }) => {
  await mockV2(page);
  await page.route("**/api/interlink", route => route.request().method() === "PATCH" ? route.fulfill({ status: 409, json: { detail: "address plan is in use" } }) : route.fallback());
  await signIn(page);
  await open(page, "Nodes", false);
  await selectNodesSection(page, "settings", false);
  await page.getByLabel("Interlink domain", { exact: true }).fill("mesh.example");
  await page.getByRole("button", { name: "Save interlink settings", exact: true }).click();
  await expect(page.getByText(/address plan is in use/)).toBeVisible();
  await expect(page.getByLabel("Interlink domain", { exact: true })).toHaveValue("mesh.example");
  await expect(page.getByText("Interlink settings saved", { exact: true })).toHaveCount(0);
});

test("Nodes DNS keeps generated records read-only and adds/deletes agent-scoped records", async ({ page }) => {
  await mockV2(page);
  const generated = { fqdn: "hub.kornode.lan", type: "A", value: "10.99.0.1", node: null as string | null, generated: true };
  let records = [generated];
  const writes: Array<{ method: string; csrf: string | undefined; body: unknown }> = [];
  await page.route("**/api/dns/records", route => {
    const method = route.request().method();
    if (method !== "GET") {
      const body = route.request().postDataJSON();
      writes.push({ method, csrf: route.request().headers()["x-kornode-csrf"], body });
      records = method === "POST" ? [generated, { fqdn: `${body.name}.node2.kornode.lan`, type: body.type, value: body.value, node: body.node, generated: false }] : [generated];
    }
    return route.fulfill({ json: { domain: "kornode.lan", records } });
  });
  await signIn(page);
  await open(page, "Nodes", false);
  await selectNodesSection(page, "dns", false);
  await expect(page.getByText("hub.kornode.lan · A · 10.99.0.1 · generated")).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete", exact: true })).toHaveCount(0);
  await page.getByLabel("Record name (relative to the zone)").fill("nas");
  await page.getByLabel("Record value").fill("192.168.2.10");
  await page.getByRole("combobox", { name: "Record scope", exact: true }).selectOption("branch");
  await page.getByRole("button", { name: "Add record", exact: true }).click();
  await expect(page.getByText(/nas.node2.kornode.lan/)).toBeVisible();
  page.once("dialog", dialog => dialog.accept());
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByText(/nas.node2.kornode.lan/)).toHaveCount(0);
  expect(writes).toEqual(["POST", "DELETE"].map(method => ({ method, csrf: "csrf", body: { name: "nas", type: "A", value: "192.168.2.10", node: "branch" } })));
});

test("Nodes hub sources navigate to and focus the existing Network editor", async ({ page }) => {
  await mockV2(page);
  await signIn(page);
  await open(page, "Nodes", false);
  await expect(page.getByText("wg · wg0 · 10.8.1.0/24")).toBeVisible();
  await expect(page.getByLabel("Source name", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Manage hub sources in Network" }).click();
  await expect(page.getByRole("heading", { name: "Network", exact: true, level: 1 })).toBeVisible();
  const editor = page.getByRole("region", { name: "Hub sources editor" });
  await expect(editor).toBeFocused();
  await expect(editor.getByLabel("Source name", { exact: true })).toBeVisible();
  await expect(editor.getByRole("button", { name: "Save source", exact: true })).toBeVisible();
});
