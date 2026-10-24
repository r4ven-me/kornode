import { expect, type Page, test } from "@playwright/test";
import { mockApi, signIn } from "./fixtures";

async function configSection(page: Page, section: string, mobile: boolean) {
  if (mobile) await page.getByRole("combobox", { name: "Config section", exact: true }).selectOption({ label: section });
  else await page.getByRole("navigation", { name: "Config sections" }).getByRole("button", { name: section, exact: true }).click();
}

for (const mobile of [false, true]) {
  for (const theme of ["light", "dark"]) {
    test(`Nodes-era navigation retains audit settings (${mobile ? "mobile" : "desktop"}, ${theme})`, async ({ page }) => {
      await page.setViewportSize(mobile ? { width: 390, height: 844 } : { width: 1440, height: 900 });
      await page.addInitScript(value => localStorage.setItem("kornode.theme", value), theme);
      await mockApi(page);
      await signIn(page);
      if (mobile) await page.getByRole("button", { name: "Menu", exact: true }).click();
      await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Nodes", exact: true }).click();
      await expect(page.getByRole("heading", { level: 1, name: "Nodes", exact: true })).toBeVisible();
      if (mobile) await page.getByRole("button", { name: "Menu", exact: true }).click();
      await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Config", exact: true }).click();
      await configSection(page, "System", mobile);
      await expect(page.getByLabel("Control plane port", { exact: true })).toBeVisible();
      await expect(page.getByLabel("Signing-key path (advanced deployment setting)")).toBeVisible();
      await expect(page.getByRole("button", { name: "Save control settings" })).toBeEnabled();
      await configSection(page, "Web / API", mobile);
      await expect(page.getByLabel("Current administrator password", { exact: true })).toBeVisible();
      await expect(page.getByLabel("New administrator password", { exact: true })).toBeVisible();
      await expect(page.getByLabel("Current password for two-factor changes")).toBeVisible();
      await expect(page.getByRole("button", { name: "Enable", exact: true })).toBeDisabled();
      await configSection(page, "Advanced", mobile);
      await expect(page.getByLabel("Persistent YAML source")).toBeVisible();
      await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
      expect(await page.evaluate(() => document.body.scrollWidth === document.body.clientWidth)).toBe(true);
    });
  }
}

test("stale YAML preserves the draft and requires an explicit versioned reload", async ({ page }) => {
  await mockApi(page);
  const saves: Array<{ etag: string | undefined; content: string }> = [];
  await page.route("**/api/config/source", route => {
    if (route.request().method() === "GET") return route.fallback();
    saves.push({ etag: route.request().headers()["if-match"], content: route.request().postDataJSON().content });
    return route.fulfill({ status: 412, json: { detail: "Source changed" } });
  });
  await signIn(page);
  await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Config", exact: true }).click();
  await configSection(page, "Advanced", false);
  const editor = page.getByLabel("Persistent YAML source");
  const draft = "web:\n  enabled: false\n";
  await editor.fill(draft);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Your edits are preserved" })).toBeVisible();
  await expect(editor).toHaveValue(draft);
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  expect(saves).toEqual([{ etag: '"source-1"', content: draft }]);
  page.once("dialog", dialog => dialog.accept());
  await page.getByRole("button", { name: "Reload", exact: true }).click();
  await expect(editor).toHaveValue("web:\n  enabled: true\n");
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
});
