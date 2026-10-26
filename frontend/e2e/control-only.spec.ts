import { expect, test } from "@playwright/test";
import { mockApi, signIn } from "./fixtures";

// D-100: a hub with server.clients: false serves agents only, so the VPN-user sections go away.
test("a control-only hub hides Users, Groups and Sessions and says so", async ({ page }) => {
  await mockApi(page, { config: { server: { enabled: true, clients: false } } });
  await signIn(page);
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav.getByRole("button", { name: "Nodes", exact: true })).toBeVisible();
  for (const hidden of ["Users", "Groups", "Sessions"]) {
    await expect(nav.getByRole("button", { name: hidden, exact: true })).toHaveCount(0);
  }
  await expect(page.getByText("Control-only", { exact: true })).toBeVisible();
});

test("a normal hub keeps the access sections", async ({ page }) => {
  await mockApi(page);
  await signIn(page);
  const nav = page.getByRole("navigation", { name: "Primary" });
  for (const shown of ["Users", "Groups", "Sessions"]) {
    await expect(nav.getByRole("button", { name: shown, exact: true })).toBeVisible();
  }
});
