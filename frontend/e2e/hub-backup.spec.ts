import { expect, test } from "@playwright/test";
import { mockApi, signIn } from "./fixtures";

for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
  for (const theme of ["light", "dark"]) {
    test(`Hub backup ${viewport.width}px ${theme}: recovery flow and layout`, async ({ page }, info) => {
      const errors: string[] = [];
      page.on("pageerror", error => errors.push(error.message));
      await page.setViewportSize(viewport);
      await page.addInitScript(value => localStorage.setItem("kornode.theme", value), theme);
      await mockApi(page);
      const restores: string[] = [];
      await page.route("**/api/hub/backup", route => {
        expect(route.request().headers()["x-kornode-csrf"]).toBe("csrf");
        return route.fulfill({ body: "encrypted-backup", contentType: "application/octet-stream" });
      });
      await page.route("**/api/hub/restore**", route => {
        const dry = new URL(route.request().url()).searchParams.get("dry_run") === "true";
        restores.push(dry ? "validate" : "stage");
        expect(route.request().headers()["x-kornode-csrf"]).toBe("csrf");
        return route.fulfill({ json: { dry_run: dry, staged: !dry, files: 21, created_at: "2026-10-16T10:00:00Z", target: "/var/lib/kornode/restores/hub-test", config_path: "/var/lib/kornode/restores/hub-test/config.yaml", restart_required: true, warning: "Stop the old hub before activation." } });
      });
      await signIn(page);
      if (viewport.width < 760) await page.getByRole("button", { name: "Menu", exact: true }).click();
      await page.getByRole("button", { name: "Config", exact: true }).click();
      if (viewport.width < 760) await page.getByRole("combobox", { name: "Config section", exact: true }).selectOption("backup");
      else await page.getByRole("button", { name: "Backup / Restore", exact: true }).click();
      const password = "private-backup-passphrase";
      await page.getByLabel("Backup passphrase", { exact: true }).fill(password);
      await page.getByLabel("Confirm backup passphrase").fill(password);
      const downloaded = page.waitForEvent("download");
      await page.getByRole("button", { name: "Download encrypted backup" }).click();
      expect((await downloaded).suggestedFilename()).toContain(".knbackup");
      await expect(page.getByLabel("Backup passphrase", { exact: true })).toHaveValue("");
      await page.getByLabel("Encrypted archive").setInputFiles({ name: "hub.knbackup", mimeType: "application/octet-stream", buffer: Buffer.from("encrypted-backup") });
      await page.getByLabel("Restore passphrase").fill(password);
      await page.getByRole("button", { name: "Validate archive" }).click();
      await expect(page.getByText(/Archive validated: 21 files/)).toBeVisible();
      await expect(page.getByLabel("Restore passphrase")).toHaveValue("");
      await page.getByLabel("Restore passphrase").fill(password);
      await page.getByLabel("I understand this stages a restore, not a live switch").check();
      const dangerContrast = await page.getByRole("button", { name: "Stage hub restore" }).evaluate(element => {
        const style = getComputedStyle(element);
        const context = document.createElement("canvas").getContext("2d")!;
        const lum = (color: string) => {
          context.fillStyle = color; context.fillRect(0, 0, 1, 1);
          const c = Array.from(context.getImageData(0, 0, 1, 1).data).slice(0, 3).map(v => { const x = v / 255; return x <= .04045 ? x / 12.92 : ((x + .055) / 1.055) ** 2.4; });
          return c[0] * .2126 + c[1] * .7152 + c[2] * .0722;
        };
        const a = lum(style.color), b = lum(style.backgroundColor);
        return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
      });
      expect(dangerContrast).toBeGreaterThanOrEqual(4.5);
      await page.screenshot({ path: info.outputPath("hub-backup-confirmation.png"), fullPage: true });
      await page.getByRole("button", { name: "Stage hub restore" }).click();
      await expect(page.getByText(/Restore staged. Live hub unchanged/)).toBeVisible();
      expect(restores).toEqual(["validate", "stage"]);
      expect(await page.evaluate(() => document.body.scrollWidth - document.body.clientWidth)).toBe(0);
      const heights = await page.locator(".hub-backup button:visible").evaluateAll(elements => elements.map(e => e.getBoundingClientRect().height));
      expect(Math.min(...heights)).toBeGreaterThanOrEqual(viewport.width < 760 ? 44 : 40);
      const contrast = await page.getByRole("button", { name: "Download encrypted backup" }).evaluate(element => {
        const style = getComputedStyle(element);
        const context = document.createElement("canvas").getContext("2d")!;
        const lum = (color: string) => {
          context.fillStyle = color; context.fillRect(0, 0, 1, 1);
          const c = Array.from(context.getImageData(0, 0, 1, 1).data).slice(0, 3).map(v => { const x = v / 255; return x <= .04045 ? x / 12.92 : ((x + .055) / 1.055) ** 2.4; });
          return c[0] * .2126 + c[1] * .7152 + c[2] * .0722;
        };
        const a = lum(style.color), b = lum(style.backgroundColor);
        return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
      });
      expect(contrast).toBeGreaterThanOrEqual(4.5);
      await page.getByLabel("Restore passphrase").focus();
      await expect(page.getByLabel("Restore passphrase")).toBeFocused();
      await expect(page.getByRole("alert")).toHaveCount(0);
      expect(errors).toEqual([]);
      await page.screenshot({ path: info.outputPath("hub-backup-restore.png"), fullPage: true });
    });
  }
}
