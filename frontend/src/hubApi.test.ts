import { afterEach, expect, it, vi } from "vitest";
import { setCsrfToken } from "./api";
import { createHubBackup, restoreHub } from "./hubApi";

afterEach(() => { setCsrfToken(null); vi.unstubAllGlobals(); });

it("adds CSRF and no-store to encrypted backup downloads", async () => {
  const mock = vi.fn().mockResolvedValue(new Response("ciphertext"));
  vi.stubGlobal("fetch", mock); setCsrfToken("csrf-token");
  await createHubBackup("private-passphrase");
  const [path, init] = mock.mock.calls[0] as [string, RequestInit];
  expect(path).toBe("/api/hub/backup"); expect(init.cache).toBe("no-store");
  expect(new Headers(init.headers).get("X-Kornode-CSRF")).toBe("csrf-token");
  expect(init.credentials).toBe("same-origin");
});

it("uploads ciphertext and encodes Unicode passphrases outside the URL", async () => {
  const mock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ staged: true })));
  vi.stubGlobal("fetch", mock); setCsrfToken("csrf-token");
  const file = new File(["ciphertext"], "hub.knbackup");
  const password = "private-passphrase-δοκιμή";
  await restoreHub(file, password, false);
  const [path, init] = mock.mock.calls[0] as [string, RequestInit];
  expect(path).toBe("/api/hub/restore?dry_run=false&confirm=restore");
  expect(path).not.toContain(password); expect(init.body).toBe(file);
  const headers = new Headers(init.headers);
  expect(headers.get("X-Kornode-CSRF")).toBe("csrf-token");
  expect(new TextDecoder().decode(Uint8Array.from(atob(headers.get("X-Kornode-Backup-Passphrase")!), c => c.charCodeAt(0)))).toBe(password);
});
