import { afterEach, expect, it, vi } from "vitest";
import { ApiError, fetchConfigSource, saveConfigSource } from "./api";

afterEach(() => vi.unstubAllGlobals());

it("round-trips the source ETag through If-Match and receives the saved version", async () => {
  const source = { path: "/config.yaml", exists: true, content: "server: {}\n", etag: '"version-one"' };
  const saved = { ...source, etag: '"version-two"', content: "server: {enabled: false}\n", config: {}, written: [], valid: true };
  const fetch = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify(source), { status: 200, headers: { ETag: source.etag } }))
    .mockResolvedValueOnce(new Response(JSON.stringify(saved), { status: 200, headers: { ETag: saved.etag } }));
  vi.stubGlobal("fetch", fetch);
  const loaded = await fetchConfigSource("session");
  const result = await saveConfigSource("session", saved.content, true, loaded.etag);
  const [path, init] = fetch.mock.calls[1] as [string, RequestInit];
  expect(path).toBe("/api/config/source");
  expect(new Headers(init.headers).get("If-Match")).toBe(source.etag);
  expect(JSON.parse(String(init.body))).toEqual({ content: saved.content, write_rendered: true });
  expect(result.etag).toBe(saved.etag);
});

it("refuses an unversioned source save before sending a request", async () => {
  const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
  await expect(saveConfigSource("session", "draft", true, "")).rejects.toMatchObject({ status: 428 });
  expect(fetch).not.toHaveBeenCalled();
});

it.each([412, 428])("preserves HTTP status %s for explicit source-conflict handling", async status => {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "Reload source first" }), { status }));
  vi.stubGlobal("fetch", fetch);
  await expect(saveConfigSource("session", "draft", true, '"old-version"')).rejects.toBeInstanceOf(ApiError);
});
