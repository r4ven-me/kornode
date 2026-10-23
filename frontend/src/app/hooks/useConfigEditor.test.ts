import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiError, type ConfigSource } from "../../api";
import type { Hydrator, PanelCore } from "../core";
import { useConfigEditor } from "./useConfigEditor";

const mocks = vi.hoisted(() => ({ source: vi.fn(), save: vi.fn(), validate: vi.fn(), diff: vi.fn() }));
vi.mock("../../api", async importOriginal => {
  const original = await importOriginal<typeof import("../../api")>();
  return { ...original, fetchConfigSource: mocks.source, saveConfigSource: mocks.save, validateConfigSource: mocks.validate, fetchConfigDiff: mocks.diff };
});
const first: ConfigSource = { path: "/config.yaml", content: "first YAML", exists: true, etag: '"v1"' };
const latest: ConfigSource = { ...first, content: "latest YAML", etag: '"v2"' };
const saved = { ...first, content: "saved YAML", etag: '"v3"', written: [], config: {}, valid: true };
beforeEach(() => { vi.clearAllMocks(); mocks.save.mockResolvedValue(saved); mocks.source.mockResolvedValue(latest); });
afterEach(cleanup);

function editor() {
  let hydrate: Hydrator = () => {};
  const core = {
    authToken: "session", loadAll: vi.fn().mockResolvedValue(undefined), setState: vi.fn(),
    registerHydrator: (_key: string, next: Hydrator) => { hydrate = next; },
    runAction: async (_key: string, _success: string, action: (token: string) => Promise<unknown>) => {
      try { return await action("session"); } catch { return null; }
    }
  };
  const hook = renderHook(() => useConfigEditor(core as unknown as PanelCore));
  act(() => hydrate({ configSource: first }));
  return { ...hook, core, hydrate: (source: ConfigSource) => act(() => hydrate({ configSource: source })) };
}

it("keeps the draft's ETag when a background refresh loads newer source", async () => {
  const { result, hydrate, core } = editor();
  act(() => result.current.editDraft("unsaved YAML"));
  hydrate(latest);
  expect(result.current.configDraft).toBe("unsaved YAML");
  await act(() => result.current.save());
  expect(mocks.save).toHaveBeenCalledWith("session", "unsaved YAML", true, first.etag);
  expect(result.current.configDraft).toBe("saved YAML");
  expect(result.current.configDirty).toBe(false);
  const update = core.setState.mock.calls[0][0];
  expect(update({}).configSource.etag).toBe(saved.etag);
  act(() => result.current.editDraft("next draft"));
  await act(() => result.current.save());
  expect(mocks.save).toHaveBeenLastCalledWith("session", "next draft", true, saved.etag);
});

it.each([412, 428])("preserves edits on %s, warns explicitly, and only reloads after confirmation", async status => {
  const { result, core } = editor();
  act(() => result.current.editDraft("keep my draft"));
  mocks.save.mockRejectedValueOnce(new ApiError(status, "version mismatch"));
  await act(() => result.current.save());
  expect(result.current.configDraft).toBe("keep my draft");
  expect(result.current.configDirty).toBe(true);
  expect(result.current.configConflict).toContain("Your edits are preserved");
  expect(core.loadAll).not.toHaveBeenCalled(); expect(core.setState).not.toHaveBeenCalled();
  expect(mocks.source).not.toHaveBeenCalled(); expect(mocks.save).toHaveBeenCalledOnce();
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  await act(() => result.current.reloadSource());
  expect(mocks.source).not.toHaveBeenCalled(); expect(result.current.configDraft).toBe("keep my draft");
  confirm.mockReturnValue(true);
  await act(() => result.current.reloadSource());
  expect(mocks.source).toHaveBeenCalledWith("session");
  expect(result.current.configDraft).toBe("latest YAML");
  expect(result.current.configConflict).toBe(""); expect(result.current.configDirty).toBe(false);
  act(() => result.current.editDraft("reconciled draft"));
  await act(() => result.current.save());
  expect(mocks.save).toHaveBeenLastCalledWith("session", "reconciled draft", true, latest.etag);
});

it("keeps the draft and conflict warning if explicitly requested reload fails", async () => {
  const { result } = editor();
  act(() => result.current.editDraft("keep this"));
  mocks.save.mockRejectedValueOnce(new ApiError(412, "stale"));
  await act(() => result.current.save());
  vi.spyOn(window, "confirm").mockReturnValue(true);
  mocks.source.mockRejectedValueOnce(new Error("network unavailable"));
  await act(() => result.current.reloadSource());
  expect(result.current.configDraft).toBe("keep this");
  expect(result.current.configDirty).toBe(true);
  expect(result.current.configConflict).toContain("Your edits are preserved");
});
