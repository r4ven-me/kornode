import { describe, expect, it } from "vitest";
import { readServerSettingsDraft } from "./drafts";

describe("server settings draft", () => {
  it("accepts VPN clients unless the hub is control-only", () => {
    expect(readServerSettingsDraft({}).clients).toBe(true);
    expect(readServerSettingsDraft({ server: { clients: true } }).clients).toBe(true);
    expect(readServerSettingsDraft({ server: { clients: false } }).clients).toBe(false);
  });
});
