import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InterlinkView } from "./InterlinkView";
import type { Agent } from "../../agentsApi";

const mocks = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("../../agentsApi", () => ({ agentGet: mocks.get }));
const agent: Agent = { id: 2, name: "alpha", description: "", roles: ["gateway"], state: "active", online: true, desired_version: 8, applied_version: 7, last_seen: null, cert_not_after: null, transport: {} };
const interlink = {
  interlink: { cidr: "10.99.0.0/24" },
  hub: { interlink_address: "10.99.0.1", server_name: "interlink.kornode.lan", prefixes: [] },
  nodes: [{ ...agent, interlink_address: "10.99.0.2", prefixes: [{ prefix: "192.168.50.0/24", kind: "lan", export: true }] }],
  sources: [{ name: "wg", interface: "wg0", cidr: "10.8.1.0/24", export: false }]
};
const props = { token: "session", agents: [agent], selected: null, busy: false, loading: false, onSelect: vi.fn(), onOpenSources: vi.fn() };

afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mocks.get.mockResolvedValue(interlink); });

describe("Nodes topology", () => {
  it("shows hub, prefixes, sources and agent versions with working navigation", async () => {
    render(<InterlinkView {...props} />);
    await screen.findByText("10.99.0.2 · 192.168.50.0/24");
    expect(screen.getByText("Hub · 10.99.0.1")).toBeTruthy();
    expect(screen.getByText("wg · wg0 · 10.8.1.0/24 · not exported")).toBeTruthy();
    expect(screen.getByText("desired 8 / reported 7")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: /alpha · node 2/ }));
    expect(props.onSelect).toHaveBeenCalledWith("alpha");
    await userEvent.click(screen.getByRole("button", { name: "Manage hub sources in Network" }));
    expect(props.onOpenSources).toHaveBeenCalledOnce();
  });

  it("keeps agent management reachable when the topology request fails", async () => {
    mocks.get.mockRejectedValue(new Error("unavailable"));
    render(<InterlinkView {...props} />);
    expect((await screen.findByRole("alert")).textContent).toContain("Topology unavailable");
    await userEvent.click(screen.getByRole("button", { name: /alpha · node 2/ }));
    expect(props.onSelect).toHaveBeenCalledWith("alpha");
  });

  it("shows an empty fleet without hiding the hub", async () => {
    render(<InterlinkView {...props} agents={[]} />);
    await screen.findByText("Hub · 10.99.0.1");
    expect(screen.getByText("No agents registered yet.")).toBeTruthy();
  });
});
