import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InterlinkDns, type ZoneRecord } from "./InterlinkDns";
import type { Agent } from "../../agentsApi";

const mocks = vi.hoisted(() => ({ get: vi.fn(), write: vi.fn() }));
vi.mock("../../agentsApi", () => ({ agentGet: mocks.get, agentWrite: mocks.write }));
const agent: Agent = { id: 3, name: "branch", description: "", roles: [], state: "active", online: true, desired_version: 1, applied_version: 1, last_seen: null, cert_not_after: null, transport: {} };
const records: ZoneRecord[] = [
  { fqdn: "hub.kornode.lan", type: "A", value: "10.100.1.1", node: "hub", generated: true },
  { fqdn: "cam.node3.kornode.lan", type: "A", value: "192.168.3.7", node: "branch", generated: false }
];
const zone = { enabled: true, domain: "kornode.lan", records };

afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mocks.get.mockResolvedValue(zone); mocks.write.mockResolvedValue(zone); });

describe("Interlink DNS", () => {
  it("lists generated and stored records; only stored ones can be deleted", async () => {
    render(<InterlinkDns token="session" agents={[agent]} />);
    await screen.findByText(/cam\.node3\.kornode\.lan/);
    expect(screen.getAllByRole("button", { name: "Delete" })).toHaveLength(1);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(mocks.write).toHaveBeenCalledWith("/api/dns/records", "DELETE", { name: "cam", type: "A", value: "192.168.3.7", node: "branch" }, "session");
  });

  it("adds a node-scoped record and shows backend refusals", async () => {
    render(<InterlinkDns token="session" agents={[agent]} />);
    await screen.findByText(/hub\.kornode\.lan/);
    await userEvent.type(screen.getByLabelText("Record name (relative to the zone)"), "nas");
    await userEvent.type(screen.getByLabelText("Record value"), "192.168.3.10");
    await userEvent.selectOptions(screen.getByLabelText("Record scope"), "branch");
    await userEvent.click(screen.getByRole("button", { name: "Add record" }));
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/dns/records", "POST", { name: "nas", type: "A", value: "192.168.3.10", node: "branch" }, "session"));
    mocks.write.mockRejectedValueOnce(new Error("hub, node<N> are generated names"));
    await userEvent.type(screen.getByLabelText("Record name (relative to the zone)"), "hub");
    await userEvent.type(screen.getByLabelText("Record value"), "10.0.0.1");
    await userEvent.click(screen.getByRole("button", { name: "Add record" }));
    expect((await screen.findByRole("alert")).textContent).toContain("generated names");
  });
});
