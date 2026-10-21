import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FabricView } from "./FabricView";

const mocks = vi.hoisted(() => ({ get: vi.fn(), write: vi.fn() }));
vi.mock("../../agentsApi", () => ({ agentGet: mocks.get, agentWrite: mocks.write }));
const fabric = {
  fabric: { cidr: "10.99.0.0/24", client_pool: "10.100.{id}.0/24", source_pool: "10.8.{id}.0/24", enroll_pool: "10.99.255.240/28", domain: "kornode.internal", reserved: [] },
  hub: { fabric_address: "10.99.0.1", server_name: "fabric.kornode.internal", prefixes: [] },
  nodes: [{ id: 2, name: "alpha", roles: ["exit"], state: "active", online: true, fabric_address: "10.99.0.2", prefixes: [{ prefix: "192.168.50.0/24", kind: "lan", export: true }] }],
  sources: [{ name: "wg", interface: "wg0", cidr: "10.8.1.0/24", export: true }]
};

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  mocks.get.mockImplementation((path: string) => Promise.resolve(path === "/api/fabric" ? fabric : { domain: "kornode.internal", records: [] }));
  mocks.write.mockResolvedValue({});
});

describe("Fabric view", () => {
  it("shows the topology with prefixes and hub sources", async () => {
    render(<FabricView token="session" />);
    await screen.findByText(/alpha · 10\.99\.0\.2 · active · online · exit · 192\.168\.50\.0\/24/);
    expect(screen.getByText(/hub · 10\.99\.0\.1 · fabric\.kornode\.internal/)).toBeTruthy();
    expect(screen.getByText(/wg · wg0 · 10\.8\.1\.0\/24/)).toBeTruthy();
  });

  it("saves settings through PATCH /api/fabric and shows refusals", async () => {
    render(<FabricView token="session" />);
    const domain = await screen.findByLabelText("Fabric domain");
    await userEvent.clear(domain);
    await userEvent.type(domain, "mesh.example");
    await userEvent.click(screen.getByRole("button", { name: "Save fabric settings" }));
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/fabric", "PATCH", expect.objectContaining({ domain: "mesh.example" }), "session"));
    await screen.findByText("Fabric settings saved.");
    mocks.write.mockRejectedValueOnce(new Error("invalid cidr"));
    await userEvent.click(screen.getByRole("button", { name: "Save fabric settings" }));
    await screen.findByText("invalid cidr");
  });
});
