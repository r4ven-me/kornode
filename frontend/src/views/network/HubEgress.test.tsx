import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HubEgress } from "./HubEgress";

const mocks = vi.hoisted(() => ({ get: vi.fn(), write: vi.fn() }));
vi.mock("../../agentsApi", () => ({ agentGet: mocks.get, agentWrite: mocks.write }));
const shown = {
  policy: { sources: [{ name: "wg", interface: "wg0", cidr: "10.8.1.0/24", export: true }], sets: {}, egress: [{ from: ["clients"], to: "any", via: "local" }] },
  warnings: []
};

afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mocks.get.mockResolvedValue(shown); mocks.write.mockResolvedValue(shown); });

describe("Hub egress", () => {
  it("lists sources and removes one after confirmation", async () => {
    render(<HubEgress token="session" />);
    await screen.findByText(/wg · wg0/);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(mocks.write).toHaveBeenCalledWith("/api/sources/wg", "DELETE", undefined, "session");
  });

  it("adds a source", async () => {
    render(<HubEgress token="session" />);
    await screen.findByText(/wg · wg0/);
    await userEvent.type(screen.getByLabelText("Source name"), "amnezia");
    await userEvent.type(screen.getByLabelText("Source interface"), "awg0");
    await userEvent.type(screen.getByLabelText("Source CIDR"), "10.8.2.0/24");
    await userEvent.click(screen.getByRole("button", { name: "Save source" }));
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/sources/amnezia", "PUT", { interface: "awg0", cidr: "10.8.2.0/24", export: true }, "session"));
  });

  it("checks and saves the policy and shows backend refusals", async () => {
    render(<HubEgress token="session" />);
    await screen.findByText(/wg · wg0/);
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/egress/check", "POST", shown.policy, "session"));
    mocks.write.mockRejectedValueOnce(new Error("exit:9 needs an active agent with role exit"));
    await userEvent.click(screen.getByRole("button", { name: "Save policy" }));
    expect((await screen.findByRole("alert")).textContent).toContain("exit:9");
  });
});
