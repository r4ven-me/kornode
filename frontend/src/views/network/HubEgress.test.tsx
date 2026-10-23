import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/sources/amnezia", "PUT", { interface: "awg0", cidr: "10.8.2.0/24", export: true, allow_outside_pool: false, description: "" }, "session"));
  });

  it("edits and clears source pool override and description explicitly", async () => {
    mocks.get.mockResolvedValue({ ...shown, policy: { ...shown.policy, sources: [{ ...shown.policy.sources[0], allow_outside_pool: true, description: "Old description" }] } });
    render(<HubEgress token="session" />);
    await screen.findByText(/wg · wg0/);
    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    const override = screen.getByLabelText("Allow outside derived source pool") as HTMLInputElement;
    expect(override.checked).toBe(true);
    await userEvent.click(override);
    await userEvent.clear(screen.getByLabelText("Source description"));
    await userEvent.click(screen.getByRole("button", { name: "Save source" }));
    expect(mocks.write).toHaveBeenCalledWith("/api/sources/wg", "PUT", { interface: "wg0", cidr: "10.8.1.0/24", export: true, allow_outside_pool: false, description: "" }, "session");
  });

  it("saves structured destination lists through the whole-policy endpoint", async () => {
    const corp = { routes: ["10.1.0.0/16"], domains: ["corp.example.com"], route_urls: ["https://example.com/routes"], domain_urls: ["https://example.com/domains"] };
    mocks.get.mockResolvedValue({ ...shown, policy: { ...shown.policy, sets: { corp } } });
    render(<HubEgress token="session" />);
    const routes = await screen.findByLabelText("Set corp routes");
    fireEvent.change(routes, { target: { value: "10.2.0.0/16" } });
    await userEvent.click(screen.getByRole("button", { name: "Save policy" }));
    expect(mocks.write).toHaveBeenCalledWith("/api/egress", "PUT", { ...shown.policy, sets: { corp: { ...corp, routes: ["10.2.0.0/16"] } } }, "session");
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

  const two = {
    policy: { sources: [], sets: {}, egress: [{ from: ["clients"], to: "any", via: "local" }, { from: ["clients"], to: { set: "corp" }, via: "drop" }] },
    warnings: ["rule 1 is shadowed by rule 0"],
    dead_rules: [{ rule: 1, shadowed_by: 0 }]
  };

  it("marks dead rules inline from the structured findings", async () => {
    mocks.get.mockResolvedValue(two);
    render(<HubEgress token="session" />);
    const row = await screen.findByTestId("egress-rule-1");
    expect(row.textContent).toContain("fully covered by rule #1");
    expect(screen.getByTestId("egress-rule-0").textContent).not.toContain("Dead rule");
  });

  it("reorders with the buttons and saves the new order", async () => {
    mocks.get.mockResolvedValue(two);
    render(<HubEgress token="session" />);
    await screen.findByTestId("egress-rule-1");
    await userEvent.click(screen.getByRole("button", { name: "Move rule 2 up" }));
    await userEvent.click(screen.getByRole("button", { name: "Save policy" }));
    const sent = mocks.write.mock.calls.find(call => call[1] === "PUT")?.[2] as { egress: { via: string }[] };
    expect(sent.egress.map(rule => rule.via)).toEqual(["drop", "local"]);
  });

  it("reorders by dragging a rule onto another", async () => {
    mocks.get.mockResolvedValue(two);
    render(<HubEgress token="session" />);
    const first = await screen.findByTestId("egress-rule-0");
    const second = screen.getByTestId("egress-rule-1");
    const dataTransfer = { setData: vi.fn() };
    fireEvent.dragStart(second, { dataTransfer });
    fireEvent.dragOver(first, { dataTransfer });
    fireEvent.drop(first, { dataTransfer });
    await userEvent.click(screen.getByRole("button", { name: "Save policy" }));
    const sent = mocks.write.mock.calls.find(call => call[1] === "PUT")?.[2] as { egress: { via: string }[] };
    expect(sent.egress.map(rule => rule.via)).toEqual(["drop", "local"]);
  });

  it("adds a rule built from the form fields and checks the draft in the background", async () => {
    render(<HubEgress token="session" />);
    await screen.findByText(/wg · wg0/);
    await userEvent.click(screen.getByRole("button", { name: "Add rule" }));
    await userEvent.selectOptions(screen.getByLabelText("Rule 2 to kind"), "set");
    await userEvent.type(screen.getByLabelText("Rule 2 to value"), "corp");
    await userEvent.selectOptions(screen.getByLabelText("Rule 2 via kind"), "exit");
    await userEvent.type(screen.getByLabelText("Rule 2 via target"), "3");
    const expected = { from: ["clients"], to: { set: "corp" }, via: "exit:3" };
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/egress/check", "POST", { ...shown.policy, egress: [...shown.policy.egress, expected] }, "session"));
    expect(screen.getByRole("button", { name: "Save source" }).closest("fieldset")?.disabled).toBe(true);
  });

  it("explains a flow against the saved policy and highlights the matching rule", async () => {
    mocks.get.mockResolvedValue(two);
    mocks.write.mockResolvedValue({ from_class: "clients", matched_rule: { index: 1 }, implicit: null, mark: null, table: 2, route: "default dev oc0", nat: null, kernel_check: null, warnings: [] });
    render(<HubEgress token="session" />);
    await screen.findByTestId("egress-rule-1");
    await userEvent.type(screen.getByLabelText("Explain destination"), "203.0.113.5");
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/net/explain", "POST", { src: "host", dst: "203.0.113.5" }, "session"));
    expect((await screen.findByTestId("egress-rule-1")).textContent).toContain("matches here");
  });

  it("keeps the JSON editor as an advanced mode in sync with the rules", async () => {
    render(<HubEgress token="session" />);
    await screen.findByText(/wg · wg0/);
    await userEvent.click(screen.getByRole("tab", { name: "JSON (advanced)" }));
    const area = screen.getByLabelText(/Policy \(JSON/) as HTMLTextAreaElement;
    expect(JSON.parse(area.value)).toEqual(shown.policy);
    fireEvent.change(area, { target: { value: JSON.stringify({ ...shown.policy, egress: [] }) } });
    await userEvent.click(screen.getByRole("tab", { name: "Rules" }));
    expect(screen.queryByTestId("egress-rule-0")).toBeNull();
  });
});
