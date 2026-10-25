import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NetworkView } from "./NetworkView";

const mocks = vi.hoisted(() => ({ get: vi.fn(), write: vi.fn(), plan: vi.fn(), status: vi.fn(), apply: vi.fn(), explain: vi.fn() }));
vi.mock("../agentsApi", () => ({ agentGet: mocks.get, agentWrite: mocks.write }));
vi.mock("../api", () => ({ fetchNetPlan: mocks.plan, fetchNetStatus: mocks.status, applyNetPlan: mocks.apply, explainNetPolicy: mocks.explain }));

const shown = {
  policy: { sources: [{ name: "wg", interface: "wg0", cidr: "10.8.1.0/24", export: true }], sets: {}, egress: [{ from: ["clients"], to: "any", via: "local" }] },
  warnings: []
};
const plan = { exits: [], warnings: [], ops: [], schema_hash: null };
const explanation = { from_class: "host", matched_rule: null, implicit: "No rule matched.", mark: null, table: null, route: null, nat: null, kernel_check: null, warnings: [] };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.get.mockResolvedValue(shown);
  mocks.write.mockResolvedValue(shown);
  mocks.plan.mockResolvedValue(plan);
  mocks.status.mockResolvedValue({ running: true, passes: 3, drift: {} });
  mocks.apply.mockResolvedValue({ ...plan, applied: false, dry_run: true });
  mocks.explain.mockResolvedValue(explanation);
});
afterEach(cleanup);

async function openDiagnostics() {
  await userEvent.click(screen.getByRole("button", { name: "Kernel diagnostics" }));
  return screen.getByRole("region", { name: "Kernel diagnostics" });
}

describe("Networks hub tasks", () => {
  it("starts with hub editing and only loads kernel diagnostics when requested", async () => {
    render(<NetworkView token="session" />);
    await screen.findByText(/wg · wg0/);
    expect(screen.getByRole("navigation", { name: "Network tasks" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Hub policy & sources" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("heading", { name: "Egress rules" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Kernel sync status" })).toBeNull();
    expect(mocks.plan).not.toHaveBeenCalled();
    expect(mocks.status).not.toHaveBeenCalled();

    const diagnostics = await openDiagnostics();
    expect(within(diagnostics).getByRole("heading", { name: "Preview & apply network plan" })).toBeTruthy();
    expect(within(diagnostics).getByRole("heading", { name: "Explain a packet" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Egress rules" })).toBeNull();
    expect(screen.getByRole("button", { name: "Kernel diagnostics" }).getAttribute("aria-pressed")).toBe("true");
    await waitFor(() => expect(mocks.plan).toHaveBeenCalledWith("session"));
    expect(mocks.status).toHaveBeenCalledWith("session");
    expect(mocks.apply).not.toHaveBeenCalled();
  });

  it("preserves structured policy and source drafts across navigation, including keyboard navigation", async () => {
    render(<NetworkView token="session" />);
    await screen.findByText(/wg · wg0/);
    await userEvent.type(screen.getByLabelText("Source name"), "amnezia");
    await userEvent.click(screen.getByRole("button", { name: "Add rule" }));
    await openDiagnostics();
    const policyButton = screen.getByRole("button", { name: "Hub policy & sources" });
    policyButton.focus();
    await userEvent.keyboard("{Enter}");
    expect((screen.getByLabelText("Source name") as HTMLInputElement).value).toBe("amnezia");
    expect(screen.getByTestId("egress-rule-1")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Save policy" })).toBeTruthy();
    expect(mocks.get).toHaveBeenCalledTimes(1);
    expect(mocks.write.mock.calls.some(call => call[1] === "PUT")).toBe(false);
  });

  it("preserves the advanced JSON draft when inspecting diagnostics", async () => {
    render(<NetworkView token="session" />);
    await screen.findByText(/wg · wg0/);
    await userEvent.click(screen.getByRole("tab", { name: "JSON (advanced)" }));
    const draft = JSON.stringify({ ...shown.policy, egress: [] });
    fireEvent.change(screen.getByLabelText(/Policy \(JSON/), { target: { value: draft } });
    await openDiagnostics();
    await userEvent.click(screen.getByRole("button", { name: "Hub policy & sources" }));
    expect((screen.getByLabelText(/Policy \(JSON/) as HTMLTextAreaElement).value).toBe(draft);
  });

  it("opens and focuses sources from a deep link, including after leaving diagnostics", async () => {
    const scroll = vi.fn();
    const original = HTMLElement.prototype.scrollIntoView;
    HTMLElement.prototype.scrollIntoView = scroll;
    try {
      const { rerender } = render(<NetworkView token="session" focus="sources" />);
      expect(document.activeElement).toBe(screen.getByRole("region", { name: "Hub sources editor" }));
      expect(scroll).toHaveBeenCalledWith({ block: "start" });
      await openDiagnostics();
      rerender(<NetworkView token="session" />);
      rerender(<NetworkView token="session" focus="sources" />);
      await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("region", { name: "Hub sources editor" })));
      expect(screen.queryByRole("heading", { name: "Kernel sync status" })).toBeNull();
      expect(screen.getByRole("button", { name: "Hub policy & sources" }).getAttribute("aria-pressed")).toBe("true");
    } finally {
      HTMLElement.prototype.scrollIntoView = original;
    }
  });

  it("keeps dry run, apply and packet explain calls unchanged in diagnostics", async () => {
    render(<NetworkView token="session" />);
    const diagnostics = await openDiagnostics();
    await within(diagnostics).findByText("Running");
    await userEvent.click(within(diagnostics).getByRole("button", { name: "Dry run" }));
    await within(diagnostics).findByText("Dry run completed.");
    expect(mocks.apply).toHaveBeenCalledWith("session", true);
    await userEvent.click(within(diagnostics).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(mocks.apply).toHaveBeenCalledWith("session", false));
    fireEvent.change(within(diagnostics).getByRole("textbox", { name: /^Destination/ }), { target: { value: " 203.0.113.5 " } });
    await userEvent.click(within(diagnostics).getByRole("button", { name: "Explain" }));
    await within(diagnostics).findByText("No rule matched.");
    expect(mocks.explain).toHaveBeenCalledWith("session", "host", "203.0.113.5");
  });

  it("keeps a diagnostics failure separate from the hub editor", async () => {
    mocks.plan.mockRejectedValue(new Error("Kernel inspection unavailable"));
    render(<NetworkView token="session" />);
    await openDiagnostics();
    expect((await screen.findByRole("alert")).textContent).toContain("Kernel inspection unavailable");
    await userEvent.click(screen.getByRole("button", { name: "Hub policy & sources" }));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("button", { name: "Save policy" })).toBeTruthy();
  });
});
