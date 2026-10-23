import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import { NodesView } from "./NodesView";
import { readInterlinkSettingsDraft } from "../lib/drafts";

const mocks = vi.hoisted(() => ({ get: vi.fn(), save: vi.fn() }));
vi.mock("../agentsApi", () => ({ agentGet: mocks.get }));
vi.mock("./agents/AgentsView", () => ({ AgentsView: () => <label>Agent draft<input /></label> }));
vi.mock("./agents/InterlinkDns", () => ({ InterlinkDns: ({ agents }: { agents: Array<{ name: string }> }) => <p>DNS scopes: {agents.map(a => a.name).join(", ")}</p> }));

function View({ busy = false }: { busy?: boolean }) {
  const [draft, setDraft] = useState(readInterlinkSettingsDraft({}));
  return <NodesView token="session" dryRun={false} draft={draft} onDraftChange={setDraft} busy={busy} onSave={() => mocks.save(draft)} onOpenSources={() => {}} />;
}
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mocks.get.mockResolvedValue({ agents: [{ name: "branch" }] }); });

describe("Nodes sections", () => {
  it("retains the Overview draft while visiting Settings and DNS", async () => {
    render(<View />);
    await userEvent.type(screen.getByLabelText("Agent draft"), "unsaved");
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    await userEvent.click(screen.getByRole("button", { name: "DNS" }));
    await screen.findByText("DNS scopes: branch");
    expect(mocks.get).toHaveBeenCalledWith("/api/agents", "session");
    await userEvent.click(screen.getByRole("button", { name: "Overview" }));
    expect((screen.getByLabelText("Agent draft") as HTMLInputElement).value).toBe("unsaved");
  });

  it("binds all seven addressing controls to the existing settings-save callback", async () => {
    render(<View />);
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    const fields = [["Hub node ID", "3"], ["Interlink CIDR", "10.90.0.0/24"], ["Client pool template", "10.101.{id}.0/24"], ["Source pool template", "10.9.{id}.0/24"], ["Enroll pool", "10.90.255.240/28"], ["Interlink domain", "mesh.example"], ["Reserved CIDRs (one per line)", "192.168.0.0/16\n172.16.0.0/12"]];
    for (const [name, value] of fields) fireEvent.change(screen.getByLabelText(name), { target: { value } });
    await userEvent.click(screen.getByRole("button", { name: "Save interlink settings" }));
    expect(mocks.save).toHaveBeenCalledWith({ nodeId: 3, cidr: "10.90.0.0/24", clientPool: "10.101.{id}.0/24", sourcePool: "10.9.{id}.0/24", enrollPool: "10.90.255.240/28", domain: "mesh.example", reserved: "192.168.0.0/16\n172.16.0.0/12" });
  });

  it("disables the settings form during save and reports scope-loading errors", async () => {
    mocks.get.mockRejectedValue(new Error("offline"));
    render(<View busy />);
    await userEvent.selectOptions(screen.getByLabelText("Nodes section"), "settings");
    expect(screen.getByRole("button", { name: "Save interlink settings" }).hasAttribute("disabled")).toBe(true);
    await userEvent.selectOptions(screen.getByLabelText("Nodes section"), "dns");
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("offline"));
  });
});
