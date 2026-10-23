import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentsView } from "./AgentsView";
import { AgentActivity } from "./AgentActivity";
import type { Agent, AgentCommand, Detail } from "../../agentsApi";

const mocks = vi.hoisted(() => ({ get: vi.fn(), write: vi.fn(), detail: vi.fn(), download: vi.fn() }));
vi.mock("../../agentsApi", () => ({
  agentGet: mocks.get, agentWrite: mocks.write, loadAgent: mocks.detail, downloadAgentArtifact: mocks.download,
  agentPath: (name: string, suffix = "") => `/api/agents/${encodeURIComponent(name)}${suffix}`
}));
const agent: Agent = { id: 2, name: "branch", description: "", roles: ["access"], state: "pending", online: false, desired_version: 0, applied_version: 0, last_seen: null, cert_not_after: null, transport: {} };
const detail: Detail = { agent, prefixes: [], policy: {}, upstreams: [], users: [], bundles: [], reports: [], commands: [], access: { configured: false } };
const status = { enabled: true, agents: 0, active: 0, rotation: null, signing_key_id: "public-id" };
const interlink = { interlink: { cidr: "10.99.0.0/24" }, hub: { interlink_address: "10.99.0.1", server_name: "hub.example", prefixes: [] }, nodes: [], sources: [] };

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear();
  mocks.get.mockImplementation((path: string) => Promise.resolve(path === "/api/control" ? status : path === "/api/interlink" ? interlink : { agents: [] }));
  mocks.detail.mockResolvedValue(detail);
  mocks.write.mockResolvedValue({ agent, token: "sensitive-one-time-token" });
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", { configurable: true, value() { this.setAttribute("open", ""); } });
});

describe("Agent management", () => {
  it("configures the access listener of an access agent", async () => {
    mocks.get.mockImplementation((path: string) => Promise.resolve(path === "/api/control" ? status : path === "/api/interlink" ? interlink : path === "/api/agents" ? { agents: [agent] } : { records: [] }));
    render(<AgentsView token="session" />);
    await userEvent.click(await screen.findByRole("button", { name: /branch · node 2/ }));
    await userEvent.selectOptions(await screen.findByLabelText("Agent section"), "users");
    expect(screen.getByText("Not configured: the agent runs no VPN server.")).not.toBeNull();
    await userEvent.type(screen.getByLabelText("Listener hostname or IP"), "vpn.branch.example");
    await userEvent.click(screen.getByRole("button", { name: "Save access listener" }));
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/agents/branch/access", "PUT", { hostname: "vpn.branch.example", port: 443, udp: false, reissue: false }, "session"));
  });

  it("creates an agent, reveals token only in ephemeral dialog, and forgets it on close", async () => {
    render(<AgentsView token="session" />);
    await screen.findByText("No agents registered yet.");
    await userEvent.click(screen.getByText("Add agent"));
    await userEvent.type(screen.getByLabelText("Agent name"), "branch");
    await userEvent.click(screen.getByRole("button", { name: "Create agent and token" }));
    await screen.findByRole("dialog");
    const field = screen.getByLabelText("Enrollment token") as HTMLInputElement;
    expect(field.value).toBe("sensitive-one-time-token"); expect(field.type).toBe("password"); expect(field.readOnly).toBe(true);
    expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
    expect(mocks.write).toHaveBeenCalledWith("/api/agents", "POST", expect.objectContaining({ name: "branch", dry_run: false }), "session");
    await userEvent.click(screen.getByRole("button", { name: "Close and forget token" }));
    expect(screen.queryByLabelText("Enrollment token")).toBeNull();
    expect(screen.queryByText("sensitive-one-time-token")).toBeNull();
  });

  it("shows backend errors and does not fabricate a successful enrollment", async () => {
    mocks.write.mockRejectedValue(new Error("node id is quarantined"));
    render(<AgentsView token="session" />);
    await screen.findByText("No agents registered yet.");
    await userEvent.click(screen.getByText("Add agent"));
    await userEvent.type(screen.getByLabelText("Agent name"), "branch");
    await userEvent.click(screen.getByRole("button", { name: "Create agent and token" }));
    expect((await screen.findByRole("alert")).textContent).toContain("quarantined");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("honors global preview for creation and requires explicit confirmation for rotation", async () => {
    mocks.write.mockResolvedValue({ dry_run: true, id: 2 });
    const { rerender } = render(<AgentsView token="session" dryRun />);
    await screen.findByText("No agents registered yet.");
    await userEvent.click(screen.getByText("Add agent"));
    await userEvent.type(screen.getByLabelText("Agent name"), "branch");
    await userEvent.click(screen.getByRole("button", { name: "Preview creation" }));
    await waitFor(() => expect(mocks.write).toHaveBeenCalledWith("/api/agents", "POST", expect.objectContaining({ dry_run: true }), "session"));
    expect(screen.queryByRole("dialog")).toBeNull();
    rerender(<AgentsView token="session" />);
    vi.spyOn(window, "confirm").mockReturnValue(false);
    await userEvent.click(screen.getByRole("button", { name: "Rotate signing key" }));
    expect(mocks.write.mock.calls.filter(call => call[0].includes("rotate-signing-key"))).toHaveLength(0);
  });

  it("refreshes an unselected fleet and pauses polling outside Overview", async () => {
    vi.useFakeTimers();
    try {
      const { rerender } = render(<AgentsView token="session" />);
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(screen.getByText("No agents registered yet.")).toBeTruthy();
      const fleetCalls = () => mocks.get.mock.calls.filter(call => call[0] === "/api/agents").length;
      const initial = fleetCalls();
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      expect(fleetCalls()).toBe(initial + 1);
      rerender(<AgentsView token="session" active={false} />);
      await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
      expect(fleetCalls()).toBe(initial + 1);
      rerender(<AgentsView token="session" active />);
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      expect(fleetCalls()).toBe(initial + 2);
    } finally { vi.useRealTimers(); }
  });

  it("shows queue lifecycle and exposes archive download only after a completed result", async () => {
    const download = vi.fn().mockResolvedValue(undefined);
    const command: AgentCommand = { id: "abc", type: "collect_diag", state: "queued", created_at: "now", args: {}, result: null };
    const props = { name: "branch", reports: [], bundles: [], busy: false, mutate: vi.fn(), read: vi.fn(), download };
    const { rerender } = render(<AgentActivity {...props} commands={[command]} />);
    expect(screen.getByText("collect_diag · queued")).not.toBeNull();
    expect(screen.queryByRole("button", { name: "Download diagnostic archive" })).toBeNull();
    rerender(<AgentActivity {...props} commands={[{ ...command, state: "done", result: { artefact_available: true } }]} />);
    await userEvent.click(screen.getByRole("button", { name: "Download diagnostic archive" }));
    expect(download).toHaveBeenCalledWith("abc");
  });
});
