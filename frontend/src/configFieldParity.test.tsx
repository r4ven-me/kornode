import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import inventory from "./configFieldInventory.json";
import { ControlSettingsPanel } from "./views/config/ControlSettingsPanel";
import { HubEgress } from "./views/network/HubEgress";
import { SourceEditor } from "./views/agents/AgentResources";
import { AgentPolicy } from "./views/agents/AgentPolicy";

const mocks = vi.hoisted(() => ({ request: vi.fn(), get: vi.fn(), write: vi.fn() }));
vi.mock("./api", () => ({ requestJson: mocks.request }));
vi.mock("./agentsApi", () => ({ agentGet: mocks.get, agentWrite: mocks.write }));
type Field = { binding: string; label?: string; labels?: Record<string, string>; control: string; sample?: unknown };
type Surface = { component: string; marker: string; label_prefix?: string };
const models = inventory.models as unknown as Array<{ name: string; surfaces: Surface[]; fields: Record<string, Field> }>;
const destination = { routes: ["10.1.0.0/16"], domains: ["corp.example.com"], route_urls: ["https://example.com/old-routes"], domain_urls: ["https://example.com/old-domains"] };
const policy = { sources: [{ name: "wg", interface: "wg0", cidr: "10.8.1.0/24", export: true }], sets: { corp: destination }, egress: [{ from: ["host"], to: destination, via: "node:3" }] };
beforeEach(() => {
  vi.clearAllMocks();
  mocks.get.mockResolvedValue({ policy, warnings: [] }); mocks.write.mockResolvedValue({ policy, warnings: [] });
  mocks.request.mockImplementation((_path, _token, init) => Promise.resolve({ control: JSON.parse(init.body) }));
});
afterEach(cleanup);

function form(container: HTMLElement, surface: Surface): HTMLFormElement {
  const found = container.querySelector<HTMLFormElement>(`form[data-capability="${surface.marker}"]`);
  expect(found).toBeTruthy();
  expect(found!.querySelector(`button[data-capability="${surface.marker}"]`)).toBeTruthy();
  return found!;
}

function edit(field: Field, label: string, parent: HTMLElement) {
  const control = screen.getByLabelText(label) as HTMLInputElement | HTMLTextAreaElement;
  expect(parent.contains(control)).toBe(true);
  expect(control.dataset.configField).toBe(field.binding);
  if (field.control === "textarea") expect(control.tagName).toBe("TEXTAREA");
  else expect((control as HTMLInputElement).type).toBe(field.control);
  if (field.control === "checkbox") {
    if ((control as HTMLInputElement).checked !== field.sample) fireEvent.click(control);
  } else {
    fireEvent.change(control, { target: { value: Array.isArray(field.sample) ? field.sample.join("\n") : String(field.sample) } });
  }
}

it("binds every inventoried ControlConfig field to a labeled native control and settings payload", () => {
  const model = models.find(item => item.name === "ControlConfig")!;
  const { container } = render(<ControlSettingsPanel config={{ control: {} }} onNotice={vi.fn()} />);
  const parent = form(container, model.surfaces[0]);
  for (const field of Object.values(model.fields)) edit(field, field.label!, parent);
  fireEvent.submit(parent);
  const [path, , init] = mocks.request.mock.calls[0];
  expect(path).toBe("/api/web-config/control-settings");
  expect(JSON.parse(init.body)).toEqual(Object.fromEntries(Object.entries(model.fields).map(([name, field]) => [name, field.sample])));
});

const sourceModel = models.find(item => item.name === "Source")!;
it.each(sourceModel.surfaces)("binds every Source field on $component with the exact save marker", async surface => {
  const mutate = vi.fn().mockResolvedValue(true);
  const hub = surface.component === "hub-source";
  const { container } = render(hub ? <HubEgress token="session" /> : <SourceEditor sources={[]} busy={false} mutate={mutate} />);
  if (hub) await screen.findByText(/wg · wg0/);
  const parent = form(container, surface);
  for (const field of Object.values(sourceModel.fields)) edit(field, field.label ?? field.labels![surface.component], parent);
  fireEvent.submit(parent);
  const expected = Object.fromEntries(Object.entries(sourceModel.fields).map(([name, field]) => [name, field.sample]));
  const { name, ...data } = expected;
  if (hub) expect(mocks.write).toHaveBeenCalledWith(`/api/sources/${name}`, "PUT", data, "session");
  else expect(mutate).toHaveBeenCalledWith(`/sources/${name}`, "PUT", data);
});

it.each(["hub", "agent"])("keeps canonical interlink selectors alongside structured destination fields on %s", async surface => {
  const agentPolicy = { ...policy, egress: [{ from: ["interlink"], to: "interlink", via: "interlink" }] };
  mocks.get.mockResolvedValue({ policy: agentPolicy, warnings: [] });
  const mutate = vi.fn().mockResolvedValue(true);
  const { container } = render(surface === "hub" ? <HubEgress token="session" /> : <AgentPolicy policy={agentPolicy} busy={false} mutate={mutate} />);
  if (surface === "hub") await screen.findByText(/wg · wg0/);
  expect((screen.getByLabelText("Rule 1 to kind") as HTMLSelectElement).value).toBe("interlink");
  expect((screen.getByLabelText("Rule 1 via kind") as HTMLSelectElement).value).toBe("interlink");
  expect(container.querySelector('datalist option[value="interlink"]')).toBeTruthy();
  expect(container.querySelector('option[value="fabric"]')).toBeNull();
  expect(screen.getByLabelText("Set corp routes")).toBeTruthy();
  const parent = container.querySelector("form")!;
  fireEvent.submit(parent);
  if (surface === "hub") expect(mocks.write).toHaveBeenCalledWith("/api/egress", "PUT", agentPolicy, "session");
  else expect(mutate).toHaveBeenCalledWith("/policy", "PUT", agentPolicy);
});

const destModel = models.find(item => item.name === "DestSet")!;
it.each(destModel.surfaces)("binds every DestSet field on $component without relying on raw JSON", async surface => {
  const mutate = vi.fn().mockResolvedValue(true);
  const hub = surface.component.startsWith("hub-");
  const inline = surface.component.endsWith("-inline");
  const { container } = render(hub ? <HubEgress token="session" /> : <AgentPolicy policy={policy} busy={false} mutate={mutate} />);
  if (hub) await screen.findByText(/wg · wg0/);
  const parent = form(container, surface);
  for (const field of Object.values(destModel.fields)) edit(field, `${surface.label_prefix} ${field.label}`, parent);
  fireEvent.submit(parent);
  const samples = Object.fromEntries(Object.entries(destModel.fields).map(([name, field]) => [name, field.sample]));
  const sent = hub ? mocks.write.mock.calls.find(call => call[0] === "/api/egress" && call[1] === "PUT")![2] : mutate.mock.calls[0][2];
  expect(sent).toEqual(inline ? { ...policy, egress: [{ ...policy.egress[0], to: samples }] } : { ...policy, sets: { corp: samples } });
});
