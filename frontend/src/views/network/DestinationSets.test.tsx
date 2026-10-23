import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { DestinationSets } from "./DestinationSets";
import { EgressRules } from "./EgressRules";
import type { JsonObject } from "../../agentsApi";

afterEach(cleanup);
const corp = { routes: ["10.1.0.0/16"], domains: ["corp.example.com"], route_urls: ["https://example.com/routes"], domain_urls: ["https://example.com/domains"] };

it("edits every destination-set list with real multiline controls, retaining unedited URLs", async () => {
  const changed = vi.fn();
  function Editor() {
    const [sets, setSets] = useState<JsonObject>({ corp });
    return <DestinationSets sets={sets} disabled={false} onChange={next => { setSets(next); changed(next); }} />;
  }
  render(<Editor />);
  const routes = screen.getByLabelText("Set corp routes");
  await userEvent.type(routes, "{End}{Enter}10.2.0.0/16");
  expect(changed.mock.calls.at(-1)?.[0]).toEqual({ corp: { ...corp, routes: ["10.1.0.0/16", "10.2.0.0/16"] } });
  fireEvent.change(screen.getByLabelText("Set corp domain list urls"), { target: { value: "https://example.com/new" } });
  expect(changed.mock.calls.at(-1)?.[0].corp.domain_urls).toEqual(["https://example.com/new"]);
  expect(screen.getByLabelText("Set corp domains")).toBeTruthy();
  expect(screen.getByLabelText("Set corp route list urls")).toBeTruthy();
});

it("adds and explicitly removes named destination sets", async () => {
  const changed = vi.fn();
  const { rerender } = render(<DestinationSets sets={{}} disabled={false} onChange={changed} />);
  await userEvent.type(screen.getByLabelText("New destination set name"), "corp");
  await userEvent.click(screen.getByRole("button", { name: "Add destination set" }));
  expect(changed).toHaveBeenCalledWith({ corp: { routes: [], domains: [], route_urls: [], domain_urls: [] } });
  rerender(<DestinationSets sets={{ corp }} disabled={false} onChange={changed} />);
  await userEvent.click(screen.getByRole("button", { name: "Remove destination set corp" }));
  expect(changed).toHaveBeenLastCalledWith({});
});

it("does not erase inline destination URLs when changing routes", () => {
  const changed = vi.fn();
  render(<EgressRules rules={[{ from: ["host"], to: corp, via: "local" }]} disabled={false} classes={[]} deadRules={[]} explain={null} onChange={changed} />);
  fireEvent.change(screen.getByLabelText("Rule 1 destination routes"), { target: { value: "10.2.0.0/16" } });
  expect(changed).toHaveBeenCalledWith([{ from: ["host"], to: { ...corp, routes: ["10.2.0.0/16"] }, via: "local" }]);
});
