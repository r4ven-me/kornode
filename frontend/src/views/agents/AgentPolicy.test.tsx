import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentPolicy } from "./AgentPolicy";

const policy = {
  sets: { corp: { routes: ["10.60.0.0/16"] } },
  egress: [
    { from: ["clients"], to: { set: "corp" }, via: "exit:3" },
    { from: ["clients"], to: "any", via: "local" },
  ],
};

afterEach(cleanup);

describe("AgentPolicy", () => {
  it("edits rules with the shared ordered editor and saves the whole policy", () => {
    const mutate = vi.fn().mockResolvedValue(undefined);
    render(<AgentPolicy policy={policy} busy={false} mutate={mutate} />);

    fireEvent.click(screen.getByLabelText("Move rule 2 up"));
    fireEvent.click(screen.getByText("Save policy"));

    expect(mutate).toHaveBeenCalledTimes(1);
    const [path, method, body] = mutate.mock.calls[0];
    expect([path, method]).toEqual(["/policy", "PUT"]);
    expect(body.egress.map((rule: { via: string }) => rule.via)).toEqual(["local", "exit:3"]);
    expect(body.sets).toEqual(policy.sets);
  });

  it("adds a rule and refuses invalid set JSON without calling the backend", () => {
    const mutate = vi.fn();
    render(<AgentPolicy policy={policy} busy={false} mutate={mutate} />);

    fireEvent.click(screen.getByText("Add rule"));
    expect(screen.getByLabelText("Rule 3 from")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Destination sets (JSON)"), { target: { value: "{" } });
    fireEvent.click(screen.getByText("Save policy"));

    expect(screen.getByRole("alert").textContent).toContain("valid JSON");
    expect(mutate).not.toHaveBeenCalled();
  });
});
