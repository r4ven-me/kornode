import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { emptyUpstreamProfileDraft } from "../../app/state";
import { ClientProfileDialog } from "./ClientProfileDialog";

// vitest's config doesn't set `globals: true`, so @testing-library/react's
// automatic afterEach(cleanup) registration (which relies on detecting a
// global `afterEach`) never fires -- without this, each test's rendered
// dialog stays mounted, and the next test's queries match duplicates.
afterEach(cleanup);

describe("ClientProfileDialog kind switch", () => {
  it("shows the OpenConnect server/auth fields by default", () => {
    render(
      <ClientProfileDialog
        draft={emptyUpstreamProfileDraft}
        isEdit={false}
        busy={null}
        onDraftChange={vi.fn()}
        onClose={vi.fn()}
        onSave={vi.fn()}
        onFetchPin={vi.fn()}
      />
    );

    expect(screen.getByText("Server")).not.toBeNull();
    expect(screen.getByText("Auth")).not.toBeNull();
    expect(screen.getByPlaceholderText("vpn.example.com")).not.toBeNull();
  });

  it("hides Server/Port/Auth and requires Interface for external_interface", async () => {
    let draft = emptyUpstreamProfileDraft;
    const onDraftChange = vi.fn((next) => {
      draft = next;
    });
    const { rerender } = render(
      <ClientProfileDialog
        draft={draft}
        isEdit={false}
        busy={null}
        onDraftChange={onDraftChange}
        onClose={vi.fn()}
        onSave={vi.fn()}
        onFetchPin={vi.fn()}
      />
    );

    await userEvent.selectOptions(screen.getByLabelText("Kind"), ["external_interface"]);
    expect(onDraftChange).toHaveBeenCalledWith(
      expect.objectContaining({ kind: "external_interface" })
    );

    rerender(
      <ClientProfileDialog
        draft={{ ...draft, kind: "external_interface" }}
        isEdit={false}
        busy={null}
        onDraftChange={onDraftChange}
        onClose={vi.fn()}
        onSave={vi.fn()}
        onFetchPin={vi.fn()}
      />
    );

    expect(screen.queryByText("Server")).toBeNull();
    expect(screen.queryByText("Auth")).toBeNull();
    const interfaceInput = screen.getByPlaceholderText("wg0") as HTMLInputElement;
    expect(interfaceInput.required).toBe(true);
  });
});
