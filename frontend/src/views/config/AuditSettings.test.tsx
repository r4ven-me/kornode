import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AdminPasswordPanel } from "./AdminPasswordPanel";
import { ControlSettingsPanel } from "./ControlSettingsPanel";
import { AdminTotpPanel } from "./AdminTotpPanel";

const mocks = vi.hoisted(() => ({ request: vi.fn(), status: vi.fn(), setup: vi.fn(), confirm: vi.fn(), disable: vi.fn() }));
vi.mock("../../api", () => ({ requestJson: mocks.request, fetchTotpStatus: mocks.status, setupTotp: mocks.setup, confirmTotp: mocks.confirm, disableTotp: mocks.disable }));
beforeEach(() => { vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear(); });
afterEach(cleanup);

it("requires matching new passwords, posts the reauthentication contract, clears secrets and signs out", async () => {
  mocks.request.mockResolvedValue({ status: "password_changed", reauthentication_required: true });
  const reauthenticate = vi.fn();
  render(<AdminPasswordPanel onNotice={vi.fn()} onReauthenticate={reauthenticate} />);
  const save = screen.getByRole("button", { name: "Change administrator password" }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);
  await userEvent.type(screen.getByLabelText("Current administrator password"), "old-password");
  await userEvent.type(screen.getByLabelText("New administrator password"), "new-password");
  await userEvent.type(screen.getByLabelText("Confirm new administrator password"), "different");
  expect(save.disabled).toBe(true);
  await userEvent.clear(screen.getByLabelText("Confirm new administrator password"));
  await userEvent.type(screen.getByLabelText("Confirm new administrator password"), "new-password");
  await userEvent.type(screen.getByLabelText("Current authenticator code (if enabled)"), "123456");
  await userEvent.click(save);
  const [path, token, init] = mocks.request.mock.calls[0];
  expect([path, token]).toEqual(["/api/auth/password", "session"]);
  expect(JSON.parse(init.body)).toEqual({ current_password: "old-password", new_password: "new-password", totp_code: "123456" });
  await waitFor(() => expect(reauthenticate).toHaveBeenCalledOnce());
  for (const input of screen.getAllByLabelText(/administrator password|authenticator code/)) expect((input as HTMLInputElement).value).toBe("");
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

it("does not display arbitrary password errors or report a failed change as successful", async () => {
  mocks.request.mockRejectedValue(new Error("private-new-password"));
  const reauthenticate = vi.fn();
  render(<AdminPasswordPanel onNotice={vi.fn()} onReauthenticate={reauthenticate} />);
  fireEvent.change(screen.getByLabelText("Current administrator password"), { target: { value: "old" } });
  for (const name of ["New administrator password", "Confirm new administrator password"]) fireEvent.change(screen.getByLabelText(name), { target: { value: "private-new-password" } });
  await userEvent.click(screen.getByRole("button", { name: "Change administrator password" }));
  expect((await screen.findByRole("alert")).textContent).not.toContain("private-new-password");
  expect(reauthenticate).not.toHaveBeenCalled();
});

it("offers editable control settings including the advanced signing-key path", async () => {
  const control = { enabled: false, port: 8444, long_poll_seconds: 60, report_interval_seconds: 30, offline_after_seconds: 90, cert_lifetime_days: 90, enroll_token_ttl_minutes: 60, bundle_history: 20, min_agent_version: "2.0.0", signing_key: "/deployment/key.pem" };
  mocks.request.mockResolvedValue({ control });
  const notice = vi.fn();
  render(<ControlSettingsPanel config={{ control }} onNotice={notice} />);
  expect(screen.getAllByRole("spinbutton")).toHaveLength(7);
  fireEvent.change(screen.getByLabelText("Control plane port"), { target: { value: "9444" } });
  await userEvent.click(screen.getByLabelText("Enable agent control plane"));
  await userEvent.click(screen.getByRole("button", { name: "Save control settings" }));
  expect(mocks.request.mock.calls[0][0]).toBe("/api/web-config/control-settings");
  expect(JSON.parse(mocks.request.mock.calls[0][2].body)).toEqual({ ...control, enabled: true, port: 9444 });
  await waitFor(() => expect(notice).toHaveBeenCalledWith("warning", expect.stringContaining("Restart")));
});

it("represents a cleared signing-key path as null, never as key material", async () => {
  mocks.request.mockResolvedValue({ control: { signing_key: null } });
  render(<ControlSettingsPanel config={{ control: { signing_key: "/deployment/key.pem" } }} onNotice={vi.fn()} />);
  const path = screen.getByLabelText("Signing-key path (advanced deployment setting)") as HTMLInputElement;
  expect(path.value).toBe("/deployment/key.pem");
  await userEvent.clear(path);
  await userEvent.click(screen.getByRole("button", { name: "Save control settings" }));
  expect(JSON.parse(mocks.request.mock.calls[0][2].body).signing_key).toBeNull();
  expect(screen.getByText(/Saving never creates or rotates key files/)).toBeTruthy();
});

it("requires current password and TOTP to disable two-factor authentication", async () => {
  mocks.status.mockResolvedValue({ enabled: true });
  mocks.disable.mockResolvedValue({ status: "disabled" });
  const reauthenticate = vi.fn();
  vi.spyOn(window, "confirm").mockReturnValue(true);
  render(<AdminTotpPanel onNotice={vi.fn()} onReauthenticate={reauthenticate} />);
  const disable = await screen.findByRole("button", { name: "Disable" }) as HTMLButtonElement;
  expect(disable.disabled).toBe(true);
  await userEvent.type(screen.getByLabelText("Current password for two-factor changes"), "current-password");
  await userEvent.type(screen.getByLabelText("Current two-factor code"), "123456");
  await userEvent.click(disable);
  expect(mocks.disable).toHaveBeenCalledWith("session", { current_password: "current-password", totp_code: "123456" });
  await waitFor(() => expect(reauthenticate).toHaveBeenCalledOnce());
});

it("reauthenticates TOTP setup/confirmation and signs out when two-factor credentials change", async () => {
  mocks.status.mockResolvedValue({ enabled: false });
  mocks.setup.mockResolvedValue({ secret: "setup-secret", qr_svg: "", otpauth_uri: "" });
  mocks.confirm.mockResolvedValue({ status: "enabled", reauthentication_required: true });
  const reauthenticate = vi.fn();
  render(<AdminTotpPanel onNotice={vi.fn()} onReauthenticate={reauthenticate} />);
  await userEvent.type(screen.getByLabelText("Current password for two-factor changes"), "current-password");
  await userEvent.click(screen.getByRole("button", { name: "Enable" }));
  expect(mocks.setup).toHaveBeenCalledWith("session", { current_password: "current-password", totp_code: undefined });
  await userEvent.type(await screen.findByLabelText("Authenticator code"), "654321");
  await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
  expect(mocks.confirm).toHaveBeenCalledWith("session", "setup-secret", "654321", { current_password: "current-password", totp_code: undefined });
  await waitFor(() => expect(reauthenticate).toHaveBeenCalledOnce());
  expect((screen.getByLabelText("Current password for two-factor changes") as HTMLInputElement).value).toBe("");
});
