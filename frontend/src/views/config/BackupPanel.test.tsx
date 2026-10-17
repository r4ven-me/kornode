import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { BackupPanel } from "./BackupPanel";

const mocks = vi.hoisted(() => ({ backup: vi.fn(), restore: vi.fn() }));
vi.mock("../../hubApi", () => ({ createHubBackup: mocks.backup, restoreHub: mocks.restore }));
const preview = { dry_run: true, staged: false, files: 12, created_at: "2026-10-16T10:00:00Z", config_path: "/staging/hub/config.yaml", target: "/staging/hub", restart_required: true, warning: "Stop the old hub." };
const password = "private-backup-passphrase";

beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear();
  mocks.backup.mockResolvedValue(new Blob(["ciphertext"]));
  mocks.restore.mockImplementation((_file, _password, dry) => Promise.resolve({ ...preview, dry_run: dry, staged: !dry }));
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: vi.fn(() => "blob:backup"), revokeObjectURL: vi.fn() }));
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("requires matching passphrases, downloads ciphertext and clears both inputs", async () => {
  render(<BackupPanel />);
  const download = screen.getByRole("button", { name: "Download encrypted backup" }) as HTMLButtonElement;
  expect(download.disabled).toBe(true);
  await userEvent.type(screen.getByLabelText("Backup passphrase"), password);
  await userEvent.type(screen.getByLabelText("Confirm backup passphrase"), "different");
  expect(download.disabled).toBe(true);
  await userEvent.clear(screen.getByLabelText("Confirm backup passphrase"));
  await userEvent.type(screen.getByLabelText("Confirm backup passphrase"), password);
  await userEvent.click(download);
  await screen.findByText(/Encrypted archive downloaded/);
  expect(mocks.backup).toHaveBeenCalledWith(password);
  expect((screen.getByLabelText("Backup passphrase") as HTMLInputElement).value).toBe("");
  expect((screen.getByLabelText("Confirm backup passphrase") as HTMLInputElement).value).toBe("");
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});

it("validates first, requires confirmation and stages without pretending to activate", async () => {
  render(<BackupPanel />);
  const file = new File(["encrypted"], "hub.knbackup", { type: "application/octet-stream" });
  await userEvent.upload(screen.getByLabelText("Encrypted archive"), file);
  await userEvent.type(screen.getByLabelText("Restore passphrase"), password);
  await userEvent.click(screen.getByRole("button", { name: "Validate archive" }));
  await screen.findByText(/Archive validated: 12 files/);
  expect(mocks.restore).toHaveBeenCalledWith(file, password, true);
  expect((screen.getByLabelText("Restore passphrase") as HTMLInputElement).value).toBe("");
  const stage = screen.getByRole("button", { name: "Stage hub restore" }) as HTMLButtonElement;
  expect(stage.disabled).toBe(true);
  await userEvent.type(screen.getByLabelText("Restore passphrase"), password);
  await userEvent.click(screen.getByLabelText("I understand this stages a restore, not a live switch"));
  await userEvent.click(stage);
  await screen.findByText(/Restore staged. Live hub unchanged/);
  expect(mocks.restore).toHaveBeenCalledWith(file, password, false);
  expect((screen.getByLabelText("Restored configuration path") as HTMLInputElement).value).toBe(preview.config_path);
});

it("keeps the passphrase after a failure for retry and never renders backend errors containing it", async () => {
  mocks.restore.mockRejectedValue(new Error(password));
  render(<BackupPanel />);
  await userEvent.upload(screen.getByLabelText("Encrypted archive"), new File(["bad"], "bad.knbackup"));
  await userEvent.type(screen.getByLabelText("Restore passphrase"), password);
  await userEvent.click(screen.getByRole("button", { name: "Validate archive" }));
  await screen.findByRole("alert");
  expect(screen.queryByText(new RegExp(password))).toBeNull();
  expect((screen.getByLabelText("Restore passphrase") as HTMLInputElement).value).toBe(password);
});

it("shows backend detail that does not contain the passphrase", async () => {
  mocks.restore.mockRejectedValue(new Error("422 archive_corrupt"));
  render(<BackupPanel />);
  await userEvent.upload(screen.getByLabelText("Encrypted archive"), new File(["bad"], "bad.knbackup"));
  await userEvent.type(screen.getByLabelText("Restore passphrase"), password);
  await userEvent.click(screen.getByRole("button", { name: "Validate archive" }));
  expect((await screen.findByRole("alert")).textContent).toContain("422 archive_corrupt");
});

it("honors global dry-run and invalidates validation when the file changes", async () => {
  render(<BackupPanel dryRun />);
  await userEvent.upload(screen.getByLabelText("Encrypted archive"), new File(["good"], "good.knbackup"));
  await userEvent.type(screen.getByLabelText("Restore passphrase"), password);
  await userEvent.click(screen.getByRole("button", { name: "Validate archive" }));
  await screen.findByText(/Archive validated/);
  await userEvent.type(screen.getByLabelText("Restore passphrase"), password);
  await userEvent.click(screen.getByLabelText("I understand this stages a restore, not a live switch"));
  expect((screen.getByRole("button", { name: "Stage hub restore" }) as HTMLButtonElement).disabled).toBe(true);
  await userEvent.upload(screen.getByLabelText("Encrypted archive"), new File(["new"], "new.knbackup"));
  await waitFor(() => expect(screen.queryByRole("button", { name: "Stage hub restore" })).toBeNull());
});
