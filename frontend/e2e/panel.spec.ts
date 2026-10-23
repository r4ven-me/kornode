import { expect, test } from "@playwright/test";

import { type MockOptions, mockApi, signIn } from "./fixtures";

test("logs in and opens every standard management section", async ({ page }) => {
  await mockApi(page);
  await signIn(page);

  for (const section of ["Users", "Sessions", "Diagnostics", "Logs", "Dashboard"]) {
    await page.getByRole("button", { name: section, exact: true }).click();
    await expect(page.getByRole("heading", { name: section, exact: true })).toBeVisible();
  }
  await expect(page.getByRole("button", { name: "Terminal", exact: true })).toHaveCount(0);
});

test("Config hub exposes every config sub-section behind its own sub-nav pill", async ({
  page
}) => {
  await mockApi(page);
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Config", exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Routing", exact: true })
  ).toHaveCount(0);

  for (const [pill, heading] of [
    ["System", "General"],
    ["Server", "VPN server"],
    ["Authentication", "Authentication methods"],
    ["Certificates", "Authority certificates"],
    ["Identity · Experimental", "Group routing"],
    ["Upstream", "Upstream profiles"],
    ["DNS", "DNS"],
    ["Web / API", "Web / API panel"],
    ["Advanced", "Persistent YAML"]
  ] as const) {
    await page.getByRole("button", { name: pill, exact: true }).click();
    await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
  }

  await page.getByRole("button", { name: "Certificates", exact: true }).click();
  for (const tab of ["Certificate authority", "Server certificate", "Let's Encrypt"]) {
    await expect(page.getByRole("tab", { name: tab, exact: true })).toBeVisible();
  }

  await page.getByRole("button", { name: "Identity · Experimental", exact: true }).click();
  for (const tab of ["Group selection", "OIDC connector", "Providers & group policies"]) {
    await expect(page.getByRole("tab", { name: tab, exact: true })).toBeVisible();
  }
});

test("Authentication OTP delivery credentials can be tested with current form values", async ({
  page
}) => {
  const mutations: NonNullable<MockOptions["mutations"]> = [];
  await mockApi(page, { mutations });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Authentication", exact: true }).click();

  await expect(page.getByText("OTP configuration", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Enable email delivery")).toBeVisible();
  await page.getByRole("tab", { name: "Email delivery" }).click();
  await page.getByLabel("Enable email delivery").check();
  await expect(page.getByLabel("SMTP host")).toBeVisible();
  await expect(page.getByRole("button", { name: "Test email" })).toBeDisabled();
  await page.getByLabel("SMTP host").fill("smtp.example.com");
  await page.getByLabel("SMTP username").fill("mailer");
  await page.getByLabel("SMTP password").fill("smtp-secret");
  await expect(page.getByLabel("SMTP password")).toHaveAttribute("type", "password");
  await page.getByLabel("From address").fill("vpn@example.com");
  await page.getByLabel("Test recipient").fill("admin@example.com");
  await page.getByRole("button", { name: "Test email" }).click();

  await expect(page.getByLabel("Enable Telegram delivery")).not.toBeVisible();
  await page.getByText("Telegram delivery", { exact: true }).click();
  await page.getByLabel("Enable Telegram delivery").check();
  await expect(page.getByRole("button", { name: "Test Telegram" })).toBeDisabled();
  await page.getByLabel("Telegram bot token").fill("bot-secret");
  await expect(page.getByLabel("Telegram bot token")).toHaveAttribute("type", "password");
  await page.getByLabel("Telegram chat ID").fill("123456");
  await page.getByRole("button", { name: "Test Telegram" }).click();

  await expect.poll(
    () => mutations.filter((entry) => entry.path.includes("/api/server/auth-settings/test-")).length
  ).toBe(2);
  const emailBody = JSON.parse(
    mutations.find((entry) => entry.path.endsWith("/test-email"))?.body ?? "{}"
  );
  expect(emailBody).toMatchObject({
    otp_smtp_host: "smtp.example.com",
    otp_smtp_port: 587,
    otp_smtp_username: "mailer",
    otp_smtp_password: "smtp-secret",
    otp_smtp_from: "vpn@example.com",
    otp_smtp_starttls: true,
    otp_smtp_test_recipient: "admin@example.com"
  });
  const telegramBody = JSON.parse(
    mutations.find((entry) => entry.path.endsWith("/test-telegram"))?.body ?? "{}"
  );
  expect(telegramBody).toMatchObject({
    otp_telegram_bot_token: "bot-secret",
    otp_telegram_chat_id: "123456"
  });
});

test("DNS Save persists one atomic draft and applies it", async ({ page }) => {
  const mutations: NonNullable<MockOptions["mutations"]> = [];
  await mockApi(page, { mutations });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "DNS", exact: true }).click();
  await expect(page.getByLabel("DNS request path")).toContainText("Built-in resolver");
  await expect(page.getByLabel("Use built-in resolver")).toHaveCount(0);
  await page.getByLabel("Enable local records").check();
  await page.getByLabel("Enable blocklist").check();
  await page.getByLabel("Upstream DNS servers", { exact: true }).fill("9.9.9.1");
  await page.getByLabel("DNS servers (same as Server)").fill("9.9.9.9\n1.1.1.1");
  await page.getByRole("tab", { name: "DNS forwarding", exact: true }).click();
  await page.getByLabel("DNS servers", { exact: true }).fill("1.1.1.1\n8.8.8.8");
  await page.getByLabel("Domains", { exact: true }).fill("example.com\nexample.net");
  await page.getByRole("button", { name: "Save", exact: true }).click();

  await expect.poll(() => mutations.find((entry) => entry.path === "/api/internal-dns/settings"))
    .toBeTruthy();
  const body = JSON.parse(
    mutations.find((entry) => entry.path === "/api/internal-dns/settings")?.body ?? "{}"
  );
  expect(body).toMatchObject({

    listen: "10.10.10.1",
    port: 53,
    blocklist_enabled: true,
    local_records_enabled: true,
    upstreams: ["9.9.9.1"],
    server_dns: ["9.9.9.9", "1.1.1.1"],
    forward_upstreams: ["1.1.1.1", "8.8.8.8"],
    forward_domains: ["example.com", "example.net"]
  });
  await expect.poll(() => mutations.some((entry) => entry.path === "/api/internal-dns/apply"))
    .toBe(false);
});

test("Upstream profiles stay manageable while disabled and routing belongs in Network", async ({ page }) => {
  await mockApi(page, { upstreamEnabled: false, upstreamProfiles: [{ name: "alpha", server: "alpha.example.com", port: "443", auth_type: "password", username: "user", enabled: true }] });
  await signIn(page);
  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Upstream profiles", exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Routing", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("tab", { name: "Host DNS & uplink" }).click();
  await expect(dialog.getByLabel("Main interface", { exact: true })).toBeEnabled();
  await expect(dialog.getByRole("combobox", { name: "Host DNS", exact: true })).toBeEnabled();
  await expect(dialog.getByText("Host mode", { exact: true })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Network", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Egress rules", exact: true })).toBeVisible();
});

test("Upstream with no profiles offers creation without obsolete routing controls", async ({ page }) => {
  await mockApi(page);
  await signIn(page);
  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await expect(page.getByRole("button", { name: "Add profile", exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Routing", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Add profile", exact: true }).click();
  await expect(page.getByRole("heading", { name: "New profile" })).toBeVisible();
});

test("shows the lazy xterm view only when terminal access is enabled", async ({ page }) => {
  await mockApi(page, { terminalEnabled: true });
  await signIn(page);

  await page.getByRole("button", { name: "Terminal", exact: true }).click();

  await expect(page.locator(".xterm-host .xterm")).toBeVisible();
  await expect(page.getByText("Root shell inside the running container")).toBeVisible();
});

test("core management buttons call expected API endpoints with CSRF", async ({ page }) => {
  const mutations: MockOptions["mutations"] = [];
  await mockApi(page, {
    mutations,
    users: [{ username: "alice", disabled: false, certificate_exists: true, p12_exists: false }],
    sessions: [
      {
        username: "alice",
        vpn_ip: "10.10.10.10",
        real_ip: "198.51.100.10",
        device: "vpns0",
        rx: "1 MiB",
        tx: "2 MiB",
        rx_rate: "10 bytes/sec",
        tx_rate: "20 bytes/sec",
        duration_seconds: 3600
      }
    ],
    routes: ["10.20.0.0/16"],
    domains: ["internal.example"],
    routingMode: "split",
    upstreamEnabled: true,
    upstreamProfiles: [
      {
        name: "alpha",
        server: "alpha.example.com",
        port: "443",
        auth_type: "password",
        username: "user",
        enabled: true
      }
    ],
    initialServerState: "stopped"
  });
  page.on("dialog", (dialog) => dialog.accept());
  await signIn(page);

  await page.getByRole("button", { name: "Start", exact: true }).click();
  await page.getByRole("button", { name: "Stop", exact: true }).click();
  await page.getByRole("button", { name: "Render configs", exact: true }).click();
  await page.getByRole("button", { name: "Network", exact: true }).click();
  await page.getByRole("button", { name: "Apply", exact: true }).click();

  await page.getByRole("button", { name: "Users", exact: true }).click();
  await page.getByLabel("Username").fill("bob");
  await page.getByLabel("Password", { exact: true }).fill("secret");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await page.locator("details.user-card", { hasText: "alice" }).locator("summary").click();
  await page.getByRole("button", { name: "Delete user", exact: true }).click();

  await page.getByRole("button", { name: "Sessions", exact: true }).click();
  await page.getByRole("button", { name: "Kick session", exact: true }).click();

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await page.getByRole("button", { name: "Network", exact: true }).click();
  await page.getByRole("tab", { name: "JSON (advanced)", exact: true }).click();
  await page.getByLabel("Policy (JSON: sources, sets, egress)").fill(JSON.stringify({ sources: [], sets: {}, egress: [{ from: ["clients"], to: "any", via: "local" }] }));
  await page.getByRole("button", { name: "Save policy", exact: true }).click();
  await expect.poll(() => mutations.some(m => m.path === "/api/egress" && m.method === "PUT")).toBe(true);

  const observed = mutations.map(({ method, path, csrf }) => ({ method, path, csrf }));
  expect(observed).toEqual(
    expect.arrayContaining([
      { method: "POST", path: "/api/server/start", csrf: "csrf" },
      { method: "POST", path: "/api/server/stop", csrf: "csrf" },
      { method: "POST", path: "/api/config/render", csrf: "csrf" },
      { method: "POST", path: "/api/net/apply", csrf: "csrf" },
      { method: "POST", path: "/api/users", csrf: "csrf" },
      { method: "DELETE", path: "/api/users/alice", csrf: "csrf" },
      { method: "POST", path: "/api/sessions/alice/kick", csrf: "csrf" },
      { method: "PUT", path: "/api/egress", csrf: "csrf" }
    ])
  );
});

test("group membership dialogs fetch fresh data instead of trusting stale state", async ({
  page
}) => {
  // Regression test: state.users is only ever refreshed after an action taken
  // through this panel, so membership changed out-of-band (CLI, another admin
  // session, or just a tab left open) used to render wrong until some
  // unrelated reload happened to refresh it. Both membership dialogs must
  // re-fetch /api/users at open time instead of reading the cached snapshot.
  await mockApi(page, {
    users: [
      {
        username: "alice",
        disabled: false,
        certificate_exists: false,
        p12_exists: false,
        groups: ["devops"]
      }
    ],
    // Every fetch after the initial page load (i.e. the ones triggered by
    // opening a membership dialog) says alice is no longer in "devops" --
    // simulating a change made outside this tab.
    usersAfterFirstFetch: [
      { username: "alice", disabled: false, certificate_exists: false, p12_exists: false, groups: [] }
    ],
    groups: [{ name: "devops", config_exists: true, has_settings: true }]
  });

  await signIn(page);

  await page.getByLabel("Primary").getByRole("button", { name: "Groups", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Groups", exact: true })).toBeVisible();
  await page.getByRole("table").getByRole("button", { name: "Members" }).click();
  await expect(page.getByRole("heading", { name: "devops members" })).toBeVisible();
  const aliceRow = page.locator(".group-choice", { hasText: "alice" });
  await expect(aliceRow.locator("input[type=checkbox]")).not.toBeChecked();
  await page.getByRole("button", { name: "Close", exact: true }).click();

  await page.getByRole("button", { name: "Users", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Users", exact: true })).toBeVisible();
  const aliceCard = page.locator("details.user-card", { hasText: "alice" });
  await aliceCard.locator("summary").click();
  await aliceCard.getByRole("button", { name: "Groups", exact: true }).click();
  await expect(page.getByRole("heading", { name: "alice groups" })).toBeVisible();
  const devopsRow = page.locator(".group-choice", { hasText: "devops" });
  await expect(devopsRow.locator("input[type=checkbox]")).not.toBeChecked();
});

test("Network stores named route/domain sets and upstream rules as arrays", async ({ page }) => {
  const mutations: NonNullable<MockOptions["mutations"]> = [];
  await mockApi(page, { mutations });
  await signIn(page);
  await page.getByRole("button", { name: "Network", exact: true }).click();
  await page.getByRole("tab", { name: "JSON (advanced)", exact: true }).click();
  const policy = { sources: [], sets: { finance: { routes: ["10.50.0.0/16", "10.60.0.0/16"], domains: ["corp.example.com"], route_files: ["/lists/routes.txt"], route_urls: ["https://lists.example.com/routes.txt"], domain_files: ["/lists/domains.txt"], domain_urls: ["https://lists.example.com/domains.txt"] } }, egress: [{ from: ["clients"], to: { set: "finance" }, via: "upstream:finance", kill_switch: true }] };
  await page.getByLabel("Policy (JSON: sources, sets, egress)").fill(JSON.stringify(policy));
  await page.getByRole("button", { name: "Save policy", exact: true }).click();
  await expect.poll(() => mutations.find(m => m.method === "PUT" && m.path === "/api/egress")).toBeTruthy();
  expect(JSON.parse(mutations.find(m => m.path === "/api/egress")?.body ?? "{}")).toEqual(policy);
  expect(mutations.some(m => m.path.startsWith("/api/routing/"))).toBe(false);
});

test("a new profile starts with every toggle off", async ({ page }) => {
  // Regression test: a freshly created profile used to default to "Turn on
  // Upstream (all profiles)" and "This profile enabled" both checked,
  // meaning saving a brand-new, half-configured profile could silently
  // flip upstream.enabled on globally. Everything now starts opt-in.
  await mockApi(page);
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await page.getByRole("button", { name: "Add profile", exact: true }).click();
  const dialog = page.getByRole("dialog");

  for (const label of [

    "This profile enabled",
    "No cert check"
  ]) {
    await expect(dialog.getByLabel(label, { exact: true })).not.toBeChecked();
  }
  await expect(dialog.getByRole("tab", { name: "Host traffic & sync" })).toHaveCount(0);
  await expect(dialog.getByLabel("Route this host’s traffic through this profile", { exact: true })).toHaveCount(0);
});

test("editing an existing profile keeps the actual profiles-enabled state, not a hardcoded default", async ({
  page
}) => {
  // Editing a profile must not silently enable the upstream feature.
  const mutations: NonNullable<MockOptions["mutations"]> = [];
  await mockApi(page, {
    mutations,
    upstreamEnabled: false,
    upstreamProfiles: [
      {
        name: "alpha",
        server: "alpha.example.com",
        port: "443",
        auth_type: "password",
        username: "user",
        enabled: true
      }
    ]
  });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await page.getByRole("button", { name: "Edit profile" }).first().click();

  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("This profile enabled", { exact: true })).toBeChecked();
  await expect(dialog.getByLabel("Turn on upstream profiles (all profiles)", { exact: true })).toHaveCount(0);
  await dialog.getByLabel("Server", { exact: true }).fill("new.example.com");
  await dialog.getByRole("button", { name: "Save profile", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText("Profiles disabled", { exact: true })).toBeVisible();
  expect(mutations.some(m => m.path === "/api/upstream/settings")).toBe(false);
  expect(JSON.parse(mutations.find(m => m.path === "/api/upstream/profiles")?.body ?? "{}")).toMatchObject({ name: "alpha", server: "new.example.com", enabled: true });
});

test("creating a profile saves connection fields without removed relay/sync controls", async ({ page }) => {
  const mutations: NonNullable<MockOptions["mutations"]> = [];
  await mockApi(page, { mutations });
  await signIn(page);
  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await page.getByRole("button", { name: "Add profile", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name", { exact: true }).fill("finance");
  await dialog.getByLabel("Server", { exact: true }).fill("finance.example.com");
  await dialog.getByLabel("Username", { exact: true }).fill("finance-user");
  await dialog.getByLabel("Password", { exact: true }).fill("finance-pass");
  await expect(dialog.getByRole("tab", { name: "Host traffic & sync" })).toHaveCount(0);
  await expect(dialog.getByLabel("Relay routes", { exact: true })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Save profile", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  const payload = JSON.parse(mutations.find(m => m.path === "/api/upstream/profiles")?.body ?? "{}");
  expect(payload).toMatchObject({ name: "finance", server: "finance.example.com", username: "finance-user", password: "finance-pass", enabled: false });
  for (const removed of ["host_routes", "host_domains", "sync_url", "route_host_enabled", "route_clients_enabled", "accept_server_routes"]) expect(payload).not.toHaveProperty(removed);
});

test("profile list shows the default profile first, then connected profiles, then the rest in order", async ({
  page
}) => {
  await mockApi(page, {
    upstreamEnabled: true,
    upstreamProfiles: [
      {
        name: "bravo",
        server: "bravo.example.com",
        port: "443",
        auth_type: "password",
        username: "user",
        enabled: true
      },
      {
        name: "alpha",
        server: "alpha.example.com",
        port: "443",
        auth_type: "password",
        username: "user",
        enabled: true
      },
      {
        name: "charlie",
        server: "charlie.example.com",
        port: "443",
        auth_type: "password",
        username: "user",
        enabled: true
      }
    ],
    upstreamStatus: {
      active_profile: "alpha",
      connections: [
        { profile: "bravo", interface: "oc-up1", connected: false, local_ip: null, remote: null },
        {
          profile: "alpha",
          interface: "oc-middle0",
          connected: false,
          local_ip: null,
          remote: null
        },
        {
          profile: "charlie",
          interface: "oc-up2",
          connected: true,
          local_ip: "10.10.10.5",
          remote: "203.0.113.9:443"
        }
      ]
    }
  });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();

  const rows = page.locator(".upstream-profiles-panel tbody tr");
  const names = await rows.locator(".strong-cell .inline-tools > span:first-child").allTextContents();
  // alpha is the configured default (rank 0), charlie is connected despite
  // not being default (rank 1), bravo is neither (rank 2, added 1st but
  // still last since sort is by rank, not insertion order, across groups).
  expect(names).toEqual(["alpha", "charlie", "bravo"]);

  const charlieRow = rows.filter({ hasText: "charlie" });
  await expect(charlieRow.getByText("Internal 10.10.10.5 / External 203.0.113.9:443")).toBeVisible();
  const alphaRow = rows.filter({ hasText: "alpha" });
  await expect(alphaRow.locator(".pill", { hasText: "Default" })).toBeVisible();
});

test("making a different profile default asks for confirmation before switching", async ({
  page
}) => {
  const mutations: MockOptions["mutations"] = [];
  await mockApi(page, {
    mutations,
    upstreamEnabled: true,
    upstreamProfiles: [
      {
        name: "alpha",
        server: "alpha.example.com",
        port: "443",
        auth_type: "password",
        username: "user",
        enabled: true
      },
      {
        name: "bravo",
        server: "bravo.example.com",
        port: "443",
        auth_type: "password",
        username: "user",
        enabled: true
      }
    ],
    upstreamStatus: { active_profile: "alpha", connections: [] }
  });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();

  let dialogMessage = "";
  page.once("dialog", (dialog) => {
    dialogMessage = dialog.message();
    void dialog.accept();
  });
  await page
    .locator(".upstream-profiles-panel tbody tr", { hasText: "bravo" })
    .getByRole("button", { name: "Make default profile", exact: true })
    .click();

  expect(dialogMessage).toContain("bravo");
  const saved = mutations.find(
    (mutation) => mutation.method === "POST" && mutation.path === "/api/upstream/switch"
  );
  expect(saved).toBeDefined();
  expect(JSON.parse(saved?.body ?? "{}").profile).toBe("bravo");
});

test("Host DNS and uplink save through the current routing settings endpoint", async ({ page }) => {
  const mutations: NonNullable<MockOptions["mutations"]> = [];
  await mockApi(page, { mutations, upstreamEnabled: true });
  await signIn(page);
  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("tab", { name: "Host DNS & uplink" }).click();
  await dialog.getByRole("combobox", { name: "Host DNS", exact: true }).selectOption("resolv_conf");
  await dialog.getByLabel("Main interface", { exact: true }).fill("eth1");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  const saved = mutations.find(m => m.path === "/api/routing/settings");
  expect(saved?.csrf).toBe("csrf");
  expect(JSON.parse(saved?.body ?? "{}")).toEqual({ host_dns: "resolv_conf", main_interface: "eth1" });
});

test("Network stores host routing in egress rather than removed host split endpoints", async ({ page }) => {
  const mutations: NonNullable<MockOptions["mutations"]> = [];
  await mockApi(page, { mutations });
  await signIn(page);
  await page.getByRole("button", { name: "Network", exact: true }).click();
  await page.getByRole("tab", { name: "JSON (advanced)", exact: true }).click();
  const policy = { sources: [], sets: { office: { routes: ["10.90.0.0/16"], domains: ["intranet.example"] } }, egress: [{ from: ["host"], to: { set: "office" }, via: "upstream:office", kill_switch: true }, { from: ["clients"], to: "any", via: "local" }] };
  await page.getByLabel("Policy (JSON: sources, sets, egress)").fill(JSON.stringify(policy));
  await page.getByRole("button", { name: "Save policy", exact: true }).click();
  await expect.poll(() => mutations.find(m => m.path === "/api/egress")).toBeTruthy();
  expect(JSON.parse(mutations.find(m => m.path === "/api/egress")?.body ?? "{}")).toEqual(policy);
  expect(mutations.some(m => m.path.startsWith("/api/routing/"))).toBe(false);
});
