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
    ["Clients", "Clients"],
    ["Upstream", "Upstream"],
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
  await expect(page.getByLabel("DNS request path")).toContainText("Direct server DNS");

  await page.getByLabel("Use built-in resolver").check();
  await page.getByLabel("Enable local records").check();
  await page.getByLabel("Enable blocklist").check();
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
    resolver_enabled: true,
    listen: "10.10.10.1",
    port: 53,
    blocklist_enabled: true,
    local_records_enabled: true,
    server_dns: ["9.9.9.9", "1.1.1.1"],
    forward_upstreams: ["1.1.1.1", "8.8.8.8"],
    forward_domains: ["example.com", "example.net"]
  });
  await expect.poll(() => mutations.some((entry) => entry.path === "/api/internal-dns/apply"))
    .toBe(false);
});

test("routing controls are inert until Clients are enabled", async ({ page }) => {
  // Regression test: routing.mode/host_traffic/host_mode and the Routes/
  // Domains lists have no effect at all while upstream.enabled is false
  // (VPN users just get plain NAT through the host regardless) -- the UI
  // used to leave them fully interactive anyway, inviting an admin to
  // "set" something that silently does nothing.
  await mockApi(page, {
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
  await expect(page.getByText("Clients disabled", { exact: true })).toBeVisible();
  // Not getByLabel("Mode"): the select's accessible name includes its selected option.
  await expect(
    page.locator("label").filter({ hasText: "Mode" }).first().locator("select")
  ).toBeDisabled();

  await page.getByRole("button", { name: "Clients", exact: true }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("tab", { name: "Host traffic" }).click();
  await expect(
    dialog.locator("label").filter({ hasText: "Route this host" }).locator("input")
  ).toBeDisabled();
  // Host mode only appears once Host traffic is checked -- it can't be, so
  // it isn't rendered at all while Clients are off.
  await expect(
    dialog.locator("label").filter({ hasText: "Host mode" }).locator("select")
  ).toHaveCount(0);
  // Infrastructure settings that matter regardless of Clients (plain NAT
  // through the host uses main_interface/fwmark/table_id/nft_prefix too)
  // live under the collapsed "Advanced" details and stay editable.
  await dialog.getByText("Advanced", { exact: true }).click();
  await expect(dialog.getByLabel("Main interface", { exact: true })).toBeEnabled();
  await expect(dialog.getByLabel("fwmark", { exact: true })).toBeEnabled();
});

test("Upstream asks for a client first when none exists", async ({ page }) => {
  await mockApi(page, { upstreamEnabled: false });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await expect(page.getByText("Upstream needs at least one client")).toBeVisible();
  await expect(page.locator("label").filter({ hasText: "Mode" })).toHaveCount(0);

  await page.getByRole("button", { name: "Go to Clients", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Clients", exact: true })).toBeVisible();
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
  await page.getByRole("button", { name: "Apply firewall/NAT", exact: true }).click();

  await page.getByRole("button", { name: "Users", exact: true }).click();
  await page.getByLabel("Username").fill("bob");
  await page.getByLabel("Password").fill("secret");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await page.getByRole("button", { name: "Delete user", exact: true }).click();

  await page.getByRole("button", { name: "Sessions", exact: true }).click();
  await page.getByRole("button", { name: "Kick session", exact: true }).click();

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  const routesPanel = page.getByRole("heading", { name: "Routes", exact: true }).locator("../..");
  await routesPanel.locator("textarea").fill("10.30.0.0/16\n203.0.113.9");
  await routesPanel.getByRole("button", { name: "Save", exact: true }).click();

  const observed = mutations.map(({ method, path, csrf }) => ({ method, path, csrf }));
  expect(observed).toEqual(
    expect.arrayContaining([
      { method: "POST", path: "/api/server/start", csrf: "csrf" },
      { method: "POST", path: "/api/server/stop", csrf: "csrf" },
      { method: "POST", path: "/api/config/render", csrf: "csrf" },
      { method: "POST", path: "/api/routing/nft/apply", csrf: "csrf" },
      { method: "POST", path: "/api/users", csrf: "csrf" },
      { method: "DELETE", path: "/api/users/alice", csrf: "csrf" },
      { method: "POST", path: "/api/sessions/alice/kick", csrf: "csrf" },
      { method: "PUT", path: "/api/routing/routes", csrf: "csrf" }
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
  await page.getByRole("table").getByRole("button", { name: "Groups" }).click();
  await expect(page.getByRole("heading", { name: "alice groups" })).toBeVisible();
  const devopsRow = page.locator(".group-choice", { hasText: "devops" });
  await expect(devopsRow.locator("input[type=checkbox]")).not.toBeChecked();
});

test("a client's relay lists are edited in Upstream and sent as arrays", async ({ page }) => {
  // The per-client relay lists (route_clients_enabled/routes/domains) moved
  // from the client dialog to Config → Upstream; they still save through
  // the profile endpoint, with the CSV/newline lists split into arrays.
  const mutations: MockOptions["mutations"] = [];
  await mockApi(page, {
    mutations,
    upstreamEnabled: true,
    upstreamProfiles: [
      {
        name: "finance",
        server: "finance.example.com",
        port: "443",
        auth_type: "password",
        username: "finance-user",
        route_clients_enabled: false,
        enabled: true
      }
    ]
  });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  await page.getByRole("button", { name: "Edit relay lists of finance", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Relay through finance" })).toBeVisible();

  await page.getByLabel("Relay VPN users’ traffic through this client", { exact: true }).check();
  await page.getByLabel("Relay routes", { exact: true }).fill("10.50.0.0/16, 10.60.0.0/16");
  await page
    .getByLabel("Relay domains", { exact: true })
    .fill("internal.example.com\ncorp.example.com");
  await page.getByRole("button", { name: "Save relay lists", exact: true }).click();

  await expect(page.getByRole("heading", { name: "Relay through finance" })).toHaveCount(0);
  const saved = mutations.find(
    (mutation) => mutation.method === "POST" && mutation.path === "/api/upstream/profiles"
  );
  expect(saved).toBeDefined();
  const payload = JSON.parse(saved?.body ?? "{}");
  expect(payload.name).toBe("finance");
  expect(payload.server).toBe("finance.example.com");
  expect(payload.route_clients_enabled).toBe(true);
  expect(payload.routes).toEqual(["10.50.0.0/16", "10.60.0.0/16"]);
  expect(payload.domains).toEqual(["internal.example.com", "corp.example.com"]);
  // Write-only secrets are never resent -- the server keeps the stored ones.
  expect(payload.password).toBeNull();
});

test("a new client starts with every toggle off", async ({ page }) => {
  // Regression test: a freshly created profile used to default to "Turn on
  // Upstream (all profiles)" and "This profile enabled" both checked,
  // meaning saving a brand-new, half-configured profile could silently
  // flip upstream.enabled on globally. Everything now starts opt-in.
  await mockApi(page);
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Clients", exact: true }).click();
  await page.getByRole("button", { name: "Create client", exact: true }).click();
  const dialog = page.getByRole("dialog");

  for (const label of [
    "Turn on Clients (all clients)",
    "This client enabled",
    "Route this host’s traffic through this client",
    "No cert check"
  ]) {
    await expect(dialog.getByLabel(label, { exact: true })).not.toBeChecked();
  }
});

test("editing an existing client keeps the actual Clients-enabled state, not a hardcoded default", async ({
  page
}) => {
  // Regression test: editing any profile used to always show "Turn on
  // Upstream (all profiles)" as checked regardless of the real
  // upstream.enabled, so saving an unrelated edit while Upstream was
  // deliberately off would silently turn it back on.
  await mockApi(page, {
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
  await page.getByRole("button", { name: "Clients", exact: true }).click();
  await page.getByRole("button", { name: "Edit client" }).first().click();

  await expect(
    page.getByRole("dialog").getByLabel("Turn on Clients (all clients)", { exact: true })
  ).not.toBeChecked();
});

test("creating a client can route host traffic, including server-pushed lists", async ({
  page
}) => {
  const mutations: MockOptions["mutations"] = [];
  await mockApi(page, { mutations });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Clients", exact: true }).click();
  await page.getByRole("button", { name: "Create client", exact: true }).click();
  await expect(page.getByRole("heading", { name: "New client" })).toBeVisible();
  // Relaying VPN users' traffic is configured in Upstream, not here.
  await expect(page.getByLabel("Relay routes", { exact: true })).toHaveCount(0);

  await page.getByLabel("Name", { exact: true }).fill("finance");
  await page.getByLabel("Server", { exact: true }).fill("finance.example.com");
  await page.getByLabel("Username", { exact: true }).fill("finance-user");
  await page.getByLabel("Password", { exact: true }).fill("finance-pass");
  await page.getByLabel("Route this host’s traffic through this client", { exact: true }).check();
  await page.getByLabel("Host routes", { exact: true }).fill("10.90.0.0/16");
  await page.getByLabel("Host domains", { exact: true }).fill("finance-internal.corp");
  await page.getByLabel("Use routes and domains pushed by the server", { exact: true }).check();
  await page.getByLabel("Sync URL", { exact: true }).fill("https://10.10.10.1:8443");
  await page.getByLabel("Sync interval (s)", { exact: true }).fill("120");
  await page.getByRole("button", { name: "Save client", exact: true }).click();

  await expect(page.getByRole("heading", { name: "New client" })).toHaveCount(0);
  const saved = mutations.find(
    (mutation) => mutation.method === "POST" && mutation.path === "/api/upstream/profiles"
  );
  expect(saved).toBeDefined();
  const payload = JSON.parse(saved?.body ?? "{}");
  expect(payload.route_host_enabled).toBe(true);
  expect(payload.host_routes).toEqual(["10.90.0.0/16"]);
  expect(payload.host_domains).toEqual(["finance-internal.corp"]);
  expect(payload.accept_server_routes).toBe(true);
  expect(payload.sync_url).toBe("https://10.10.10.1:8443");
  expect(payload.sync_interval).toBe(120);
  expect(payload.sync_verify_tls).toBe(false);
  // route_clients_enabled left at its default draft state (false).
  expect(payload.route_clients_enabled).toBe(false);
});

test("the clients table shows server-pushed lists and syncs them on demand", async ({
  page
}) => {
  const mutations: MockOptions["mutations"] = [];
  await mockApi(page, {
    mutations,
    upstreamEnabled: true,
    upstreamProfiles: [
      {
        name: "office",
        server: "vpn.example.com",
        port: "443",
        auth_type: "password",
        username: "user",
        route_host_enabled: true,
        accept_server_routes: true,
        sync_url: "https://10.10.10.1:8443",
        enabled: true
      }
    ],
    upstreamStatus: {
      active_profile: "office",
      connections: [
        {
          profile: "office",
          interface: "oc-middle0",
          connected: true,
          local_ip: "10.10.10.7",
          remote: "203.0.113.9",
          server_routing: {
            accept: true,
            active: true,
            routes: ["10.20.0.0/16", "10.30.0.0/16"],
            domains: ["corp.example.com"],
            dns: ["10.10.10.1"],
            source: "handshake",
            version: "",
            updated_at: 1,
            synced_at: 0,
            sync_error: "",
            warnings: []
          }
        }
      ]
    }
  });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Clients", exact: true }).click();
  const row = page.locator(".upstream-profiles-panel tbody tr", { hasText: "office" });
  await expect(row.getByText("2 routes / 1 domains")).toBeVisible();
  await expect(row.locator(".pill", { hasText: "received" })).toBeVisible();

  await row.getByRole("button", { name: "Sync server lists now", exact: true }).click();
  await expect
    .poll(() =>
      mutations.some(
        (mutation) =>
          mutation.method === "POST" && mutation.path === "/api/upstream/profiles/office/sync"
      )
    )
    .toBe(true);
});

test("client list shows the default client first, then connected clients, then the rest in order", async ({
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
  await page.getByRole("button", { name: "Clients", exact: true }).click();

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

test("making a different client default asks for confirmation before switching", async ({
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
  await page.getByRole("button", { name: "Clients", exact: true }).click();

  let dialogMessage = "";
  page.once("dialog", (dialog) => {
    dialogMessage = dialog.message();
    void dialog.accept();
  });
  await page
    .locator(".upstream-profiles-panel tbody tr", { hasText: "bravo" })
    .getByRole("button", { name: "Make default client", exact: true })
    .click();

  expect(dialogMessage).toContain("bravo");
  const saved = mutations.find(
    (mutation) => mutation.method === "POST" && mutation.path === "/api/upstream/switch"
  );
  expect(saved).toBeDefined();
  expect(JSON.parse(saved?.body ?? "{}").profile).toBe("bravo");
});

test("toggling host-traffic routing sends host_traffic/host_mode to the API", async ({
  page
}) => {
  const mutations: MockOptions["mutations"] = [];
  await mockApi(page, { mutations, upstreamEnabled: true });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Clients", exact: true }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByText("Host traffic", { exact: true }).click();
  await dialog
    .locator("label")
    .filter({ hasText: "Route this host" })
    .locator("input")
    .check();
  // Not getByLabel: this <select>'s computed accessible name concatenates
  // the label text with its own currently-selected option ("Host
  // modeFull (all host traffic)"), so an exact label match never hits.
  await dialog
    .locator("label")
    .filter({ hasText: "Host mode" })
    .locator("select")
    .selectOption("split");
  await dialog
    .locator("label")
    .filter({ hasText: "Host DNS" })
    .locator("select")
    .selectOption("resolv_conf");
  await dialog.locator('button[type="submit"]').click();
  // onSave awaits three sequential saves (upstream settings, check host,
  // routing settings) before closing the dialog -- wait for that instead of
  // a fixed timeout, since the routing/settings POST is the last of the three.
  await expect(dialog).toHaveCount(0);

  const saved = mutations.find(
    (mutation) => mutation.method === "POST" && mutation.path === "/api/routing/settings"
  );
  expect(saved).toBeDefined();
  const payload = JSON.parse(saved?.body ?? "{}");
  expect(payload.host_traffic).toBe(true);
  expect(payload.host_mode).toBe("split");
  expect(payload.host_dns).toBe("resolv_conf");
});

test("host split routing saves to its own dedicated routes endpoint, not the client's", async ({
  page
}) => {
  const mutations: MockOptions["mutations"] = [];
  await mockApi(page, { mutations, upstreamEnabled: true });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Clients", exact: true }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByText("Host traffic", { exact: true }).click();

  // Host routes/domains fields only appear once host traffic + split mode
  // are both on -- same progressive-disclosure pattern as the client's.
  await expect(dialog.getByRole("heading", { name: "Host routes" })).toHaveCount(0);
  await dialog
    .locator("label")
    .filter({ hasText: "Route this host" })
    .locator("input")
    .check();
  await dialog
    .locator("label")
    .filter({ hasText: "Host mode" })
    .locator("select")
    .selectOption("split");

  const hostRoutesPanel = dialog
    .getByRole("heading", { name: "Host routes", exact: true })
    .locator("../..");
  await hostRoutesPanel.locator("textarea").fill("10.90.0.0/16");
  // Saving triggers a PUT followed by a full state reload, which -- since
  // the mock's /api/config never reflects host_traffic -- resets the draft
  // and makes this whole panel disappear again; wait for the PUT response
  // itself rather than any UI state that won't survive that reload.
  await Promise.all([
    page.waitForResponse(
      (response) =>
        response.url().includes("/api/routing/host-routes") && response.request().method() === "PUT"
    ),
    hostRoutesPanel.getByRole("button", { name: "Save", exact: true }).click()
  ]);

  const savedRoutes = mutations.find(
    (mutation) => mutation.method === "PUT" && mutation.path === "/api/routing/host-routes"
  );
  expect(JSON.parse(savedRoutes?.body ?? "{}").items).toEqual(["10.90.0.0/16"]);
  // Never touched the client's own routes endpoint.
  expect(
    mutations.some((mutation) => mutation.path === "/api/routing/routes" && mutation.method === "PUT")
  ).toBe(false);
});

test("host split domains save to their own dedicated endpoint, not the client's", async ({
  page
}) => {
  const mutations: MockOptions["mutations"] = [];
  await mockApi(page, { mutations, upstreamEnabled: true });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Clients", exact: true }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByText("Host traffic", { exact: true }).click();

  await dialog
    .locator("label")
    .filter({ hasText: "Route this host" })
    .locator("input")
    .check();
  await dialog
    .locator("label")
    .filter({ hasText: "Host mode" })
    .locator("select")
    .selectOption("split");

  const hostDomainsPanel = dialog
    .getByRole("heading", { name: "Host domains", exact: true })
    .locator("../..");
  await hostDomainsPanel.locator("textarea").fill("intranet.example");
  await Promise.all([
    page.waitForResponse(
      (response) =>
        response.url().includes("/api/routing/host-domains") &&
        response.request().method() === "PUT"
    ),
    hostDomainsPanel.getByRole("button", { name: "Save", exact: true }).click()
  ]);

  const savedDomains = mutations.find(
    (mutation) => mutation.method === "PUT" && mutation.path === "/api/routing/host-domains"
  );
  expect(JSON.parse(savedDomains?.body ?? "{}").items).toEqual(["intranet.example"]);
  expect(
    mutations.some(
      (mutation) => mutation.path === "/api/routing/domains" && mutation.method === "PUT"
    )
  ).toBe(false);
});

test("turning off relaying to the default client sends client_traffic: false", async ({
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
      }
    ]
  });
  await signIn(page);

  await page.getByRole("button", { name: "Config", exact: true }).click();
  await page.getByRole("button", { name: "Upstream", exact: true }).click();
  const form = page.locator(".upstream-settings-form");

  // On by default -- Mode select starts visible.
  await expect(
    form.locator("label").filter({ hasText: "Mode" }).first().locator("select")
  ).toBeVisible();
  await form
    .locator("label")
    .filter({ hasText: "Relay VPN users" })
    .locator("input")
    .uncheck();
  // Unchecking hides the now-irrelevant Mode select.
  await expect(
    form.locator("label").filter({ hasText: "Mode" }).first().locator("select")
  ).toHaveCount(0);
  await Promise.all([
    page.waitForResponse(
      (response) =>
        response.url().includes("/api/routing/settings") && response.request().method() === "POST"
    ),
    form.getByRole("button", { name: "Save", exact: true }).click()
  ]);

  const saved = mutations.find(
    (mutation) => mutation.method === "POST" && mutation.path === "/api/routing/settings"
  );
  expect(JSON.parse(saved?.body ?? "{}").client_traffic).toBe(false);
});
