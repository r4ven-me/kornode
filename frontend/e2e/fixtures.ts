import { expect, type Page } from "@playwright/test";

const commandResult = {
  argv: ["korctl", "server", "status"],
  returncode: 0,
  stdout: "ocserv RUNNING\n",
  stderr: "",
  dry_run: false
};

type MockUser = {
  username: string;
  disabled: boolean;
  certificate_exists: boolean;
  p12_exists: boolean;
  groups?: string[];
};

export type MockOptions = {
  terminalEnabled?: boolean;
  users?: MockUser[];
  // Returned starting from the second GET /api/users onward, to simulate
  // membership changing out-of-band (CLI, another admin session) between the
  // initial page load and a later re-fetch.
  usersAfterFirstFetch?: MockUser[];
  groups?: Array<{ name: string; config_exists: boolean; has_settings: boolean }>;
  otpRecords?: Array<{ username: string; enabled: boolean }>;
  sessions?: Array<{
    username: string;
    vpn_ip: string | null;
    real_ip: string | null;
    device: string | null;
    rx: string | null;
    tx: string | null;
    rx_rate: string | null;
    tx_rate: string | null;
    duration_seconds: number | null;
  }>;
  routes?: string[];
  domains?: string[];
  hostRoutes?: string[];
  hostDomains?: string[];
  mutations?: Array<{ method: string; path: string; csrf: string | null; body: string | null }>;
  initialServerState?: "running" | "stopped";
  routingMode?: "full" | "split";
  upstreamEnabled?: boolean;
  upstreamProfiles?: Array<Record<string, unknown>>;
  upstreamStatus?: Record<string, unknown>;
  // Extra top-level sections merged into GET /api/config (server, web,
  // system, upstream, ...), for checking that forms hydrate from it.
  config?: Record<string, unknown>;
  letsEncrypt?: Record<string, unknown>;
  logFiles?: Array<{ name: string; size: number }>;
};

export async function mockApi(page: Page, options: MockOptions = {}) {
  let authenticated = false;
  let serverState = options.initialServerState ?? "running";
  let userFetchCount = 0;
  const users = options.users ?? [];
  const groups = options.groups ?? [];
  const otpRecords = options.otpRecords ?? [];
  const sessions = options.sessions ?? [];
  const routes = options.routes ?? [];
  const domains = options.domains ?? [];
  const hostRoutes = options.hostRoutes ?? [];
  const hostDomains = options.hostDomains ?? [];
  const mutations = options.mutations ?? [];
  await page.route("**/healthz", (route) =>
    route.fulfill({ json: { status: "ok", version: "0.1.0" } })
  );
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/api/auth/login") {
      authenticated = true;
      await route.fulfill({
        json: { authenticated: true, username: "admin", csrf_token: "csrf" }
      });
      return;
    }
    if (path === "/api/auth/me") {
      await route.fulfill({
        status: authenticated ? 200 : 401,
        json: authenticated
          ? { authenticated: true, username: "admin", csrf_token: "csrf" }
          : { detail: "authentication required" }
      });
      return;
    }
    if (method !== "GET") {
      mutations.push({
        method,
        path,
        csrf: route.request().headers()["x-kornode-csrf"] ?? null,
        body: route.request().postData()
      });
    }
    if (path === "/api/server/start") {
      serverState = "running";
    }
    if (path === "/api/server/stop") {
      serverState = "stopped";
    }
    if (path === "/api/users" && method === "GET") {
      userFetchCount += 1;
    }
    const currentUsers =
      userFetchCount <= 1 || !options.usersAfterFirstFetch ? users : options.usersAfterFirstFetch;
    const serverStatus = {
      ...commandResult,
      stdout: serverState === "running" ? "ocserv RUNNING\n" : "ocserv STOPPED\n"
    };
    const responses: Record<string, unknown> = {
      "/api/server/status": serverStatus,
      "/api/server/processes": [],
      "/api/server/start": commandResult,
      "/api/server/stop": commandResult,
      "/api/server/reload": commandResult,
      "/api/server/restart": commandResult,
      "/api/users": method === "GET" ? currentUsers : commandResult,
      "/api/groups": groups,
      "/api/users/otp": otpRecords,
      "/api/sessions": sessions,
      "/api/routing/routes":
        method === "GET" ? routes : JSON.parse(route.request().postData() ?? "{}").items ?? [],
      "/api/routing/domains":
        method === "GET" ? domains : JSON.parse(route.request().postData() ?? "{}").items ?? [],
      "/api/routing/settings": { status: "ok" },
      "/api/routing/routes/status": { files: [], urls: [] },
      "/api/routing/domains/status": { files: [], urls: [] },
      "/api/routing/routes/refresh": {
        status: "refreshed",
        url: "",
        total_lines: 0,
        valid: 0,
        skipped: 0,
        sample: [],
        saved: true,
        written: []
      },
      "/api/routing/domains/refresh": {
        status: "refreshed",
        url: "",
        total_lines: 0,
        valid: 0,
        skipped: 0,
        sample: [],
        saved: true,
        written: []
      },
      "/api/routing/host-routes":
        method === "GET"
          ? hostRoutes
          : JSON.parse(route.request().postData() ?? "{}").items ?? [],
      "/api/routing/host-domains":
        method === "GET"
          ? hostDomains
          : JSON.parse(route.request().postData() ?? "{}").items ?? [],
      "/api/routing/host-routes/status": { files: [], urls: [] },
      "/api/routing/host-domains/status": { files: [], urls: [] },
      "/api/routing/host-routes/refresh": {
        status: "refreshed",
        url: "",
        total_lines: 0,
        valid: 0,
        skipped: 0,
        sample: [],
        saved: true,
        written: []
      },
      "/api/routing/host-domains/refresh": {
        status: "refreshed",
        url: "",
        total_lines: 0,
        valid: 0,
        skipped: 0,
        sample: [],
        saved: true,
        written: []
      },
      "/api/routing/reload": [commandResult],
      "/api/routing/nft": commandResult,
      "/api/routing/nft/apply": [commandResult],
      "/api/routing/nft/cleanup": [commandResult],
      "/api/internal-dns/status": {
        enabled: false,
        blocklist_enabled: false,
        local_records_enabled: false,
        listen: "10.10.10.1",
        port: 53,
        client_dns: ["1.1.1.1", "8.8.8.8"],
        forward_upstreams: [],
        forward_domains: [],
        blocklist_domains: [],
        blocklist_files: [],
        blocklist_urls: [],
        total: 0,
        cache_size: 150,
        log_queries: false,
        local_records: []
      },
      "/api/internal-dns/settings": {
        status: "saved_and_applied",
        reconnect_required: false,
        commands: []
      },
      "/api/upstream/status": {
        enabled: options.upstreamEnabled ?? false,
        active_profile: null,
        interface: "oc-middle0",
        connected: false,
        local_ip: null,
        remote: null,
        connections: [],
        ...options.upstreamStatus
      },
      "/api/upstream": options.upstreamProfiles ?? [],
      "/api/upstream/settings": { status: "ok" },
      "/api/upstream/profiles": { status: "ok" },
      "/api/upstream/profiles/office/sync": {
        status: "synced",
        server_routing: {
          accept: true,
          active: true,
          routes: ["10.20.0.0/16"],
          domains: [],
          dns: [],
          source: "sync",
          version: "v2",
          updated_at: 2,
          synced_at: 2,
          sync_error: "",
          warnings: []
        }
      },
      "/api/upstream/connect": commandResult,
      "/api/upstream/fetch-pin": {
        pin: "pin-sha256:UPSTREAMpin0000000000000000000000000000000=",
        sha256: "sha256:00"
      },
      "/api/certificates/server-pin": {
        path: "/var/lib/kornode/certs/server.crt",
        pin: "pin-sha256:THISserverPin00000000000000000000000000000=",
        sha256: "sha256:ab"
      },
      "/api/upstream/disconnect": commandResult,
      "/api/identity": {
        auth: {
          enabled: false,
          connector: "pam",
          pam: { service: "ocserv", gid_min: null },
          radius: {
            config_file: "/etc/radiusclient/radiusclient.conf",
            groupconfig: true,
            nas_identifier: null,
            group_separator: "semicolon"
          }
        },
        oidc_providers: [],
        group_policies: [],
        config_per_group_dir: null,
        select_group_by_url: false,
        default_select_group: null,
        default_group_config: null
      },
      "/api/config": {
        auth: {
          password: { enabled: true },
          certificate: { enabled: false },
          otp: {
            enabled: true,
            issuer: "Korvus Node",
            send_by_email: false,
            send_by_telegram: false,
            smtp_port: 587,
            smtp_starttls: true
          }
        },
        routing: { mode: options.routingMode ?? "full", split: {} },
        web: { terminal_enabled: options.terminalEnabled ?? false },
        ...options.config
      },
      "/api/config/source": {
        path: "/etc/kornode/config.yaml",
        exists: true,
        content: "web:\n  enabled: true\n"
      },
      "/api/config/render": {},
      "/api/config/source/validate": {},
      "/api/config/diff": { diff: "" },
      "/api/auth/totp/status": { enabled: false },
      "/api/diagnostics": {},
      "/api/diagnostics/software": [],
      "/api/diagnostics/interface-stats": { interface: null, rx_bytes: null, tx_bytes: null },
      "/api/logs/files": options.logFiles ?? [],
      "/api/logs": {
        name: new URL(route.request().url()).searchParams.get("name") ?? "",
        lines: Number(new URL(route.request().url()).searchParams.get("lines") ?? 0),
        content: "log line one\nlog line two\n"
      },
      "/api/logs/rotation": {
        enabled: false,
        max_size_mb: 50,
        max_age: 0,
        max_age_unit: "days",
        keep_files: 5
      },
      "/api/certificates": {
        mode: "auto",
        active: {
          server_cert: "",
          server_key: "",
          ca_cert: "",
          server_cert_exists: true,
          server_key_exists: true,
          ca_cert_exists: true
        },
        authority: {
          ca_cert: "",
          ca_key: "",
          ca_cert_exists: true,
          ca_key_exists: true
        },
        external: {
          server_cert: "",
          server_key: "",
          ca_cert: "",
          server_cert_exists: false,
          server_key_exists: false,
          ca_cert_exists: false
        },
        letsencrypt: {
          enabled: false,
          email: null,
          domains: [],
          renew_reload: true,
          auto_renew_enabled: true,
          auto_renew_interval: 7,
          auto_renew_interval_unit: "days",
          http01_address: null,
          http01_port: 80,
          paths: null,
          ...options.letsEncrypt
        },
        certbot_available: true
      }
    };
    if (/^\/api\/users\/[^/]+$/.test(path) && method === "DELETE") {
      await route.fulfill({ json: commandResult });
      return;
    }
    if (/^\/api\/users\/[^/]+\/(password|enable|disable|cert|p12)$/.test(path)) {
      await route.fulfill({
        json: path.endsWith("/cert") && method === "POST" ? { results: [commandResult] } : commandResult
      });
      return;
    }
    if (/^\/api\/users\/[^/]+\/otp$/.test(path)) {
      await route.fulfill({ json: { status: "ok" } });
      return;
    }
    if (/^\/api\/(users|groups)\/[^/]+\/config$/.test(path) && method !== "GET") {
      await route.fulfill({ json: commandResult });
      return;
    }
    if (/^\/api\/sessions\/[^/]+\/kick$/.test(path)) {
      await route.fulfill({ json: commandResult });
      return;
    }
    await route.fulfill({ json: responses[path] ?? { status: "ok" } });
  });
}

export async function signIn(page: Page) {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("secret");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
}
