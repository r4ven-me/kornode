import { afterEach, describe, expect, it, vi } from "vitest";

import {
  applyInternalDns,
  applyNetPlan,
  login,
  saveAuthMethodsSettings,
  saveFabricSettings,
  saveInternalDnsSettings,
  saveRoutingSettings,
  saveUpstreamProfile,
  setCsrfToken,
  testOtpEmail,
  testOtpTelegram,
  writeRenderedConfig,
  type UpstreamProfileDraft
} from "./api";
import { netDriftCount, netPlanLines } from "./lib/net";

afterEach(() => {
  setCsrfToken(null);
  vi.unstubAllGlobals();
});

describe("browser API authentication", () => {
  it("uses a same-origin cookie login without an Authorization header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          authenticated: true,
          username: "admin",
          csrf_token: "csrf-value"
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )
    );
    vi.stubGlobal("fetch", fetchMock);

    await login("admin", "secret");

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(path).toBe("/api/auth/login");
    expect(init.credentials).toBe("same-origin");
    expect(headers.has("Authorization")).toBe(false);
    expect(JSON.parse(String(init.body))).toEqual({
      username: "admin",
      password: "secret"
    });
  });

  it("adds the CSRF header to mutating requests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ written: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("csrf-value");

    await writeRenderedConfig("session");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(init.method).toBe("POST");
    expect(headers.get("X-Kornode-CSRF")).toBe("csrf-value");
  });
});

const upstreamProfileDraft: UpstreamProfileDraft = {
  name: "finance",
  kind: "openconnect",
  server: "finance.example.com",
  port: "443",
  interface: "oc-finance",
  auth_type: "password",
  trusted_cert: false,
  username: "user",
  password: "",
  cert_file: "",
  cert_file_base64: "",
  key_file: "",
  key_file_base64: "",
  cert_pass: "",
  server_cert_pin: "",
  check_host: "",
  camouflage_secret: "",
  enabled: true
};

const authMethodsPayload = {
  password_enabled: true,
  certificate_enabled: false,
  otp_enabled: true,
  otp_ocserv_oath_auth: false,
  otp_issuer: "Korvus Node",
  otp_send_by_email: true,
  otp_send_by_telegram: true,
  otp_smtp_host: "smtp.example.com",
  otp_smtp_port: 587,
  otp_smtp_username: "mailer",
  otp_smtp_password: "smtp-secret",
  otp_smtp_from: "vpn@example.com",
  otp_smtp_starttls: true,
  otp_smtp_test_recipient: "admin@example.com",
  otp_telegram_bot_token: "bot-secret",
  otp_telegram_chat_id: "123456"
};

describe("OTP delivery settings API", () => {
  it.each([
    ["save", saveAuthMethodsSettings, "/api/server/auth-settings"],
    ["email test", testOtpEmail, "/api/server/auth-settings/test-email"],
    ["Telegram test", testOtpTelegram, "/api/server/auth-settings/test-telegram"]
  ])("sends the complete flattened payload for %s", async (_name, action, expectedPath) => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await action("session", authMethodsPayload);

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe(expectedPath);
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual(authMethodsPayload);
  });
});

describe("saveFabricSettings", () => {
  it("sends the structured fabric payload", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveFabricSettings("session", {
      node_id: 3,
      cidr: "10.99.0.0/24",
      client_pool: "10.100.{id}.0/24",
      source_pool: "10.8.{id}.0/24",
      enroll_pool: "10.99.255.240/28",
      domain: "kornode.internal",
      reserved: ["10.200.0.0/16"]
    });

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/fabric");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(String(init.body))).toEqual({
      node_id: 3,
      cidr: "10.99.0.0/24",
      client_pool: "10.100.{id}.0/24",
      source_pool: "10.8.{id}.0/24",
      enroll_pool: "10.99.255.240/28",
      domain: "kornode.internal",
      reserved: ["10.200.0.0/16"]
    });
  });
});

describe("saveUpstreamProfile", () => {
  it("sends no v1 routing fields", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveUpstreamProfile("session", upstreamProfileDraft);

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/upstream/profiles");
    const sent = JSON.parse(String(init.body));
    for (const key of [
      "route_clients_enabled", "routes", "domains", "routes_urls", "domains_urls",
      "route_host_enabled", "host_routes", "host_domains", "accept_server_routes",
      "sync_url", "sync_interval", "sync_verify_tls", "routing_offset"
    ]) {
      expect(sent).not.toHaveProperty(key);
    }
  });
});

describe("internal DNS settings API", () => {
  it("saves and applies the complete DNS draft atomically", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ status: "saved_and_applied", reconnect_required: false, commands: [] }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      )
    );
    vi.stubGlobal("fetch", fetchMock);
    const payload = {
      listen: "10.10.10.1",
      port: 53,
      blocklist_enabled: true,
      local_records_enabled: true,
      server_dns: ["9.9.9.9"],
      search_domains: ["corp.example"],
      upstreams: ["9.9.9.9"],
      forward_upstreams: ["1.1.1.1"],
      forward_domains: ["example.com"],
      blocklist_domains: ["ads.example"],
      blocklist_files: [],
      blocklist_urls: [],
      cache_size: 150,
      log_queries: false,
      local_records: ["nas.corp.example 10.0.0.2"]
    };

    await saveInternalDnsSettings("session", payload);

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/internal-dns/settings");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual(payload);
  });

  it("applies DNS changes through the dedicated action", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await applyInternalDns("session");

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/internal-dns/apply");
    expect(init.method).toBe("POST");
  });
});

describe("saveRoutingSettings", () => {
  it("sends only host_dns and main_interface", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveRoutingSettings("session", { host_dns: "resolv_conf", main_interface: "auto" });

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/routing/settings");
    expect(JSON.parse(String(init.body))).toEqual({
      host_dns: "resolv_conf",
      main_interface: "auto"
    });
  });
});

describe("network API", () => {
  it("posts the dry-run flag when applying the network plan", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ applied: false, dry_run: true, ops: [], warnings: [], exits: [], schema_hash: null }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await applyNetPlan("session", true);

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/net/apply");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ dry_run: true });
  });
});

describe("network view helpers", () => {
  it("uses the kernel match line when a plan has no operations", () => {
    expect(netPlanLines([])).toEqual(["kernel matches the compiled policy"]);
  });

  it("sums reconciler drift counters", () => {
    expect(netDriftCount({ running: true, drift: { rules: 2, routes: 3 } })).toBe(5);
  });
});
