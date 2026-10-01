import { afterEach, describe, expect, it, vi } from "vitest";

import {
  applyInternalDns,
  login,
  saveAuthMethodsSettings,
  saveInternalDnsSettings,
  saveRoutingSettings,
  saveUpstreamProfile,
  setCsrfToken,
  testOtpEmail,
  testOtpTelegram,
  writeRenderedConfig,
  type UpstreamProfileDraft
} from "./api";

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
  route_clients_enabled: false,
  routes: "",
  domains: "",
  routesFilesText: "",
  routesUrlsText: "",
  domainsFilesText: "",
  domainsUrlsText: "",
  route_host_enabled: false,
  host_routes: "",
  host_domains: "",
  accept_server_routes: false,
  sync_url: "",
  sync_interval: "60",
  sync_verify_tls: false,
  routing_offset: "",
  enable: true,
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

describe("saveUpstreamProfile server routing fields", () => {
  it("sends the sync settings normalized, a blank sync URL as null", async () => {
    const fetchMock = vi.fn().mockImplementation(
      async () =>
        new Response(JSON.stringify({ status: "saved" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveUpstreamProfile("session", {
      ...upstreamProfileDraft,
      accept_server_routes: true,
      sync_url: " https://10.10.10.1:8443 ",
      sync_interval: "120",
      sync_verify_tls: true
    });
    await saveUpstreamProfile("session", { ...upstreamProfileDraft, sync_interval: "" });

    const withSync = JSON.parse(String((fetchMock.mock.calls[0] as [string, RequestInit])[1].body));
    expect(withSync.accept_server_routes).toBe(true);
    expect(withSync.sync_url).toBe("https://10.10.10.1:8443");
    expect(withSync.sync_interval).toBe(120);
    expect(withSync.sync_verify_tls).toBe(true);
    const blank = JSON.parse(String((fetchMock.mock.calls[1] as [string, RequestInit])[1].body));
    expect(blank.sync_url).toBeNull();
    expect(blank.sync_interval).toBe(60);
  });
});

describe("saveUpstreamProfile", () => {
  it("splits the newline/comma-separated routes and domains textareas into arrays", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveUpstreamProfile("session", {
      ...upstreamProfileDraft,
      routes: "10.50.0.0/16, 10.60.0.0/16\n10.70.0.0/16",
      domains: "internal.example.com,\ncorp.example.com"
    });

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/upstream/profiles");
    const sent = JSON.parse(String(init.body));
    expect(sent.routes).toEqual(["10.50.0.0/16", "10.60.0.0/16", "10.70.0.0/16"]);
    expect(sent.domains).toEqual(["internal.example.com", "corp.example.com"]);
  });

  it("splits the host routes/domains textareas the same way as the client ones", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveUpstreamProfile("session", {
      ...upstreamProfileDraft,
      route_host_enabled: true,
      host_routes: "10.90.0.0/16, 10.91.0.0/16",
      host_domains: "finance-internal.corp"
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(String(init.body));
    expect(sent.host_routes).toEqual(["10.90.0.0/16", "10.91.0.0/16"]);
    expect(sent.host_domains).toEqual(["finance-internal.corp"]);
  });

  it("sends routing_offset as a number, or null when left blank", async () => {
    const fetchMock = vi.fn().mockImplementation(
      async () =>
        new Response(JSON.stringify({ status: "saved" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveUpstreamProfile("session", { ...upstreamProfileDraft, routing_offset: "5" });
    await saveUpstreamProfile("session", { ...upstreamProfileDraft, routing_offset: " " });

    const sent = fetchMock.mock.calls.map(([, init]) => JSON.parse(String((init as RequestInit).body)));
    expect(sent[0].routing_offset).toBe(5);
    expect(sent[1].routing_offset).toBeNull();
  });

  it("sends an empty array, not a list with a blank string, for an empty textarea", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveUpstreamProfile("session", upstreamProfileDraft);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(String(init.body));
    expect(sent.routes).toEqual([]);
    expect(sent.domains).toEqual([]);
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
      resolver_enabled: true,
      listen: "10.10.10.1",
      port: 53,
      blocklist_enabled: true,
      local_records_enabled: true,
      server_dns: ["9.9.9.9"],
      search_domains: ["corp.example"],
      tunnel_dns: true,
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
  it("sends host_traffic/host_mode alongside the rest of the routing payload", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await saveRoutingSettings("session", {
      client_traffic: true,
      mode: "split",
      tunnel_dns: true,
      host_traffic: true,
      host_mode: "split",
      host_dns: "resolv_conf",
      main_interface: "auto",
      fwmark: "0x0c01",
      table_id: 1201,
      nft_prefix: "kornode",
      routes_files: [],
      routes_urls: [],
      domains_files: [],
      domains_urls: [],
      host_routes_files: [],
      host_routes_urls: [],
      host_domains_files: [],
      host_domains_urls: []
    });

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/routing/settings");
    const sent = JSON.parse(String(init.body));
    expect(sent.host_traffic).toBe(true);
    expect(sent.host_mode).toBe("split");
    expect(sent.host_dns).toBe("resolv_conf");
  });
});
