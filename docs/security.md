# Security requirements

## Defaults

- Web GUI disabled by default.
- Admin bootstrap required before GUI/API write operations.
- Bind GUI to localhost by default if enabled without explicit listen address.
- Do not expose GUI on `0.0.0.0` without an explicit config value.
- Built-in HTTPS is enabled by default whenever the optional GUI is enabled.
- Reverse proxy mode must explicitly set `web.tls: false` and
  `web.allow_insecure_http: true`; keep that HTTP listener private. Configure
  `web.trusted_proxies` with the proxy IP/CIDR so forwarded headers are trusted
  only from that proxy. `trusted_proxies` is a blanket trust setting, not scoped to
  the admin API alone: it also governs which `X-Forwarded-For` value is trusted for
  login rate-limiting (`api/auth.py`) and for the unauthenticated VPN-client-facing
  `/api/client/routing` endpoint's IP-based identification. Only list a proxy that
  strictly overwrites (never appends to or passes through) the `X-Forwarded-For`
  header from anything it forwards, and that itself only accepts connections from
  trusted sources -- otherwise a client able to reach that proxy could spoof another
  VPN user's source IP or bypass the login lockout.
- Browser authentication uses an `HttpOnly`, `SameSite=Strict`, secure cookie and
  CSRF token. Basic authentication remains available for non-browser API clients.
- Interactive terminal access is disabled by default and has idle/session limits.
- Terminal tickets are one-time, terminal sessions are audited, and xterm.js talks
  directly to a bounded PTY WebSocket without rendering command output as HTML.

## Secrets

Never log:

- admin password;
- user password;
- p12 passphrase;
- OTP seed;
- OIDC client secret;
- private keys;
- Telegram token;
- SMTP password;
- upstream VPN password.

Implement secret masking centrally.

## Filesystem permissions

Use restrictive modes:

- private keys: `0600`;
- secrets directory: `0700`;
- generated public configs: `0644` only where safe;
- logs: avoid secrets.

## Command execution

- Use explicit argv lists.
- Use timeouts.
- Capture stdout/stderr safely.
- Mask command arguments in logs.
- Return structured errors.

## Audit log

Log administrative actions:

- user created/deleted;
- password changed;
- certificate generated/revoked;
- config applied;
- routing changed;
- upstream switched;
- session kicked.

Audit log must not contain secrets.

The JSON-lines audit log is stored at `/var/log/kornode/audit.jsonl` with mode `0600`.
It records the actor, action, outcome, source address and non-secret metadata.

## OIDC caveat

VPN clients do not complete a normal browser redirect OIDC flow against ocserv directly.
Use a PAM or RADIUS bridge backed by Keycloak/authentik for production deployments.
