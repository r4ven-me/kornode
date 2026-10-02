# AGENTS.md

You are working on a production-grade OpenConnect VPN management platform.

Project name: `kornode`.

## Main objective

Rewrite the existing OpenConnect/ocserv Docker project from scratch into a clean, maintainable platform with:

- Python backend;
- Python CLI available at all times;
- optional Web GUI built with Node.js and TypeScript;
- YAML-first configuration;
- full environment variable and `.env` override support;
- Docker image build files;
- support for both normal ocserv VPN server mode and middle-server mode.

## Source materials to study first

Before coding, read and extract behavior from:

- https://github.com/r4ven-me/openconnect-middle-server
- https://github.com/r4ven-me/openconnect
- https://gitlab.com/openconnect/ocserv/-/blob/master/doc/sample.config
- https://r4ven.me/networking/podnimaem-openconnect-ssl-vpn-server-ocserv-v-docker-dlya-vnutrennih-proektov/
- https://r4ven.me/networking/nastraivaem-openconnect-middle-server-dlya-dostupa-k-zakrytomu-konturu/
- https://r4ven.me/networking/podklyuchenie-openwrt-k-openconnect-serveru/
- https://r4ven.me/virtualization/sobiraem-openconnect-ocserv-versii-1-3-iz-ishodnikov-v-debian-12-docker-obraz/

## Hard requirements

- Do not copy old shell scripts as-is.
- Design a proper architecture: config models, service layer, command runner, renderers, API, CLI, GUI.
- CLI must work even when Web GUI is disabled.
- Web GUI must be disabled by default.
- All application config values must be configurable through environment variables and `.env` when omitted from YAML.
- CLI flags override YAML, YAML overrides env, env overrides application defaults.
- Never log secrets.
- Never print passphrases, tokens, passwords or private key material.
- Prefer explicit subprocess argument lists over shell commands.
- Use `shell=True` only when unavoidable and document why.
- All generated system configuration must be idempotent.
- Use atomic file writes for generated configs and secrets.
- Do not destroy user files without explicit CLI/API action.
- Support dry-run for dangerous network changes.
- Mark runtime-dependent operations clearly in code and docs.

## GUI ⇄ config parity

- Every field in `AppConfig` (`backend/kornode/config/models.py`) must have a corresponding
  structured control in the web panel — a labeled input/select/checkbox bound to that field,
  not just reachability through the raw YAML "Config" tab editor.
- When you add a new config field, add its GUI control (and settings-save endpoint, following
  the existing `apply_config_patch` pattern in `backend/kornode/api/routes_config.py`) in the
  same change. Do not let the two drift apart.
- Documented exceptions (stay YAML-only, on purpose):
  - deploy-time paths fixed via `.env`/volume mounts at container start:
    `system.data_dir`, `system.log_dir`, `system.generated_dir`, `system.secrets_dir`,
    `identity.config_per_group_dir`, `identity.config_per_user_dir`,
    `web.tls_cert`, `web.tls_key`, `web.static_dir`,
    `routing.split.routes_file`, `routing.split.domains_file`,
    `routing.host_split.routes_file`, `routing.host_split.domains_file` (internal generated-state
    paths, the same category as the others above — not something an admin edits day to
    day; the runtime *contents* of these files are what the Upstream tab's route/domain
    list actually edits);
  - `advanced.raw_ocserv_options` — a free-form escape hatch by design, not a fixed field a
    form can validate meaningfully;
  - `web.admin_password` / `web.admin_password_hash` — go through a dedicated
    change-password action, not a plain-text field in a general settings dump;
  - `web.admin_totp_enabled` / `web.admin_totp_secret` — same pattern as
    `admin_password`/`admin_password_hash`: managed entirely through the panel's own
    two-factor setup/confirm/disable flow (`/api/auth/totp/*`), not a plain-text field in
    a general settings dump.

## Target stack

Backend:

- Python 3.12+
- FastAPI
- Pydantic v2
- Typer or Click for CLI
- Jinja2 for config templates
- python-dotenv or equivalent
- PyYAML or ruamel.yaml
- pytest
- ruff
- mypy

Frontend:

- Node.js
- TypeScript
- Vite
- React, Vue or Svelte
- API client generated or typed manually from OpenAPI

Runtime tools:

- ocserv
- openconnect client
- occtl
- ocpasswd
- certtool / GnuTLS
- oathtool / oath-toolkit
- qrencode
- dnsmasq
- nftables
- iproute2
- curl/wget for healthchecks

Container:

- Dockerfile
- compose.yaml
- healthcheck
- `/dev/net/tun`
- `NET_ADMIN`
- `NET_RAW`
- persistent volumes for config, data, secrets, certificates and logs.

## Coding style

- Typed Python.
- Small modules.
- No giant Bash entrypoint.
- Bash is allowed only for tiny container bootstrapping if Python is not appropriate.
- Domain logic must be reusable by CLI and API.
- CLI and API must call the same services.
- Frontend must not duplicate backend validation rules when avoidable.
- All command output parsing must be isolated and tested.

## Deliverables

The finished repository must contain:

- `backend/kornode/` Python package;
- `frontend/` GUI source;
- `templates/` for ocserv, dnsmasq, nftables, supervisor/s6 configs;
- `Dockerfile`;
- `compose.yaml`;
- `config.example.yaml`;
- `.env.example`;
- `README.md`;
- `docs/`;
- `tests/`;
- `Makefile`;
- CI-friendly lint/test commands.
