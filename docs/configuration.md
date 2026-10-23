# Configuration model

Main config path:

```text
/etc/kornode/config.yaml
```

Default data paths:

```text
/etc/kornode/config.yaml
/var/lib/kornode/
/var/lib/kornode/secrets/
/var/lib/kornode/certs/
/var/lib/kornode/generated/
/var/log/kornode/
```

## Precedence

1. CLI overrides.
2. YAML config (explicit values, including empty lists).
3. Process environment variables.
4. `.env` file.
5. Application defaults.

Environment values fill omitted YAML fields; they do not override values already
saved in YAML. API/CLI saves preserve `${SECRET:NAME}` references so rotation in
the environment continues to take effect.

## Environment variable mapping

Use prefix:

```text
KORNODE_
```

Nested keys are joined with `__`:

```text
server.port -> KORNODE_SERVER__PORT
web.enabled -> KORNODE_WEB__ENABLED
routing.host_dns -> KORNODE_ROUTING__HOST_DNS
```

Lists can be overridden as JSON:

```text
KORNODE_SERVER__DNS='["8.8.8.8", "1.1.1.1"]'
KORNODE_EGRESS='[]'
KORNODE_SOURCES='[]'
KORNODE_SETS='{"corp":{"routes":["10.20.0.0/16"],"domains":["corp.example"]}}'
```

`.env` files support plain `KEY=value`, optional `export KEY=value`, single or double quoted
values, and inline comments after unquoted values:

```dotenv
export KORNODE_SERVER__REALM="Corp # VPN"
KORNODE_SERVER__CN=vpn.example.com # comment
```

Secret references:

```yaml
password: "${SECRET:ADMIN_PASSWORD}"
```

The loader must resolve this from environment variables without logging the value.

## Validation

Validate:

- required paths;
- port ranges;
- CIDR validity;
- route overlap;
- VPN subnet not equal to upstream private subnet;
- domain syntax;
- files readable/writable depending on operation;
- mode compatibility.

## Config rendering

Generated files must be written into a generated directory, e.g.:

```text
/var/lib/kornode/generated/ocserv.conf
/var/lib/kornode/generated/dnsmasq.conf
/var/lib/kornode/generated/nftables.nft
/var/lib/kornode/generated/supervisor.conf
```

Write atomically:

1. render to temp file;
2. fsync if practical;
3. validate syntax where possible;
4. rename into place.
