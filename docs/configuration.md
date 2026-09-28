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

1. CLI flags.
2. Environment variables.
3. `.env` file.
4. YAML config.
5. Application defaults.

## Environment variable mapping

Use prefix:

```text
KORNODE_
```

Nested keys are joined with `__`:

```text
server.port -> KORNODE_SERVER__PORT
web.enabled -> KORNODE_WEB__ENABLED
routing.split.tunnel_dns -> KORNODE_ROUTING__SPLIT__TUNNEL_DNS
```

Lists can be overridden as JSON:

```text
KORNODE_SERVER__DNS='["8.8.8.8", "1.1.1.1"]'
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
