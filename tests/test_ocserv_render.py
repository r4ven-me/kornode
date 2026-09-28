from __future__ import annotations

from pathlib import Path

from kornode.config.loader import load_config
from kornode.renderers.ocserv import OcservConfigRenderer
from kornode.services.config import ConfigService


def test_ocserv_render_contains_core_options(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
server:
  port: 10443
  ipv4_network: 10.77.0.0/24
  dns:
    - 1.1.1.1
  routes:
    - 192.168.1.0/24
auth:
  password:
    enabled: true
  certificate:
    enabled: true
""",
        encoding="utf-8",
    )
    config = load_config(config_path, environ={})

    rendered = OcservConfigRenderer().render(config)

    assert "tcp-port = 10443" in rendered
    assert "device = vpns" in rendered
    assert "use-occtl = true" in rendered
    assert f"occtl-socket-file = {config.generated_path('occtl.sock')}" in rendered
    assert f"socket-file = {config.generated_path('ocserv.sock')}" in rendered
    assert "cert-user-oid = 2.5.4.3" in rendered
    assert "realm =" not in rendered
    assert "ipv4-network = 10.77.0.0/24" in rendered
    assert "dns = 1.1.1.1" in rendered
    assert "route = 192.168.1.0/24" in rendered
    assert 'auth = "certificate"' in rendered
    assert "log-level = 2" in rendered


def test_ocserv_render_contains_new_tuning_directives_with_defaults(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            }
        },
        environ={},
    )

    rendered = OcservConfigRenderer().render(config)

    assert "dpd = 90" in rendered
    assert "mobile-dpd = 1800" in rendered
    assert "isolate-workers = true" in rendered
    assert "try-mtu-discovery = true" in rendered
    assert "predictable-ips = true" in rendered
    assert "deny-roaming = false" in rendered
    assert "ping-leases = false" in rendered
    assert "dtls-legacy = true" in rendered
    assert "client-bypass-protocol = false" in rendered
    assert "rate-limit-ms = 200" in rendered
    assert "server-stats-reset-time = 604800" in rendered
    assert "switch-to-tcp-timeout = 25" in rendered
    assert "auth-timeout = 240" in rendered
    assert "cookie-timeout = 600" in rendered
    assert "rekey-time = 172800" in rendered
    assert "rekey-method = ssl" in rendered
    assert "ban-time = 300" in rendered
    assert "max-ban-score = 80" in rendered
    assert "ban-reset-time = 1200" in rendered
    assert "tls-priorities =" not in rendered


def test_ocserv_render_emits_quoted_tls_priorities_when_set(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "server": {"tls_priorities": "NORMAL:%SERVER_PRECEDENCE:-VERS-TLS1.0"},
        },
        environ={},
    )

    rendered = OcservConfigRenderer().render(config)

    assert 'tls-priorities = "NORMAL:%SERVER_PRECEDENCE:-VERS-TLS1.0"' in rendered


def test_ocserv_render_can_override_cert_user_oid(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
server:
  cert_user_oid: "0.9.2342.19200300.100.1.1"
auth:
  certificate:
    enabled: true
""",
        encoding="utf-8",
    )
    config = load_config(config_path, environ={})

    rendered = OcservConfigRenderer().render(config)

    assert "cert-user-oid = 0.9.2342.19200300.100.1.1" in rendered


def test_ocserv_render_omits_debug_directive_when_disabled(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "server": {"debug_level": 0},
        },
        environ={},
    )

    rendered = OcservConfigRenderer().render(config)

    assert "log-level =" not in rendered


def test_config_service_writes_atomically(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            }
        },
        environ={},
    )

    written = ConfigService().write_rendered_files(config)

    assert config.generated_path("ocserv.conf") in written
    assert config.generated_path("ocserv.conf").exists()


def test_ocserv_render_omits_oath_auth_unless_runtime_backend_is_enabled(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
auth:
  password:
    enabled: true
  otp:
    enabled: true
    ocserv_oath_auth: false
""",
        encoding="utf-8",
    )
    config = load_config(config_path, environ={})

    rendered = OcservConfigRenderer().render(config)

    assert "users.oath" not in rendered
    assert 'auth = "plain' in rendered


def test_ocserv_render_can_enable_oath_auth_explicitly(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
auth:
  password:
    enabled: true
  otp:
    enabled: true
    ocserv_oath_auth: true
""",
        encoding="utf-8",
    )
    config = load_config(config_path, environ={})

    rendered = OcservConfigRenderer().render(config)

    assert f'oath[usersfile={config.secret_path("users.oath")}]' in rendered


def test_ocserv_render_includes_user_config_without_group_policies(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "identity": {
                "config_per_user_dir": str(tmp_path / "generated" / "users"),
                "group_policies": [],
            },
        },
        environ={},
    )

    rendered = OcservConfigRenderer().render(config)

    assert f"config-per-user = {tmp_path}/generated/users" in rendered
    assert f"config-per-group = {tmp_path}/generated/config-per-group" in rendered


def test_ocserv_render_supports_oidc_pam_and_group_policies(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
system:
  data_dir: {tmp_path}/data
  generated_dir: {tmp_path}/generated
  secrets_dir: {tmp_path}/secrets
auth:
  password:
    enabled: false
  oidc:
    enabled: true
    connector: pam
    pam:
      service: ocserv-oidc
      gid_min: 1000
identity:
  config_per_group_dir: {tmp_path}/generated/groups
  select_group_by_url: true
  default_select_group: devops
  group_policies:
    - name: devops
      display_name: DevOps
      routes:
        - 10.20.0.0/16
      dns:
        - 10.10.10.1
      split_dns:
        - corp.example.com
      max_same_clients: 4
""",
        encoding="utf-8",
    )
    config = load_config(config_path, environ={})

    rendered = OcservConfigRenderer().render(config)
    group_rendered = OcservConfigRenderer().render_group_policy(config.identity.group_policies[0])

    assert 'auth = "pam[service=ocserv-oidc,gid-min=1000]"' in rendered
    assert f"config-per-group = {tmp_path}/generated/groups" in rendered
    assert "select-group = devops[DevOps]" in rendered
    assert "select-group-by-url = true" in rendered
    assert "default-select-group = devops" in rendered
    assert "route = 10.20.0.0/16" in group_rendered
    assert "dns = 10.10.10.1" in group_rendered
    assert "split-dns = corp.example.com" in group_rendered


def test_config_service_renders_group_policy_files(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "identity": {
                "config_per_group_dir": str(tmp_path / "generated" / "groups"),
                "group_policies": [{"name": "admins", "routes": ["10.40.0.0/16"]}],
            },
        },
        environ={},
    )

    written = ConfigService().write_rendered_files(config)

    assert config.identity.config_per_group_dir / "admins" in written
    assert (config.identity.config_per_group_dir / "admins").read_text(
        encoding="utf-8"
    ).count("route = 10.40.0.0/16") == 1
