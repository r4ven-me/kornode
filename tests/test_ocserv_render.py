from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
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
    # The built-in resolver is mandatory while server.enabled, pushed at its
    # auto-computed listen address for this customized ipv4_network (see
    # AppConfig.migrate_legacy_dns_keys) -- not server.dns's 1.1.1.1.
    assert "dns = 10.77.0.1" in rendered
    assert "route = 192.168.1.0/24" in rendered
    assert 'auth = "certificate"' in rendered
    # Agent login belongs to the interlink vhost only (D-71), not to the client host.
    client_host = rendered.partition("[vhost:")[0]
    assert "enable-auth" not in client_host
    assert "cert-group-oid" not in client_host
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


def _interlink_config(tmp_path: Path, **overrides: object) -> AppConfig:
    return load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            **overrides,
        },
        environ={},
    )


def test_ocserv_render_puts_agents_on_a_interlink_vhost(tmp_path: Path) -> None:
    config = _interlink_config(
        tmp_path,
        auth={
            "password": {"enabled": True},
            "certificate": {"enabled": True},
            "oidc": {"enabled": True, "connector": "pam"},
        },
    )

    rendered = OcservConfigRenderer().render(config)
    head, _, vhost = rendered.partition("[vhost:interlink.kornode.lan]")

    # The client host keeps every client login method and none of the interlink ones.
    assert f'auth = "plain[passwd={config.secret_path("ocpasswd")}]"' in head
    assert 'auth = "certificate"' in head
    assert 'auth = "pam[' in head
    assert "enable-auth" not in head
    assert "cert-group-oid" not in head
    # The vhost is the last section: its options end the file.
    assert vhost
    assert f'auth = "plain[passwd={config.secret_path("ocpasswd-enroll")}]"' in vhost
    assert 'enable-auth = "certificate"' in vhost
    assert "cert-user-oid = 2.5.4.3" in vhost
    assert "cert-group-oid = 2.5.4.11" in vhost
    assert f"server-cert = {config.cert_path('interlink.crt')}" in vhost
    assert f"ca-cert = {config.cert_path('ca.crt')}" in vhost
    assert "pam[" not in vhost
    assert "[vhost:" not in vhost


def test_ocserv_render_vhost_has_no_global_only_options(tmp_path: Path) -> None:
    """D-83: ocserv >= 1.4.2 (the image builds 1.5.0) refuses to start on a global-only
    option inside a vhost; the vhost inherits the ports (and DTLS) from the default host."""
    config = _interlink_config(tmp_path)

    head, _, vhost = OcservConfigRenderer().render(config).partition("[vhost:")

    assert f"udp-port = {config.server.port}" in head
    for option in ("udp-port", "tcp-port", "listen-host", "socket-file", "run-as-user"):
        assert not re.search(rf"^{option}\s*=", vhost, re.MULTILINE), option


def test_connect_script_interlink_guard(tmp_path: Path) -> None:
    config = _interlink_config(tmp_path, auth={"password": {"enabled": True}})

    rendered = OcservConfigRenderer().render_connect_script(config)
    assert "# Interlink guard (D-43, D-71)" in rendered
    assert "hook failures here are deliberately swallowed" in rendered
    assert rendered.index("# Interlink guard") < rendered.index("korctl_bin=")

    script = tmp_path / "connect.sh"
    script.write_text(rendered, encoding="utf-8")
    empty_path = tmp_path / "bin"
    empty_path.mkdir()
    # Only agents with a config-per-user file (= active in the registry) get in.
    user_dir = tmp_path / "generated" / "config-per-user"
    user_dir.mkdir(parents=True)
    (user_dir / "agent-3").write_text("explicit-ipv4 = 10.99.0.3\n", encoding="utf-8")
    interlink = config.interlink.server_name
    cases = [
        # interlink vhost: only agents and enroll sessions
        ({"VHOST": interlink, "GROUPNAME": ""}, 1),
        ({"VHOST": interlink, "GROUPNAME": "agents", "USERNAME": "agent-3"}, 0),
        ({"VHOST": interlink, "GROUPNAME": "agents", "USERNAME": "agent-4"}, 1),
        ({"VHOST": interlink, "GROUPNAME": "agents", "USERNAME": "alice"}, 1),
        ({"VHOST": interlink, "GROUPNAME": "agents", "USERNAME": "agent-03"}, 1),
        ({"VHOST": interlink, "GROUPNAME": "enroll", "USERNAME": "enroll-3-x"}, 0),
        ({"VHOST": interlink, "GROUPNAME": "enroll", "USERNAME": "bob"}, 1),
        ({"VHOST": interlink, "GROUPNAME": "clients", "USERNAME": "alice"}, 1),
        # client host: any login except a session in an interlink group; a user without
        # a group (OIDC) is fine there
        ({"VHOST": "", "GROUPNAME": "clients", "USERNAME": "alice"}, 0),
        ({"VHOST": "", "GROUPNAME": "", "USERNAME": "alice"}, 0),
        ({"GROUPNAME": "", "USERNAME": "alice"}, 0),
        ({"VHOST": "", "GROUPNAME": "agents", "USERNAME": "agent-3"}, 1),
        ({"VHOST": "", "GROUPNAME": "enroll", "USERNAME": "enroll-3-x"}, 1),
        # reserved user names are refused on the client host whatever the group: the
        # agent-N config-per-user files (explicit-ipv4) are global to every vhost
        ({"VHOST": "", "GROUPNAME": "", "USERNAME": "agent-3"}, 1),
        ({"VHOST": "", "GROUPNAME": "clients", "USERNAME": "agent-3"}, 1),
        ({"GROUPNAME": "", "USERNAME": "agent-3"}, 1),
        ({"VHOST": "", "GROUPNAME": "", "USERNAME": "enroll-x"}, 1),
        ({"VHOST": "", "GROUPNAME": "", "USERNAME": "agentsmith"}, 0),
    ]
    for env, expected in cases:
        result = subprocess.run(
            ["/bin/sh", str(script)],
            check=False,
            capture_output=True,
            env={**env, "PATH": os.fspath(empty_path)},
            text=True,
        )
        assert result.returncode == expected, (env, result)


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

    assert f"oath[usersfile={config.secret_path('users.oath')}]" in rendered


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
        - 10.100.1.1
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
    assert "dns = 10.100.1.1" in group_rendered
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
    assert (config.identity.config_per_group_dir / "admins").read_text(encoding="utf-8").count(
        "route = 10.40.0.0/16"
    ) == 1


def test_ocserv_render_includes_internal_dns_forward_domains_in_split_dns(
    tmp_path: Path,
) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "internal_dns": {
                "forward_upstreams": ["127.207.207.1"],
                "forward_domains": ["r4ven.lan"],
            },
        },
        environ={},
    )

    rendered = OcservConfigRenderer().render(config)

    assert "split-dns = r4ven.lan" in rendered
    # default-domain stays tied to search_domains, not to forward zones.
    assert "default-domain" not in rendered


def test_ocserv_render_dedupes_split_dns_shared_between_search_and_forward(
    tmp_path: Path,
) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "secrets_dir": str(tmp_path / "secrets"),
            },
            "server": {"search_domains": ["r4ven.lan"]},
            "internal_dns": {
                "forward_upstreams": ["127.207.207.1"],
                "forward_domains": ["r4ven.lan"],
            },
        },
        environ={},
    )

    rendered = OcservConfigRenderer().render(config)

    assert rendered.count("split-dns = r4ven.lan") == 1


def test_control_only_hub_refuses_every_client_login_but_keeps_the_agents_vhost(
    tmp_path: Path,
) -> None:
    """`server.clients: false`: ocserv stays up for agents; the default host serves nobody."""
    normal = _interlink_config(
        tmp_path,
        auth={"password": {"enabled": True}, "certificate": {"enabled": True}},
    )
    control = _interlink_config(
        tmp_path,
        server={"clients": False},
        auth={"password": {"enabled": True}, "certificate": {"enabled": True}},
    )
    marker = "[vhost:interlink.kornode.lan]"

    head, _, vhost = OcservConfigRenderer().render(control).partition(marker)
    _, _, normal_vhost = OcservConfigRenderer().render(normal).partition(marker)

    # Only a deny-all method (the plain module over the, normally empty, ocpasswd file).
    auth_lines = re.findall(r'^auth = "(.*)"$', head, re.MULTILINE)
    assert auth_lines == [f"plain[passwd={control.secret_path('ocpasswd')}]"]
    assert "cert-user-oid" not in head and "select-group" not in head.replace(
        "select-group-by-url", ""
    )
    # The agents' host is byte-for-byte what a normal hub renders.
    assert vhost == normal_vhost
    assert f"server-cert = {control.cert_path('interlink.crt')}" in vhost


def test_control_only_connect_script_refuses_the_default_host_and_nothing_else(
    tmp_path: Path,
) -> None:
    config = _interlink_config(tmp_path, server={"clients": False})
    script = tmp_path / "connect.sh"
    script.write_text(OcservConfigRenderer().render_connect_script(config), encoding="utf-8")
    empty_path = tmp_path / "bin"
    empty_path.mkdir()
    user_dir = tmp_path / "generated" / "config-per-user"
    user_dir.mkdir(parents=True)
    (user_dir / "agent-3").write_text("explicit-ipv4 = 10.99.0.3\n", encoding="utf-8")
    interlink = config.interlink.server_name
    cases = [
        ({"VHOST": "", "GROUPNAME": "clients", "USERNAME": "alice"}, 1),
        ({"VHOST": "", "GROUPNAME": "", "USERNAME": "alice"}, 1),
        ({"GROUPNAME": "", "USERNAME": "alice"}, 1),  # no VHOST at all: the default host
        ({"VHOST": interlink, "GROUPNAME": "agents", "USERNAME": "agent-3"}, 0),
        ({"VHOST": interlink, "GROUPNAME": "enroll", "USERNAME": "enroll-3-x"}, 0),
        ({"VHOST": interlink, "GROUPNAME": "clients", "USERNAME": "alice"}, 1),
    ]
    for env, expected in cases:
        result = subprocess.run(
            ["/bin/sh", str(script)],
            check=False,
            capture_output=True,
            env={**env, "PATH": os.fspath(empty_path)},
            text=True,
        )
        assert result.returncode == expected, (env, result)


def test_hub_that_accepts_clients_renders_as_before(tmp_path: Path) -> None:
    """The flag defaults to true and changes nothing for existing hubs."""
    default = _interlink_config(tmp_path)
    assert default.server.clients is True
    script = OcservConfigRenderer().render_connect_script(default)
    assert "__DEFAULT_HOST__" not in script and "    exit 1\n    case" not in script
