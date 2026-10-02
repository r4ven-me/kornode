from __future__ import annotations

from pathlib import Path

from kornode.config.env import parse_dotenv_file
from kornode.config.loader import load_config


def test_parse_dotenv_file_handles_common_dotenv_syntax(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        """
# comments and empty lines are ignored
export KORNODE_SERVER__REALM="Corp # VPN"
KORNODE_SERVER__CN=vpn.example.com # inline comment
KORNODE_WEB__ADMIN_PASSWORD='hash#kept'
KORNODE_CERTIFICATES__CA_NAME="Line\\nTwo"
INVALID-KEY=ignored
""",
        encoding="utf-8",
    )

    values = parse_dotenv_file(env_path)

    assert values == {
        "KORNODE_SERVER__REALM": "Corp # VPN",
        "KORNODE_SERVER__CN": "vpn.example.com",
        "KORNODE_WEB__ADMIN_PASSWORD": "hash#kept",
        "KORNODE_CERTIFICATES__CA_NAME": "Line\nTwo",
    }


def test_yaml_overrides_env_while_process_env_overrides_dotenv(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    env_path = tmp_path / ".env"
    config_path.write_text(
        """
server:
  port: 443
  dns:
    - 8.8.8.8
web:
  enabled: false
""",
        encoding="utf-8",
    )
    env_path.write_text(
        "KORNODE_SERVER__PORT=4443\n"
        "KORNODE_SERVER__REALM=Dotenv Realm\n"
        "KORNODE_WEB__ENABLED=true\n",
        encoding="utf-8",
    )

    config = load_config(
        config_path,
        env_file=env_path,
        environ={
            "KORNODE_SERVER__DNS": '["1.1.1.1", "9.9.9.9"]',
            "KORNODE_SERVER__REALM": "Process Realm",
            "KORNODE_WEB__ENABLED": "true",
        },
    )

    assert config.server.port == 443
    assert config.server.dns == ["8.8.8.8"]
    assert config.server.realm == "Process Realm"
    assert config.web.enabled is False


def test_cli_overrides_env(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        environ={"KORNODE_SERVER__PORT": "4443"},
        cli_overrides={"server": {"port": 10443}},
    )

    assert config.server.port == 10443


def test_numeric_password_env_override_stays_string(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        environ={
            "KORNODE_WEB__ENABLED": "true",
            "KORNODE_WEB__ADMIN_PASSWORD": "12345678",
        },
    )

    assert config.web.admin_password == "12345678"
