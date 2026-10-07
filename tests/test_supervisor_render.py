from __future__ import annotations

from pathlib import Path

from kornode.config.loader import load_config
from kornode.renderers.supervisor import SupervisorConfigRenderer


def test_supervisor_render_supports_supervisorctl(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            }
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "[unix_http_server]" in rendered
    assert "[rpcinterface:supervisor]" in rendered
    assert "[supervisorctl]" in rendered
    assert f"serverurl=unix://{tmp_path}/generated/supervisor.sock" in rendered
    assert "username=kornodectl" in rendered
    assert "password=kornodectl-local" in rendered
    assert "stdout_logfile=" in rendered
    assert "redirect_stderr=true" in rendered
    assert ".err.log" not in rendered


def test_supervisor_render_adds_certbot_auto_renew(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            },
            "certificates": {
                "letsencrypt": {
                    "enabled": True,
                    "domains": ["vpn.example.com"],
                    "auto_renew_enabled": True,
                    "auto_renew_interval": 7,
                    "auto_renew_interval_unit": "days",
                }
            },
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "[program:certbot-renew]" in rendered
    assert "certbot --config-dir" in rendered
    assert "renew --reuse-key" in rendered
    assert "sleep 604800" in rendered


def test_supervisor_render_certbot_interval_units(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            },
            "certificates": {
                "letsencrypt": {
                    "enabled": True,
                    "domains": ["vpn.example.com"],
                    "auto_renew_enabled": True,
                    "auto_renew_interval": 2,
                    "auto_renew_interval_unit": "months",
                }
            },
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "sleep 5184000" in rendered


def test_supervisor_render_always_includes_log_rotation_loop(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            }
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "[program:log-rotation]" in rendered
    assert "korctl logs-rotate" in rendered


def test_supervisor_render_always_includes_domain_resolver(tmp_path: Path) -> None:
    # Always registered, like host-dns-guard/log-rotation: a no-op cycle
    # when there's nothing configured to resolve, so turning split routing
    # on in the panel needs no supervisord restart.
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            }
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "[program:domain-resolver]" in rendered
    assert "korctl domains watch" in rendered


def test_supervisor_render_enables_web_tls_by_default(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "data_dir": str(tmp_path / "data"),
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            },
            "web": {"enabled": True, "admin_password": "secret"},
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "[program:api]" in rendered
    assert f"--ssl-certfile {tmp_path}/data/certs/server.crt" in rendered
    assert f"--ssl-keyfile {tmp_path}/data/certs/server.key" in rendered
    assert "server.key\nautorestart=true" in rendered


def test_supervisor_render_supports_reverse_proxy_http(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            },
            "web": {
                "enabled": True,
                "tls": False,
                "allow_insecure_http": True,
                "admin_password": "secret",
            },
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "[program:api]" in rendered
    assert "--ssl-certfile" not in rendered
    assert "--ssl-keyfile" not in rendered


def test_supervisor_render_adds_upstream_watchdog_when_enabled(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            },
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "primary",
                        "server": "vpn.example.com",
                        "auth_type": "password",
                        "username": "user",
                    }
                ],
            },
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "[program:upstream-watchdog]" in rendered
    assert "command=/usr/local/bin/korctl upstream watch" in rendered


def test_supervisor_render_omits_upstream_watchdog_when_disabled(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            }
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "[program:upstream-watchdog]" not in rendered


def test_supervisor_render_enables_proxy_headers_for_trusted_proxies(tmp_path: Path) -> None:
    config = load_config(
        tmp_path / "missing.yaml",
        cli_overrides={
            "system": {
                "generated_dir": str(tmp_path / "generated"),
                "log_dir": str(tmp_path / "logs"),
            },
            "web": {
                "enabled": True,
                "admin_password": "secret",
                "trusted_proxies": ["127.0.0.1", "172.18.0.0/16"],
            },
        },
        environ={},
    )

    rendered = SupervisorConfigRenderer().render(config)

    assert "--proxy-headers" in rendered
    assert "--forwarded-allow-ips 127.0.0.1,172.18.0.0/16" in rendered
