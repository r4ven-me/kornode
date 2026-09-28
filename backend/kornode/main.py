from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import yaml

from kornode.config.loader import DEFAULT_CONFIG_PATH, load_config
from kornode.config.models import AppConfig
from kornode.services.certificates import CertificateService
from kornode.services.command import CommandError
from kornode.services.config import ConfigService
from kornode.services.files import FileManager
from kornode.services.nftables import NftablesService
from kornode.services.server_certificates import ServerCertificateService


def unlink_stale_runtime_sockets(generated_dir: Path) -> None:
    for path in [
        generated_dir / "supervisor.sock",
        generated_dir / "occtl.sock",
        *generated_dir.glob("ocserv.sock*"),
        *generated_dir.glob("occtl.sock*"),
    ]:
        if path.is_socket():
            path.unlink(missing_ok=True)


def initialize_runtime(config_path: Path | None = None) -> None:
    resolved_config_path = config_path or DEFAULT_CONFIG_PATH
    config = load_config(resolved_config_path)
    files = FileManager()
    files.ensure_dir(config.system.data_dir)
    files.ensure_dir(config.system.log_dir)
    files.ensure_dir(config.system.generated_dir)
    files.ensure_dir(config.system.secrets_dir, mode=0o700)
    unlink_stale_runtime_sockets(config.system.generated_dir)
    config = prepare_startup_letsencrypt(config, resolved_config_path, files)
    ConfigService(files).write_rendered_files(config)
    NftablesService(config, files=files).apply()

    certs = CertificateService(config, files=files)
    if not config.cert_path("ca.key").exists() or not config.cert_path("ca.crt").exists():
        certs.init_ca()

    if config.certificates.mode == "auto":
        server_key_missing = not config.cert_path("server.key").exists()
        server_cert_missing = not config.cert_path("server.crt").exists()
        if server_key_missing or server_cert_missing:
            certs.create_server_certificate()


def prepare_startup_letsencrypt(
    config: AppConfig,
    config_path: Path | None,
    files: FileManager,
) -> AppConfig:
    le = config.certificates.letsencrypt
    if not (le.enabled and le.email and le.domains):
        return config
    service = ServerCertificateService(config, files=files)
    paths = service.letsencrypt_paths(le.domains[0])
    cert_missing = not paths.server_cert.exists()
    key_missing = not paths.server_key.exists()
    if cert_missing or key_missing:
        try:
            service.issue_letsencrypt(email=le.email, domains=le.domains)
        except CommandError as exc:
            _write_startup_warning(
                config.system.log_dir / "startup.log",
                "Let's Encrypt startup issue failed; continuing with existing/default "
                f"certificates.\n{exc.result.stderr or exc.result.stdout}\n",
            )
            return config
    patch: dict[str, Any] = {
        "mode": "external",
        "server_cert": str(paths.server_cert),
        "server_key": str(paths.server_key),
        # ocserv's ca-cert verifies client certificates, which are always signed by the
        # local CA (see CertificateService.create_user_certificate), not by Let's Encrypt.
        "ca_cert": str(config.cert_path("ca.crt")),
        "letsencrypt": {
            "enabled": True,
            "email": le.email,
            "domains": le.domains,
            "renew_reload": le.renew_reload,
            "auto_renew_enabled": le.auto_renew_enabled,
            "auto_renew_interval": le.auto_renew_interval,
            "auto_renew_interval_unit": le.auto_renew_interval_unit,
        },
    }
    if config_path is not None:
        _persist_certificate_patch(config_path, patch, files)
        return load_config(config_path)
    return AppConfig.model_validate({"certificates": patch})


def _persist_certificate_patch(
    config_path: Path,
    patch: dict[str, Any],
    files: FileManager,
) -> None:
    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        data = cast(dict[str, Any], loaded if isinstance(loaded, dict) else {})
    else:
        data = {}
    certificates = data.setdefault("certificates", {})
    if not isinstance(certificates, dict):
        raise ValueError("certificates config must be a mapping")
    certificates.update(patch)
    files.atomic_write_text(config_path, yaml.safe_dump(data, sort_keys=False), mode=0o600)


def _write_startup_warning(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(message.rstrip() + "\n")


def run() -> None:
    config_path_env = os.getenv("KORNODE_CONFIG")
    config_path = Path(config_path_env) if config_path_env else None
    initialize_runtime(config_path)
    config = load_config(config_path)
    supervisor_conf = config.generated_path("supervisor.conf")
    os.execvp("supervisord", ["supervisord", "-c", str(supervisor_conf)])


if __name__ == "__main__":
    run()
