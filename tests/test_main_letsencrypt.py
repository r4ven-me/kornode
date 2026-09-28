from __future__ import annotations

from pathlib import Path

import yaml

from kornode.config.loader import load_config
from kornode.main import prepare_startup_letsencrypt
from kornode.services.files import FileManager
from kornode.services.server_certificates import ServerCertificateService


def _write_config(config_path: Path, tmp_path: Path) -> None:
    config_path.write_text(
        yaml.safe_dump(
            {
                "system": {
                    "data_dir": str(tmp_path / "data"),
                    "generated_dir": str(tmp_path / "generated"),
                    "log_dir": str(tmp_path / "logs"),
                    "secrets_dir": str(tmp_path / "secrets"),
                },
                "certificates": {
                    "letsencrypt": {
                        "enabled": True,
                        "email": "admin@example.com",
                        "domains": ["vpn.example.com"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )


def test_prepare_startup_letsencrypt_keeps_local_ca_for_client_verification(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, tmp_path)
    config = load_config(config_path)
    files = FileManager()

    # Pre-seed the certbot "live" files so issuance is skipped and we can
    # observe the config patch that activates the certificate.
    paths = ServerCertificateService(config, files=files).letsencrypt_paths(
        "vpn.example.com"
    )
    files.ensure_dir(paths.server_cert.parent, mode=0o700)
    files.atomic_write_text(paths.server_cert, "fullchain\n", mode=0o600)
    files.atomic_write_text(paths.server_key, "privkey\n", mode=0o600)
    files.atomic_write_text(paths.ca_cert, "chain\n", mode=0o600)

    updated = prepare_startup_letsencrypt(config, config_path, files)

    assert updated.certificates.mode == "external"
    assert updated.certificates.server_cert == paths.server_cert
    assert updated.certificates.server_key == paths.server_key
    # ca-cert must stay the locally managed CA (used to verify client
    # certificates) rather than Let's Encrypt's issuer chain, otherwise
    # certificate-based client auth breaks.
    assert updated.certificates.ca_cert == config.cert_path("ca.crt")
    assert updated.certificates.ca_cert != paths.ca_cert
