from __future__ import annotations

from pathlib import Path

import pytest

from kornode.config.models import AppConfig
from kornode.main import initialize_runtime
from kornode.services.net import NetApplyError


class FailingNetService:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def converge(self) -> dict[str, object]:
        raise NetApplyError("kernel did not converge: OSError: permission denied")


def test_initialize_runtime_aborts_when_the_kernel_does_not_converge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "log_dir": tmp_path / "logs",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    monkeypatch.setattr("kornode.main.load_config", lambda _path: config)
    monkeypatch.setattr("kornode.main.NetService", FailingNetService)
    monkeypatch.setattr("kornode.main.prepare_startup_letsencrypt", lambda cfg, *_a: cfg)

    with pytest.raises(SystemExit) as exc:
        initialize_runtime(tmp_path / "config.yaml")

    assert "failed to converge kernel networking state" in str(exc.value)
    assert "permission denied" in str(exc.value)


class QuietNetService:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def converge(self) -> dict[str, object]:
        return {}


def test_initialize_runtime_leaves_everything_ocserv_needs_to_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The rendered ocserv.conf names the CA, the server and interlink certificates and the CRL
    (D-71): a fresh hub must have all of them once initialize_runtime returns."""
    config = AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "log_dir": tmp_path / "logs",
                "secrets_dir": tmp_path / "secrets",
            }
        }
    )
    monkeypatch.setattr("kornode.main.load_config", lambda _path: config)
    monkeypatch.setattr("kornode.main.NetService", QuietNetService)
    monkeypatch.setattr("kornode.main.prepare_startup_letsencrypt", lambda cfg, *_a: cfg)

    from kornode.services.certificates import CertificateService
    from test_certificates import WritingRunner

    monkeypatch.setattr(
        "kornode.main.CertificateService",
        lambda cfg, files: CertificateService(cfg, files=files, runner=WritingRunner()),
    )
    initialize_runtime(tmp_path / "config.yaml")

    for name in ("ca.crt", "ca.key", "server.crt", "interlink.crt", "interlink.key", "crl.pem"):
        assert config.cert_path(name).is_file(), name
    rendered = (config.system.generated_dir / "ocserv.conf").read_text(encoding="utf-8")
    assert f"[vhost:{config.interlink.server_name}]" in rendered


@pytest.mark.parametrize("existing", ["ca.key", "ca.crt"])
def test_partial_ca_aborts_before_any_runtime_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing: str,
) -> None:
    config = AppConfig.model_validate({"system": {"data_dir": tmp_path}})
    path = config.cert_path(existing)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"original")
    monkeypatch.setattr("kornode.main.load_config", lambda _path: config)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("partial CA must abort before network/config/certificate changes")

    monkeypatch.setattr("kornode.main._converge_kernel", forbidden)
    monkeypatch.setattr("kornode.main.prepare_startup_letsencrypt", forbidden)
    monkeypatch.setattr("kornode.main.CertificateService", forbidden)
    with pytest.raises(SystemExit, match="incomplete CA state"):
        initialize_runtime(tmp_path / "config.yaml")
    assert path.read_bytes() == b"original"
