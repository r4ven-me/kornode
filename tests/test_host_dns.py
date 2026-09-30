from __future__ import annotations

from pathlib import Path

from kornode.config.models import AppConfig
from kornode.services.host_dns import MARK, HostDnsService

ORIGINAL = "nameserver 192.168.1.1\nsearch lan\n"


def _config(tmp_path: Path, host_dns: str, *, dnsmasq: bool = True, port: int = 53) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "data_dir": tmp_path / "data",
                "generated_dir": tmp_path / "generated",
                "secrets_dir": tmp_path / "secrets",
            },
            "routing": {"host_dns": host_dns},
            "internal_dns": {"resolver_enabled": dnsmasq, "port": port},
        }
    )


def _service(tmp_path: Path, config: AppConfig) -> HostDnsService:
    return HostDnsService(
        config,
        resolv_conf=tmp_path / "host" / "resolv.conf",
        resolved_dir=tmp_path / "host" / "resolved.conf.d",
    )


def _mount_resolv(tmp_path: Path) -> Path:
    path = tmp_path / "host" / "resolv.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ORIGINAL)
    return path


def test_resolv_conf_mode_points_host_at_dnsmasq_and_keeps_a_backup(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)
    service = _service(tmp_path, _config(tmp_path, "resolv_conf"))

    result = service.apply()

    assert result.changed
    assert "nameserver 10.10.10.1" in resolv.read_text()
    assert service.backup_path.read_text() == ORIGINAL
    assert service.apply().changed is False


def test_resolv_conf_is_reasserted_after_an_external_rewrite(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)
    service = _service(tmp_path, _config(tmp_path, "resolv_conf"))
    service.apply()
    resolv.write_text("nameserver 192.168.1.254\n")  # DHCP renewal

    assert service.apply().changed
    assert "nameserver 10.10.10.1" in resolv.read_text()
    # The newest host configuration is what comes back on restore.
    assert service.backup_path.read_text() == "nameserver 192.168.1.254\n"


def test_restore_puts_the_original_back(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)
    service = _service(tmp_path, _config(tmp_path, "resolv_conf"))
    service.apply()

    assert service.restore().changed
    assert resolv.read_text() == ORIGINAL
    assert service.restore().changed is False


def test_turning_host_dns_off_restores_resolv_conf(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)
    _service(tmp_path, _config(tmp_path, "resolv_conf")).apply()

    _service(tmp_path, _config(tmp_path, "off")).apply()

    assert resolv.read_text() == ORIGINAL


def test_host_is_never_pointed_at_a_dnsmasq_that_does_not_run(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)
    _service(tmp_path, _config(tmp_path, "resolv_conf")).apply()

    result = _service(tmp_path, _config(tmp_path, "resolv_conf", dnsmasq=False)).apply()

    assert "not running" in result.detail
    assert resolv.read_text() == ORIGINAL


def test_resolv_conf_mode_reports_a_missing_mount(tmp_path: Path) -> None:
    result = _service(tmp_path, _config(tmp_path, "resolv_conf")).apply()

    assert result.changed is False
    assert "not mounted" in result.detail


def test_resolv_conf_mode_refuses_a_non_standard_port(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)

    result = _service(tmp_path, _config(tmp_path, "resolv_conf", port=5353)).apply()

    assert "port" in result.detail
    assert resolv.read_text() == ORIGINAL


def test_resolved_mode_writes_a_dropin_and_off_removes_it(tmp_path: Path) -> None:
    dropin_dir = tmp_path / "host" / "resolved.conf.d"
    dropin_dir.mkdir(parents=True)
    service = _service(tmp_path, _config(tmp_path, "resolved", port=5353))

    result = service.apply()

    content = (dropin_dir / "kornode.conf").read_text()
    assert result.changed and "systemctl restart systemd-resolved" in result.detail
    assert MARK in content and "DNS=\nDNS=10.10.10.1:5353\nDomains=~.\n" in content

    _service(tmp_path, _config(tmp_path, "off")).apply()
    assert not (dropin_dir / "kornode.conf").exists()


def test_resolved_mode_leaves_a_foreign_dropin_alone(tmp_path: Path) -> None:
    dropin_dir = tmp_path / "host" / "resolved.conf.d"
    dropin_dir.mkdir(parents=True)
    (dropin_dir / "kornode.conf").write_text("[Resolve]\nDNS=9.9.9.9\n")

    _service(tmp_path, _config(tmp_path, "off")).apply()

    assert (dropin_dir / "kornode.conf").exists()


def test_restore_also_removes_a_resolved_dropin(tmp_path: Path) -> None:
    # Regression test: restore() (called by host-dns-guard on SIGTERM, i.e.
    # container shutdown) used to only restore resolv.conf, leaving a
    # systemd-resolved drop-in behind forever in "resolved" mode -- the host
    # would keep being told to send DNS to a dnsmasq that just stopped.
    dropin_dir = tmp_path / "host" / "resolved.conf.d"
    dropin_dir.mkdir(parents=True)
    service = _service(tmp_path, _config(tmp_path, "resolved", port=5353))
    service.apply()
    assert (dropin_dir / "kornode.conf").exists()

    result = service.restore()

    assert result.changed
    assert "drop-in removed" in result.detail
    assert not (dropin_dir / "kornode.conf").exists()
    assert service.restore().changed is False


def test_restore_reports_both_when_resolv_conf_and_dropin_are_both_present(
    tmp_path: Path,
) -> None:
    # An admin could in principle have leftovers from both modes (e.g. after
    # switching routing.host_dns back and forth, or restore() itself having
    # skipped the drop-in on a previous kornode version); restore() must
    # clean up both in one pass and say so.
    resolv = _mount_resolv(tmp_path)
    dropin_dir = tmp_path / "host" / "resolved.conf.d"
    dropin_dir.mkdir(parents=True)
    service = _service(tmp_path, _config(tmp_path, "resolv_conf"))
    service.apply()
    # Written directly rather than via a second apply(): apply() itself
    # undoes the OTHER mode's leftovers as part of switching (see its own
    # docstring), which would defeat the point of this test -- restore()
    # must not depend on that ever having run.
    (dropin_dir / "kornode.conf").write_text(f"{MARK}: leftover\n[Resolve]\nDNS=10.10.10.1\n")

    result = service.restore()

    assert result.changed
    assert "resolv.conf restored" in result.detail
    assert "drop-in removed" in result.detail
    assert resolv.read_text() == ORIGINAL
    assert not (dropin_dir / "kornode.conf").exists()


def test_status_reports_mounts(tmp_path: Path) -> None:
    _mount_resolv(tmp_path)
    service = _service(tmp_path, _config(tmp_path, "resolv_conf"))
    service.apply()

    status = service.status()

    assert status["resolv_conf_mounted"] is True
    assert status["resolv_conf_managed"] is True
    assert status["resolved_dir_mounted"] is False
