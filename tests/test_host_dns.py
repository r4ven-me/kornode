from __future__ import annotations

from pathlib import Path

import pytest

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
            # dnsmasq now runs automatically whenever server.enabled -- there
            # is no separate opt-in switch left, see AppConfig.dns_tunnel_active().
            "server": {"enabled": dnsmasq},
            "internal_dns": {"port": port},
        }
    )


def _service(tmp_path: Path, config: AppConfig) -> HostDnsService:
    return HostDnsService(
        config,
        resolv_conf=tmp_path / "host" / "resolv.conf",
        resolved_dir=tmp_path / "host" / "resolved.conf.d",
        readiness_probe=lambda: True,
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
    assert "nameserver 10.100.1.1" in resolv.read_text()
    assert service.backup_path.read_text() == ORIGINAL
    assert service.apply().changed is False


def test_resolv_conf_is_reasserted_after_an_external_rewrite(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)
    service = _service(tmp_path, _config(tmp_path, "resolv_conf"))
    service.apply()
    resolv.write_text("nameserver 192.168.1.254\n")  # DHCP renewal

    assert service.apply().changed
    assert "nameserver 10.100.1.1" in resolv.read_text()
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


def test_missing_dnsmasq_configuration_does_not_enable_fallback_dns(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)
    _service(tmp_path, _config(tmp_path, "resolv_conf")).apply()
    managed = resolv.read_bytes()
    service = _service(tmp_path, _config(tmp_path, "resolv_conf", dnsmasq=False))

    result = service.apply()

    assert not result.changed
    assert "not configured to run" in result.detail
    assert resolv.read_bytes() == managed
    assert service.status()["observed_state"] == "not_configured"
    service.restore()
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
    assert MARK in content and "DNS=\nDNS=10.100.1.1:5353\nDomains=~.\n" in content

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
    (dropin_dir / "kornode.conf").write_text(f"{MARK}: leftover\n[Resolve]\nDNS=10.100.1.1\n")

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


@pytest.mark.parametrize("mode", ["resolv_conf", "resolved"])
def test_readiness_guard_defers_new_redirect_and_preserves_managed_state(
    tmp_path: Path,
    mode: str,
) -> None:
    resolv = _mount_resolv(tmp_path)
    resolved = tmp_path / "host" / "resolved.conf.d"
    resolved.mkdir()
    ready = False
    service = HostDnsService(
        _config(tmp_path, mode),
        resolv_conf=resolv,
        resolved_dir=resolved,
        readiness_probe=lambda: ready,
    )
    result = service.apply()
    assert not result.changed
    assert "deferred" in result.detail
    assert resolv.read_text() == ORIGINAL
    assert not service.dropin_path.exists()
    assert not service.backup_path.exists()
    assert service.status()["observed_state"] == "waiting"
    ready = True
    assert service.apply().changed
    saved_resolv = resolv.read_bytes()
    saved_dropin = service.dropin_path.read_bytes() if service.dropin_path.exists() else None
    ready = False
    result = service.apply()
    assert not result.changed
    assert "no fallback" in result.detail
    assert resolv.read_bytes() == saved_resolv
    assert (
        service.dropin_path.read_bytes() if service.dropin_path.exists() else None
    ) == saved_dropin
    assert service.status()["resolver_ready"] is False
    # Explicit off remains the administrator's opt-out, even during an outage.
    service.config = _config(tmp_path, "off")
    service.apply()
    assert resolv.read_text() == ORIGINAL
    assert not service.dropin_path.exists()


def test_probe_failure_does_not_restore_fallback_dns(tmp_path: Path) -> None:
    resolv = _mount_resolv(tmp_path)
    service = _service(tmp_path, _config(tmp_path, "resolv_conf"))
    service.apply()
    before = resolv.read_bytes()

    def unavailable() -> bool:
        raise OSError("resolver unavailable")

    service._readiness_probe = unavailable
    assert not service.apply().changed
    assert resolv.read_bytes() == before
    assert "could not be verified" in str(service.status()["readiness_detail"])


def test_default_probe_requires_running_process_and_a_valid_local_dns_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import dns.message

    from kornode.services import host_dns

    state = "STOPPED"
    calls = []

    class Rpc:
        def __init__(self, *_args: object) -> None:
            pass

        def get_process_info(self, name: str) -> dict[str, str]:
            assert name == "dnsmasq"
            return {"statename": state}

    def query(request: dns.message.Message, address: str, **kwargs: object) -> dns.message.Message:
        calls.append((address, kwargs))
        assert request.question[0].name.to_text() == "version.bind."
        assert request.question[0].rdclass == 3  # CHAOS, never forwarded to public DNS
        return dns.message.make_response(request)

    monkeypatch.setattr(host_dns, "SupervisorRpcClient", Rpc)
    monkeypatch.setattr(dns.query, "udp", query)
    service = HostDnsService(_config(tmp_path, "resolv_conf"))
    assert not service.readiness()[0]
    assert not calls
    state = "RUNNING"
    assert service.readiness()[0]
    assert calls == [("10.100.1.1", {"port": 53, "timeout": 1})]

    def timeout(*_args: object, **_kwargs: object) -> dns.message.Message:
        raise OSError("timeout")

    monkeypatch.setattr(dns.query, "udp", timeout)
    assert not service.readiness()[0]


def test_failed_mode_switch_does_not_restore_fallback_dns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolv = _mount_resolv(tmp_path)
    service = _service(tmp_path, _config(tmp_path, "resolv_conf"))
    service.apply()
    original = resolv.read_bytes()
    service.resolved_dir.mkdir()
    service.config = _config(tmp_path, "resolved")

    def failed() -> object:
        raise OSError("drop-in write failed")

    monkeypatch.setattr(service, "_write_dropin", failed)
    with pytest.raises(OSError):
        service.apply()
    assert resolv.read_bytes() == original


@pytest.mark.parametrize("mode", ["resolv_conf", "resolved"])
def test_unconfigured_resolver_leaves_unmanaged_host_dns_untouched(
    tmp_path: Path, mode: str
) -> None:
    resolv = _mount_resolv(tmp_path)
    service = _service(tmp_path, _config(tmp_path, mode, dnsmasq=False))
    result = service.apply()
    assert not result.changed
    assert "no fallback" in result.detail
    assert resolv.read_text() == ORIGINAL
    assert not service.backup_path.exists()
    assert not service.dropin_path.exists()
