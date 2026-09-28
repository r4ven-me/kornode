from __future__ import annotations

import re

import pytest

from kornode.config.models import AppConfig
from kornode.services import logs as logs_module
from kornode.services.logs import LogRotationService, LogService


@pytest.fixture(autouse=True)
def _clear_marker_cache():
    LogService._markers.clear()
    yield
    LogService._markers.clear()


def test_log_service_lists_nested_certbot_logs(tmp_path) -> None:
    log_dir = tmp_path / "logs"
    certbot_dir = log_dir / "certbot"
    certbot_dir.mkdir(parents=True)
    (certbot_dir / "letsencrypt.log").write_text("issued\n", encoding="utf-8")
    (log_dir / "api.log").write_text("api\n", encoding="utf-8")
    config = AppConfig.model_validate({"system": {"log_dir": log_dir}})

    records = LogService(config).list_logs()

    assert [record["name"] for record in records] == ["api.log", "certbot/letsencrypt.log"]
    assert re.match(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4} issued",
        LogService(config).tail("certbot/letsencrypt.log"),
    )


def test_log_service_keeps_existing_timestamps(tmp_path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "api.log").write_text("2026-06-30 12:30:00 event\n", encoding="utf-8")
    config = AppConfig.model_validate({"system": {"log_dir": log_dir}})

    assert LogService(config).tail("api.log") == "2026-06-30 12:30:00 event"


def test_log_service_reuses_the_timestamp_a_line_first_appeared_with(
    tmp_path, monkeypatch
) -> None:
    # ocserv/supervisord write lines with no timestamp of their own, and
    # ocserv repeats the exact same banner text on every restart. Re-reading
    # the file must not re-date already-seen lines to "now" on every poll -
    # that previously made restarts that happened hours apart look like they
    # all happened in the same instant.
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "ocserv.log"
    config = AppConfig.model_validate({"system": {"log_dir": log_dir}})

    log_path.write_text("listening (TCP) on 0.0.0.0:443...\n", encoding="utf-8")
    monkeypatch.setattr(logs_module, "_now", lambda: "2026-06-30 10:00:00 +0000")
    first = LogService(config).tail("ocserv.log")
    assert first == "2026-06-30 10:00:00 +0000 listening (TCP) on 0.0.0.0:443..."

    # Re-polling identical content later must reuse the original stamp.
    monkeypatch.setattr(logs_module, "_now", lambda: "2026-06-30 11:00:00 +0000")
    second = LogService(config).tail("ocserv.log")
    assert second == first

    # A second, later restart appends the exact same banner text again - it
    # must get its own, later timestamp rather than inheriting the first
    # occurrence's stamp just because the text is identical.
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write("listening (TCP) on 0.0.0.0:443...\n")
    third = LogService(config).tail("ocserv.log")
    assert third.splitlines() == [
        "2026-06-30 10:00:00 +0000 listening (TCP) on 0.0.0.0:443...",
        "2026-06-30 11:00:00 +0000 listening (TCP) on 0.0.0.0:443...",
    ]


def test_log_service_rejects_path_traversal(tmp_path) -> None:
    config = AppConfig.model_validate({"system": {"log_dir": tmp_path / "logs"}})

    assert LogService(config).tail("../secret") == ""


def _rotation_config(tmp_path, **rotation) -> AppConfig:
    return AppConfig.model_validate(
        {
            "system": {
                "log_dir": tmp_path / "logs",
                "generated_dir": tmp_path / "generated",
                "log_rotation": {"enabled": True, **rotation},
            }
        }
    )


def test_log_rotation_by_size_copies_and_truncates(tmp_path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    payload = b"x" * (1024 * 1024 + 1)
    (log_dir / "api.log").write_bytes(payload)
    (log_dir / "small.log").write_bytes(b"tiny\n")
    config = _rotation_config(tmp_path, max_size_mb=1, max_age=0)

    rotated = LogRotationService(config).rotate()

    assert rotated == ["api.log"]
    assert (log_dir / "api.log").stat().st_size == 0
    assert (log_dir / "api.log.1").read_bytes() == payload
    assert not (log_dir / "small.log.1").exists()


def test_log_rotation_keeps_a_bounded_chain(tmp_path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    path = log_dir / "api.log"
    config = _rotation_config(tmp_path, keep_files=2)
    service = LogRotationService(config)

    for generation in (b"first", b"second", b"third"):
        path.write_bytes(generation)
        assert service.rotate(force=True) == ["api.log"]

    assert (log_dir / "api.log.1").read_bytes() == b"third"
    assert (log_dir / "api.log.2").read_bytes() == b"second"
    assert not (log_dir / "api.log.3").exists()


def test_log_rotation_skips_already_rotated_files(tmp_path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "api.log.1").write_bytes(b"old copy")
    config = _rotation_config(tmp_path)

    assert LogRotationService(config).rotate(force=True) == []
    assert not (log_dir / "api.log.1.1").exists()


def test_log_rotation_by_age_counts_from_first_sighting(tmp_path, monkeypatch) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "api.log").write_bytes(b"line\n")
    config = _rotation_config(tmp_path, max_size_mb=0, max_age=1, max_age_unit="hours")
    service = LogRotationService(config)

    monkeypatch.setattr(logs_module.time, "time", lambda: 1_000_000.0)
    assert service.rotate() == []

    monkeypatch.setattr(logs_module.time, "time", lambda: 1_000_000.0 + 3599)
    assert service.rotate() == []

    monkeypatch.setattr(logs_module.time, "time", lambda: 1_000_000.0 + 3601)
    assert service.rotate() == ["api.log"]
    assert (log_dir / "api.log.1").read_bytes() == b"line\n"


def test_log_rotation_disabled_is_noop_unless_forced(tmp_path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "api.log").write_bytes(b"x" * (2 * 1024 * 1024))
    config = AppConfig.model_validate(
        {
            "system": {
                "log_dir": log_dir,
                "generated_dir": tmp_path / "generated",
                "log_rotation": {"enabled": False, "max_size_mb": 1},
            }
        }
    )
    service = LogRotationService(config)

    assert service.rotate() == []
    assert not (log_dir / "api.log.1").exists()
    assert service.rotate(force=True) == ["api.log"]
    assert (log_dir / "api.log.1").exists()
