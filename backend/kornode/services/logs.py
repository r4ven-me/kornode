from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import ClassVar, TypedDict

from kornode.config.models import AppConfig
from kornode.services.secrets import collect_config_secrets, mask_text

_TIMESTAMP_PREFIX_RE = re.compile(
    r"^(?:"
    r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\[\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"
    r")"
)

_MAX_MARKERS_PER_FILE = 200


class LogRecord(TypedDict):
    name: str
    size: int


class LogService:
    # Class-level (not per-instance) because a fresh LogService is built for
    # every request. Maps an absolute log path to a growing list of
    # (byte_size_seen_at_poll, timestamp) markers. ocserv/supervisord write
    # plain lines with no timestamp of their own; tagging every such line
    # with "now" at read time (the old behaviour) made lines written hours
    # apart look like they all happened in the same instant. Tying each line
    # to the earliest poll at which its byte offset was already on disk
    # gives it a real, stable timestamp (accurate to one poll interval)
    # instead of a fabricated one that changes on every read.
    _markers: ClassVar[dict[str, list[tuple[int, str]]]] = {}
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def list_logs(self) -> list[LogRecord]:
        if not self.config.system.log_dir.exists():
            return []
        records: list[LogRecord] = []
        for path in self.config.system.log_dir.rglob("*"):
            if path.is_file():
                records.append(
                    {
                        "name": path.relative_to(self.config.system.log_dir).as_posix(),
                        "size": path.stat().st_size,
                    }
                )
        return sorted(records, key=lambda item: item["name"])

    def tail(self, name: str = "api.log", lines: int = 100) -> str:
        safe_name = Path(name)
        if safe_name.is_absolute() or ".." in safe_name.parts:
            return ""
        path = self.config.system.log_dir / safe_name
        try:
            path.relative_to(self.config.system.log_dir)
        except ValueError:
            return ""
        if not path.exists():
            return ""
        raw = path.read_bytes()
        markers = self._record_marker(str(path), len(raw))
        stamped = self._stamp_lines(raw.decode("utf-8", errors="replace"), lines, markers)
        return mask_text("\n".join(stamped), collect_config_secrets(self.config))

    @classmethod
    def _record_marker(cls, key: str, size: int) -> list[tuple[int, str]]:
        with cls._lock:
            markers = cls._markers.setdefault(key, [])
            if markers and size < markers[-1][0]:
                markers.clear()  # file was rotated or truncated
            if not markers or size > markers[-1][0]:
                markers.append((size, _now()))
                if len(markers) > _MAX_MARKERS_PER_FILE:
                    del markers[: len(markers) - _MAX_MARKERS_PER_FILE]
            return list(markers)

    @staticmethod
    def _stamp_lines(text: str, lines: int, markers: list[tuple[int, str]]) -> list[str]:
        entries = text.splitlines(keepends=True)
        offsets: list[int] = []
        acc = 0
        for entry in entries:
            acc += len(entry.encode("utf-8"))
            offsets.append(acc)
        start = max(0, len(entries) - lines)
        stamped: list[str] = []
        for index in range(start, len(entries)):
            line = entries[index].rstrip("\n").rstrip("\r")
            if not line or _TIMESTAMP_PREFIX_RE.match(line):
                stamped.append(line)
                continue
            stamp = next((s for size, s in markers if size >= offsets[index]), markers[-1][1])
            stamped.append(f"{stamp} {line}")
        return stamped


def _now() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


_ROTATED_SUFFIX_RE = re.compile(r"\.\d+$")


class LogRotationService:
    """Rotates files under system.log_dir by size and/or age.

    Rotation is copy-then-truncate: the writers (supervisord, certbot) keep
    their file descriptors open in append mode, so renaming the live file
    out from under them would leave them logging into the rotated copy.
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    @property
    def state_path(self) -> Path:
        return self.config.generated_path("log-rotation-state.json")

    def rotate(self, *, force: bool = False) -> list[str]:
        settings = self.config.system.log_rotation
        log_dir = self.config.system.log_dir
        if (not settings.enabled and not force) or not log_dir.exists():
            return []
        state = self._load_state()
        now = time.time()
        rotated: list[str] = []
        for path in sorted(log_dir.rglob("*")):
            if not path.is_file() or _ROTATED_SUFFIX_RE.search(path.name):
                continue
            name = path.relative_to(log_dir).as_posix()
            since = state.setdefault(name, now)
            size = path.stat().st_size
            if force:
                due = size > 0
            else:
                due = (settings.max_size_mb > 0 and size >= settings.max_size_bytes) or (
                    settings.max_age > 0 and now - since >= settings.max_age_seconds
                )
            if not due:
                continue
            self._rotate_file(path, keep=settings.keep_files)
            state[name] = now
            rotated.append(name)
        state = {
            name: stamp for name, stamp in state.items() if (log_dir / name).is_file()
        }
        self._save_state(state)
        return rotated

    @staticmethod
    def _rotate_file(path: Path, *, keep: int) -> None:
        oldest = path.with_name(f"{path.name}.{keep}")
        oldest.unlink(missing_ok=True)
        for index in range(keep - 1, 0, -1):
            source = path.with_name(f"{path.name}.{index}")
            if source.exists():
                os.replace(source, path.with_name(f"{path.name}.{index + 1}"))
        shutil.copyfile(path, path.with_name(f"{path.name}.1"))
        with path.open("r+b") as handle:
            handle.truncate(0)

    def _load_state(self) -> dict[str, float]:
        try:
            loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(loaded, dict):
            return {}
        return {
            str(name): float(stamp)
            for name, stamp in loaded.items()
            if isinstance(stamp, (int, float))
        }

    def _save_state(self, state: dict[str, float]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
