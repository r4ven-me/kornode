from __future__ import annotations

import os
import tempfile
from pathlib import Path


class FileManager:
    def ensure_dir(self, path: Path, mode: int = 0o755) -> None:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)

    def atomic_write_text(self, path: Path, content: str, mode: int = 0o644) -> None:
        if not path.parent.exists():
            self.ensure_dir(path.parent)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, mode)
            os.replace(temp_path, path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def atomic_write_private_text(self, path: Path, content: str) -> None:
        self.atomic_write_text(path, content, mode=0o600)

    def atomic_write_bytes(self, path: Path, content: bytes, mode: int = 0o600) -> None:
        if not path.parent.exists():
            self.ensure_dir(path.parent)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, mode)
            os.replace(temp_path, path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def read_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        return path.read_text(encoding="utf-8").splitlines()

    def write_unique_lines(self, path: Path, lines: list[str], mode: int = 0o644) -> None:
        normalized: list[str] = []
        seen: set[str] = set()
        for line in lines:
            item = line.strip()
            if not item or item.startswith("#") or item in seen:
                continue
            normalized.append(item)
            seen.add(item)
        self.atomic_write_text(
            path,
            "\n".join(normalized) + ("\n" if normalized else ""),
            mode=mode,
        )
