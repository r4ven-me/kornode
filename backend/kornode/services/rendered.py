from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RenderedFile:
    path: Path
    content: str
    mode: int = 0o644
