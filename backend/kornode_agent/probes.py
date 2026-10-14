from __future__ import annotations

from pathlib import Path


def link_exists(interface: str) -> bool:
    return Path("/sys/class/net", interface).exists()
