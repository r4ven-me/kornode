from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined


def default_template_dir() -> Path:
    configured = os.getenv("KORNODE_TEMPLATE_DIR")
    candidates = [
        Path(configured) if configured else None,
        Path.cwd() / "templates",
        Path(__file__).resolve().parents[3] / "templates",
        Path("/opt/kornode/templates"),
        Path("/usr/share/kornode/templates"),
    ]
    for candidate in candidates:
        if candidate is not None and candidate.exists():
            return candidate
    return Path(__file__).resolve().parents[3] / "templates"


class TemplateRenderer:
    def __init__(self, template_dir: Path | None = None) -> None:
        self.template_dir = template_dir or default_template_dir()
        self.environment = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
            undefined=StrictUndefined,
        )

    def render_template(self, template_name: str, context: dict[str, Any]) -> str:
        return self.environment.get_template(template_name).render(**context)
