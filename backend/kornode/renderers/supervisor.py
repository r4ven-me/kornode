from __future__ import annotations

from pathlib import Path
from typing import Any

from kornode.config.models import AppConfig
from kornode.renderers.base import TemplateRenderer
from kornode.services.supervisor_rpc import RPC_PASSWORD, RPC_USERNAME


class SupervisorConfigRenderer(TemplateRenderer):
    def render(self, config: AppConfig) -> str:
        context: dict[str, Any] = {
            "config": config,
            "rpc_username": RPC_USERNAME,
            "rpc_password": RPC_PASSWORD,
        }
        return self.render_template("supervisor.conf.j2", context)

    def target_path(self, config: AppConfig) -> Path:
        return config.generated_path("supervisor.conf")
