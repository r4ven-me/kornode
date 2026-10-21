"""`agent.yaml`: the bootstrap written by enrollment (spec 06 "Local files")."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from kornode_agent.store import StoreError, atomic_write


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HubConfig(_Model):
    host: str
    port: int
    pin: str
    control_url: str
    camouflage: str | None = None
    server_name: str | None = None


class FabricConfig(_Model):
    interface: str = "oc-hub0"
    transport: Literal["tcp", "auto"] = "auto"


class AgentConfig(_Model):
    node_id: int
    hub: HubConfig
    fabric: FabricConfig = FabricConfig()
    log_level: Literal["debug", "info", "warning", "error"] = "info"


def load_config(root: Path) -> AgentConfig:
    path = root / "agent.yaml"
    try:
        return AgentConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise StoreError(f"cannot read {path}: {exc}") from exc


def save_config(root: Path, config: AgentConfig) -> None:
    text = yaml.safe_dump(config.model_dump(exclude_none=True), sort_keys=False)
    atomic_write(root / "agent.yaml", text.encode("utf-8"), 0o600)
