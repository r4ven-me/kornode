"""P3-08 CLI management with the Web GUI disabled and real ocserv/ocpasswd."""

# ruff: noqa: F811 - pytest fixtures imported from test_p3_groups
from __future__ import annotations

import base64
import json

import pytest
import yaml
from tests.netlab.kornode_nodes import korctl
from tests.netlab.test_p3_groups import (  # noqa: F401 - fixtures
    RenderedHub,
    node_tmp,
    rendered_hub,
)

pytestmark = pytest.mark.netlab


def test_cli_management_without_web(rendered_hub: RenderedHub) -> None:
    hub = rendered_hub
    config = yaml.safe_load(hub.root.config_path.read_text())
    assert not config.get("web", {}).get("enabled", False)

    def call(*args: str) -> dict:
        return json.loads(korctl(hub.hub, hub.root.config_path, *args, "--json").stdout)

    preview = call("agent", "create", "branch", "--id", "4", "--dry-run")
    assert preview["dry_run"] and preview["id"] == 4
    assert all(n["name"] != "branch" for n in call("agent", "list")["agents"])
    created = call("agent", "create", "branch", "--id", "4")
    assert created["agent"]["state"] == "pending"
    token = created["token"]
    doc = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    assert doc["user"].startswith("enroll-4-")
    passwd = hub.root.secrets_dir / "ocpasswd"
    assert doc["user"] in passwd.read_text()
    assert token not in json.dumps(call("agent", "list"))
    replacement = call("agent", "token", "branch")["token"]
    assert replacement != token and doc["user"] not in passwd.read_text()
    call("agent", "token", "branch", "--revoke")
    assert "enroll-4-" not in passwd.read_text()
    assert call("agent", "delete", "branch", "--dry-run")["revoke_first"]
    assert call("agent", "show", "branch")["id"] == 4
    call("agent", "revoke", "branch", "--yes")
    assert call("agent", "show", "branch")["state"] == "revoked"
    call("agent", "delete", "branch", "--yes")
    assert all(n["name"] != "branch" for n in call("agent", "list")["agents"])
    refused = korctl(
        hub.hub,
        hub.root.config_path,
        "agent",
        "create",
        "reuse",
        "--id",
        "4",
        "--json",
        check=False,
    )
    assert refused.returncode == 3 and json.loads(refused.stdout)["error"] == "id_unavailable"
    assert call("control", "status")["enabled"]
    assert call("control", "rotate-signing-key", "--dry-run")["dry_run"]
