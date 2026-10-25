"""P3-09 privileged DR smoke: wipe hub files; existing agent cert reconnects.

Run ONLY in the disposable netlab VM. No network action is safe on a dev host.
"""

# ruff: noqa: F811 - pytest fixtures imported from test_p3_groups
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml
from tests.netlab.helpers import tcp_check
from tests.netlab.kornode_nodes import (
    KornodeRoot,
    _popen_in_namespace,
    _terminate_process,
    _wait_until,
    initialize_runtime,
    korctl,
)
from tests.netlab.test_p3_enrollment import _enroll_agent, _http
from tests.netlab.test_p3_groups import (  # noqa: F401 - fixtures
    CONTROL_PORT,
    HUB_INTERLINK_ADDR,
    RenderedHub,
    node_tmp,
    rendered_hub,
)

from kornode.config.loader import load_config

pytestmark = pytest.mark.netlab


def test_hub_wipe_restore_reconnects_without_reenrollment(
    rendered_hub: RenderedHub,
    node_tmp: Path,
) -> None:
    hub = rendered_hub
    crt, key = _enroll_agent(hub, node_tmp)
    assert hub.connect_interlink(hub.agent, cert=(crt, key))
    status, body = _http(hub, hub.agent.ns, "GET", "/agent/v1/poll?since=0", cert=(crt, key))
    assert status == 200, body
    initial_version = json.loads(body)["bundle"]["version"]
    korctl(hub.hub, hub.root.config_path, "control", "rotate-signing-key", "--yes", "--json")
    before = json.loads(korctl(hub.hub, hub.root.config_path, "control", "status", "--json").stdout)
    recovery_config = node_tmp / "recovery.yaml"
    recovery_config.write_text(
        yaml.safe_dump(load_config(hub.root.config_path).model_dump(mode="json"))
    )
    recovery_config.chmod(0o600)
    passphrase = node_tmp / "backup-passphrase"
    passphrase.write_text("netlab-private-backup-passphrase\n")
    passphrase.chmod(0o600)
    archive = node_tmp / "hub.knbackup"
    korctl(
        hub.hub,
        hub.root.config_path,
        "hub",
        "backup",
        "--out",
        str(archive),
        "--passphrase-file",
        str(passphrase),
        "--json",
    )
    hub.agent.stop()
    for process in hub.processes:
        if isinstance(process.args, list) and (
            "ocserv" in process.args or "kornode.control" in process.args
        ):
            _terminate_process(process)
    old_root = hub.root.root
    assert old_root.is_relative_to(node_tmp)  # guard the destructive test itself
    shutil.rmtree(old_root)
    target = node_tmp / "restored"
    result = json.loads(
        korctl(
            hub.hub,
            recovery_config,
            "hub",
            "restore",
            str(archive),
            "--target",
            str(target),
            "--passphrase-file",
            str(passphrase),
            "--yes",
            "--json",
        ).stdout
    )
    assert result["staged"]
    # Explicit activation step: workers need traversal, not access to secrets.
    # kornode initialization recreates generated/user/group directory permissions.
    target.chmod(0o711)
    config_path = Path(result["config_path"])
    cfg = load_config(config_path)
    hub.root = KornodeRoot(
        target,
        config_path,
        cfg.system.data_dir,
        cfg.system.generated_dir,
        cfg.system.secrets_dir,
        cfg.system.log_dir,
    )
    initialize_runtime(hub.hub, config_path)
    control = _popen_in_namespace(
        hub.hub,
        [
            "env",
            f"KORNODE_CONFIG={config_path}",
            f"PATH={Path(sys.executable).absolute().parent}{os.pathsep}{os.environ['PATH']}",
            sys.executable,
            "-m",
            "kornode.control",
        ],
        cfg.system.log_dir / "control-restored.log",
    )
    hub.processes.append(control)
    _wait_until(
        lambda: control.poll() is None and tcp_check(hub.hub, HUB_INTERLINK_ADDR, CONTROL_PORT),
        "restored control API",
    )
    ocserv = _popen_in_namespace(
        hub.hub,
        ["ocserv", "-f", "--log-stderr", "-c", str(cfg.generated_path("ocserv.conf"))],
        cfg.system.log_dir / "ocserv-restored.log",
    )
    hub.processes.append(ocserv)
    _wait_until(
        lambda: ocserv.poll() is None and tcp_check(hub.agent.ns, hub.agent.hub_addr, 443),
        "restored ocserv",
    )
    # No new token, CSR, or key: old pin + old certificate + old private key.
    assert hub.connect_interlink(hub.agent, cert=(crt, key))
    assert _http(hub, hub.agent.ns, "GET", "/agent/v1/ping", cert=(crt, key))[0] == 204
    since = initial_version + 100
    status, body = _http(hub, hub.agent.ns, "GET", f"/agent/v1/poll?since={since}", cert=(crt, key))
    assert status == 200, body
    assert json.loads(body)["bundle"]["version"] > since
    after = json.loads(korctl(hub.hub, config_path, "control", "status", "--json").stdout)
    assert after["signing_key_id"] == before["signing_key_id"]
    assert after["rotation"]["started_at"] == before["rotation"]["started_at"]
