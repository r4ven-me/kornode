from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("path", "service"), [("compose.yaml", "kornode"), ("compose.agent.yaml", "agent")]
)
def test_host_network_compose_gives_the_reconciler_only_net_sysctls(
    path: str, service: str
) -> None:
    """D-83: with `network_mode: host` Docker mounts /proc/sys read-only and refuses
    `sysctls:`; the host's /proc/sys/net is bind-mounted at KORNODE_PROC_SYS instead.
    Neither `privileged` nor `systempaths=unconfined`: those also open kernel.*."""
    spec = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))["services"][service]

    assert spec["network_mode"] == "host"
    assert "/proc/sys/net:/host/proc/sys/net" in spec["volumes"]
    assert spec["environment"]["KORNODE_PROC_SYS"] == "/host/proc/sys"
    assert not spec.get("privileged")
    assert not spec.get("security_opt")
