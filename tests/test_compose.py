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


def test_agent_compose_runs_the_published_image_without_a_source_tree() -> None:
    """The agent can be deployed from compose.agent.yaml alone: the image name is
    overridable (KORNODE_AGENT_IMAGE), the local build stays the default."""
    spec = yaml.safe_load((ROOT / "compose.agent.yaml").read_text(encoding="utf-8"))
    agent = spec["services"]["agent"]

    assert agent["image"] == "${KORNODE_AGENT_IMAGE:-kornode-agent:latest}"
    assert agent["build"]["dockerfile"] == "Dockerfile.agent"


def test_release_workflow_publishes_the_hub_and_the_agent_image() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release-image.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["publish"]
    images = {entry["name"]: entry["dockerfile"] for entry in job["strategy"]["matrix"]["include"]}
    steps = yaml.safe_dump(job["steps"])

    assert images == {"kornode": "Dockerfile", "kornode-agent": "Dockerfile.agent"}
    assert job["strategy"]["fail-fast"] is False
    # Each image checks its own tag, so the agent is published for a version the hub already has.
    version_step = next(step for step in job["steps"] if step.get("id") == "version")
    assert version_step["env"]["IMAGE_NAME"] == "${{ matrix.name }}"
    assert "os.environ['IMAGE_NAME']" in version_step["run"]
    exists_step = next(step for step in job["steps"] if step.get("id") == "exists")
    assert exists_step["env"]["IMAGE"] == "${{ steps.version.outputs.image }}"
    assert "file: ${{ matrix.dockerfile }}" in steps
    assert "scope=${{ matrix.name }}" in steps
