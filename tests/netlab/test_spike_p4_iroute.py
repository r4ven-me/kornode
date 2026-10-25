"""Spike S-03 (docs/redesign/DECISIONS.md): `iroute` in the per-user file installs a
kernel route to the agent's prefix via its session device for the session lifetime,
and `explicit-ipv4` keeps the agent address across reconnects (P4-01).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.netlab.lab import Lab
from tests.netlab.test_spike_p3_groups import (
    AGENT_ID,
    INTERLINK_CIDR,
    GroupsLab,
    _start,
    spike_tmp,  # noqa: F401 - fixture
)

pytestmark = pytest.mark.netlab

OWN_PREFIX = "192.168.3.0/24"
OTHER_PREFIX = "192.168.2.0/24"


@pytest.fixture
def groups_lab(lab: Lab, spike_tmp: Path) -> Iterator[GroupsLab]:  # noqa: F811
    handle = _start(lab, spike_tmp, guard=True)
    # What InterlinkGroupsService renders for an agent with an exported LAN (P4-01).
    (spike_tmp / "users" / f"agent-{AGENT_ID}").write_text(
        f"explicit-ipv4 = 10.99.0.{AGENT_ID}\niroute = {OWN_PREFIX}\nroute = {OTHER_PREFIX}\n",
        encoding="utf-8",
    )
    try:
        yield handle
    finally:
        handle.stop()


def _hub_routes(handle: GroupsLab) -> str:
    return handle.hub.run(["ip", "route", "show"]).stdout


def test_s03_ocserv_does_not_install_iroute_routes_itself(groups_lab: GroupsLab) -> None:
    """Result of S-03: without `route-add-cmd` ocserv logs "route-add-cmd or
    route-del-cmd are not set" and installs only the /32 of the session. A
    `route-add-cmd` would make ocserv a second kernel writer (violates "only
    kornode.net touches the kernel"), so the hub reconciler installs the routes
    (fallback of S-03, D-63)."""
    assert groups_lab.agent.connect(groups_lab.pin, cert=groups_lab.agent_cert)
    routes = _hub_routes(groups_lab)
    print(routes)  # noqa: T201 - spike evidence
    assert f"10.99.0.{AGENT_ID} dev vpns" in routes
    assert OWN_PREFIX not in routes
    log = (groups_lab.tmp / "ocserv.log").read_text(encoding="utf-8")
    assert "route-add-cmd or route-del-cmd are not set" in log


def test_s03_explicit_ipv4_and_pushed_routes_survive_a_reconnect(groups_lab: GroupsLab) -> None:
    assert groups_lab.agent.connect(groups_lab.pin, cert=groups_lab.agent_cert)
    pushed = groups_lab.agent.pushed_routes()
    assert INTERLINK_CIDR in pushed and OTHER_PREFIX in pushed and OWN_PREFIX not in pushed
    assert groups_lab.agent.address() == f"10.99.0.{AGENT_ID}"

    groups_lab.agent.stop()
    assert groups_lab.agent.connect(groups_lab.pin, cert=groups_lab.agent_cert)
    assert groups_lab.agent.address() == f"10.99.0.{AGENT_ID}"
    assert OTHER_PREFIX in groups_lab.agent.pushed_routes()
