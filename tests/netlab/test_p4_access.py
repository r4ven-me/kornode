"""P4-04 (D-67): the agent's own ocserv, configured from a real bundle.

The files are what the agent renders from the bundle's `access` section; ocserv
runs in a namespace and a raw openconnect client logs in with the delivered
ocpasswd hashes. No hub is involved after the bundle is compiled, which is the
"local auth works without the hub" requirement.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from tests.netlab.kornode_nodes import _wait_until
from tests.netlab.lab import Lab, Namespace
from tests.netlab.ocserv_peers import Peer
from tests.test_agent_access import World

from kornode.tunnels.pin import certificate_pin, pem_to_der
from kornode_agent.access import AccessServer

pytestmark = pytest.mark.netlab

AGENT_ADDR = "192.0.2.1"
CLIENT_ADDR = "192.0.2.2"


def _real_hash(password: str) -> str:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "passwd"
        subprocess.run(
            ["ocpasswd", "-c", str(path), "user"],
            input=f"{password}\n{password}\n",
            text=True,
            capture_output=True,
            check=True,
        )
        return path.read_text().strip().split(":")[-1]


class Control:
    """Supervisor stand-in: the ocserv process lives in the agent namespace."""

    def __init__(self, ns: Namespace, conf: Path) -> None:
        self.ns, self.conf = ns, conf
        self.process: subprocess.Popen[bytes] | None = None
        self.restarts = 0

    def __call__(self, action: str) -> bool:
        self.stop_process()
        if action == "stop":
            return True
        self.restarts += 1
        self.process = subprocess.Popen(  # noqa: S603 - explicit argv, no shell
            [
                "ip", "netns", "exec", self.ns.full_name, "ocserv",
                "--foreground", "--log-stderr", "--config", str(self.conf),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )  # fmt: skip
        return True

    def stop_process(self) -> None:
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None


@dataclass
class AccessLab:
    world: World
    agent: Namespace
    client: Peer
    server: AccessServer
    control: Control
    pin: str


@pytest.fixture
def access_lab(lab: Lab, tmp_path: Path) -> Iterator[AccessLab]:
    if shutil.which("ocserv") is None or shutil.which("openconnect") is None:
        pytest.skip("needs ocserv and openconnect")
    world = World(tmp_path / "hub", password_hasher=_real_hash)
    world.service.set_access("node3", {"hostname": AGENT_ADDR, "port": 443})
    world.service.set_user("node3", "alice", {"password": "alice-password", "groups": ["staff"]})
    world.service.set_user("node3", "bob", {"password": "bob-password1"})
    agent, client_ns = lab.add_namespace("agent"), lab.add_namespace("client")
    lab.add_veth(agent, client_ns, addr_a=f"{AGENT_ADDR}/24", addr_b=f"{CLIENT_ADDR}/24")
    root = Path(tempfile.mkdtemp(prefix="kornode-netlab-access-"))
    for parent in (root, root / "run"):
        parent.mkdir(exist_ok=True)
        parent.chmod(0o755)
    server = AccessServer(root / "run/access", control=lambda action: True)
    control = Control(agent, root / "run/access/ocserv.conf")
    server.control = control
    validated = world.bundle()
    pin = certificate_pin(pem_to_der(validated.bundle.access.server_cert_pem)).pin  # type: ignore[union-attr]
    client = Peer(client_ns, AGENT_ADDR, "vpnc0", root)
    handle = AccessLab(world, agent, client, server, control, pin)
    try:
        yield handle
    finally:
        client.stop()
        control.stop_process()
        world.env.registry.conn.close()
        shutil.rmtree(root, ignore_errors=True)


def _apply(handle: AccessLab) -> None:
    validated = handle.world.bundle()
    assert handle.server.apply(validated.bundle, validated.secrets)


def _login(handle: AccessLab, user: str, password: str, *, wait: float = 15) -> bool:
    """Poll: ocserv needs a moment after its (re)start before it listens."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if handle.client.connect(handle.pin, user=user, password=password):
            return True
        time.sleep(0.5)
    return False


def _refused(handle: AccessLab, user: str, password: str) -> bool:
    # Server needs a moment to listen; a refused login after that is final.
    time.sleep(1)
    return not handle.client.connect(handle.pin, user=user, password=password)


def test_delivered_hashes_authenticate_and_the_client_gets_a_pool_address(
    access_lab: AccessLab,
) -> None:
    _apply(access_lab)
    assert _login(access_lab, "alice", "alice-password")
    address = access_lab.client.address()
    assert address is not None and address.startswith("10.100.3.")
    access_lab.client.stop()
    assert _refused(access_lab, "alice", "wrong-password")


def test_disabled_and_removed_users_lose_access_without_a_restart(access_lab: AccessLab) -> None:
    _apply(access_lab)
    assert _login(access_lab, "bob", "bob-password1")
    access_lab.client.stop()
    access_lab.world.service.set_user("node3", "bob", {"enabled": False})
    access_lab.world.service.set_user("node3", "carol", {"password": "carol-password"})
    _apply(access_lab)
    assert access_lab.control.restarts == 1  # only ocpasswd changed
    assert _refused(access_lab, "bob", "bob-password1")
    assert _login(access_lab, "carol", "carol-password")


def test_no_listener_means_no_server(access_lab: AccessLab) -> None:
    _apply(access_lab)
    _wait_until(lambda: access_lab.control.process is not None, "ocserv start", timeout=5)
    access_lab.world.service.set_access("node3", None)
    _apply(access_lab)
    assert access_lab.control.process is None
    assert _refused(access_lab, "alice", "alice-password")
