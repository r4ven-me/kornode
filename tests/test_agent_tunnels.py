from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from kornode.tunnels.argv import DialSpec
from kornode_agent.tunnels import TunnelManager, TunnelSpec


class Fake:
    """Runner + converge + links in one place so call order is observable."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[str] = []
        self.codes: list[int] = []
        self.links: set[str] = set()
        self.argvs: list[list[str]] = []
        self.stdin: list[str | None] = []
        self.now = 0.0
        self.procs: list[subprocess.Popen[bytes]] = []

    def converge(self) -> None:
        self.calls.append("converge")

    def link_up(self, iface: str) -> bool:
        return iface in self.links

    def run(self, argv: list[str], *, input_text: str | None, timeout: int, log: Path) -> int:
        self.calls.append("dial")
        self.argvs.append(argv)
        self.stdin.append(input_text)
        code = self.codes.pop(0) if self.codes else 0
        if code == 0:
            pid_file = Path(next(a for a in argv if a.startswith("--pid-file=")).split("=", 1)[1])
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            proc = subprocess.Popen(["sleep", "60"])  # a real, harmless daemon stand-in
            self.procs.append(proc)
            pid_file.write_text(f"{proc.pid}\n")
            self.links.add(argv[argv.index("--interface") + 1])
        return code

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake(tmp_path: Path) -> Iterator[Fake]:
    instance = Fake(tmp_path)
    yield instance
    for proc in instance.procs:
        proc.kill()
        proc.wait()


def _spec(root: Path, *servers: str, password: str | None = None) -> TunnelSpec:
    dials = tuple(
        DialSpec(
            server=server,
            port=443,
            interface="oc-hub0",
            pid_file=root / "run" / "oc-fabric.pid",
            script=root / "run" / "vpnc-script-kornode",
            auth_type="password" if password else "cert",
            password=password,
        )
        for server in servers
    )
    return TunnelSpec("fabric", dials, password=password)


def _manager(fake: Fake, root: Path) -> TunnelManager:
    return TunnelManager(
        root,
        converge=fake.converge,
        link_up=fake.link_up,
        runner=fake,
        resolve=lambda server: ["203.0.113.9"],
        clock=fake.clock,
        sleep=fake.sleep,
        jitter=lambda: 1.0,
    )


def test_killswitch_pass_and_carrier_come_before_the_dial(tmp_path: Path, fake: Fake) -> None:
    manager = _manager(fake, tmp_path)
    manager.set_desired({"fabric": _spec(tmp_path, "hub.example", password="s3cret")})

    manager.tick()

    assert fake.calls[:2] == ["converge", "dial"]
    assert manager.carrier("fabric") == ("203.0.113.9",)
    assert fake.stdin == ["s3cret\n"] and "s3cret" not in " ".join(fake.argvs[0])
    assert manager.is_up("fabric")
    assert (tmp_path / "run" / "vpnc-script-kornode").stat().st_mode & 0o777 == 0o755


def test_failed_dial_backs_off_and_fails_over_to_the_next_hub(tmp_path: Path, fake: Fake) -> None:
    fake.codes = [1, 1, 0]
    manager = _manager(fake, tmp_path)
    manager.set_desired({"fabric": _spec(tmp_path, "hub-a", "hub-b")})

    manager.tick()
    assert "hub-a:443" in fake.argvs[0] and "fabric" in manager.errors
    manager.tick()  # still inside the backoff window: no new dial
    assert len(fake.argvs) == 1

    fake.now += 1.0
    manager.tick()
    assert "hub-b:443" in fake.argvs[1]
    fake.now += 3.0
    manager.tick()
    assert "hub-a:443" in fake.argvs[2] and "fabric" not in manager.errors


def test_changed_spec_restarts_and_suspend_stops_redialing(tmp_path: Path, fake: Fake) -> None:
    manager = _manager(fake, tmp_path)
    manager.set_desired({"fabric": _spec(tmp_path, "hub-a")})
    manager.tick()
    assert manager.is_up("fabric")

    manager.suspend("fabric")
    manager.tick()
    assert len(fake.argvs) == 1  # a revoked node does not hammer the hub

    manager.set_desired({})
    assert manager.carrier("fabric") == () and not manager.is_up("fabric")
