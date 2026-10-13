from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from tests.netlab.helpers import tcp_check
from tests.netlab.lab import Lab, Namespace
from tests.netlab.topology import HUB_ADDR, INET_HTTP_ADDR, Topology

from kornode.renderers.base import default_template_dir
from kornode.services.command import CommandResult

VPN_USERNAME = "netlab"
VPN_PASSWORD = "netlab-password"
VPN_POOL = "10.250.0.0/24"
SERVER_PORT = 443
UPSTREAM_PROFILE = "hub"
UPSTREAM_INTERFACE = "oc-middle0"


@dataclass(frozen=True)
class KornodeRoot:
    root: Path
    config_path: Path
    data_dir: Path
    generated_dir: Path
    secrets_dir: Path
    log_dir: Path


@dataclass
class HubServerHandle:
    config_path: Path
    root: KornodeRoot
    process: subprocess.Popen[bytes]
    server_addr: str
    port: int
    server_cert_pin: str

    def stop(self) -> None:
        _terminate_process(self.process)


@dataclass
class UpstreamHandle:
    config_path: Path
    root: KornodeRoot
    namespace: Namespace
    profile: str = UPSTREAM_PROFILE
    interface: str = UPSTREAM_INTERFACE
    # The reconciler derives both from the exit's position in the compiled
    # policy, so they are read from `korctl net plan`, never hardcoded.
    table: str = ""
    fwmark: str = ""

    def disconnect(self) -> None:
        korctl(
            self.namespace,
            self.config_path,
            "upstream",
            "disconnect",
            self.profile,
            check=False,
        )
        self.kill_leftover()

    def stop(self) -> None:
        self.disconnect()

    def kill_leftover(self) -> None:
        _kill_openconnect(self.root.generated_dir / f"upstream-{self.profile}.pid")


def _hub_connect_script(tmp: Path) -> str | None:
    """The hub is only a test server, so its config must work on any kornode
    version under test: kornode before P0-01 has no connect-script template,
    and pointing ocserv at a missing script makes it refuse every login."""
    if not (default_template_dir() / "ocserv-connect-script-kornode").exists():
        return None
    return str(tmp / "hub" / "generated" / "ocserv-connect-script-kornode")


def korctl(ns: Namespace, cfg_path: Path, *args: str, check: bool = True) -> CommandResult:
    bin_dir = Path(sys.executable).absolute().parent
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    return ns.run(
        [str(bin_dir / "korctl"), "--config", str(cfg_path), *args],
        env=env,
        check=check,
        timeout=90,
    )


def start_hub_server(lab: Lab, topology: Topology, tmp: Path) -> HubServerHandle:
    root = write_kornode_config(
        lab,
        "hub",
        tmp,
        {
            "server": {
                "enabled": True,
                "listen": HUB_ADDR,
                "port": SERVER_PORT,
                "udp_enabled": False,
                "device": "vpns",
                "cn": HUB_ADDR,
                "ipv4_network": VPN_POOL,
                "dns": [INET_HTTP_ADDR],
                "routes": [],  # no route lines = ocserv pushes a default route
                "debug_level": 3,
                "connect_script": _hub_connect_script(tmp),
            },
            "auth": {
                "password": {"enabled": True},
                "certificate": {"enabled": False},
                "otp": {"enabled": False},
                "oidc": {"enabled": False},
            },
            "routing": {"client_policy": "off", "host_policy": "off"},
        },
    )
    initialize_runtime(topology.hub, root.config_path)
    korctl(
        topology.hub,
        root.config_path,
        "user",
        "create",
        VPN_USERNAME,
        "--password",
        VPN_PASSWORD,
    )
    pin = json.loads(
        korctl(topology.hub, root.config_path, "certificates", "pin").stdout
    )["pin"]
    log_file = root.log_dir / "ocserv.log"
    process = _popen_in_namespace(
        topology.hub,
        [
            "ocserv",
            "-f",
            "--log-stderr",
            "-c",
            str(root.generated_dir / "ocserv.conf"),
        ],
        log_file,
    )
    _wait_until(
        lambda: process.poll() is None and tcp_check(topology.node3, HUB_ADDR, SERVER_PORT),
        f"ocserv on {HUB_ADDR}:{SERVER_PORT}",
        timeout=10,
    )
    return HubServerHandle(
        config_path=root.config_path,
        root=root,
        process=process,
        server_addr=HUB_ADDR,
        port=SERVER_PORT,
        server_cert_pin=pin,
    )


def connect_node_upstream(
    lab: Lab,
    ns: Namespace,
    tmp: Path,
    *,
    server_addr: str,
    server_cert_pin: str,
    host_policy: str = "full",
    client_policy: str = "off",
    check_host: str | None = None,
) -> UpstreamHandle:
    root = write_kornode_config(
        lab,
        ns.name,
        tmp,
        {
            "server": {
                "enabled": False,
                "ipv4_network": "10.251.0.0/24",
                "dns": [INET_HTTP_ADDR],
            },
            "auth": {
                "password": {"enabled": True},
                "certificate": {"enabled": False},
                "otp": {"enabled": False},
                "oidc": {"enabled": False},
            },
            "upstream": {
                "enabled": True,
                "interface": UPSTREAM_INTERFACE,
                "active_profile": UPSTREAM_PROFILE,
                "connect_on_boot": False,
                "profiles": [
                    {
                        "name": UPSTREAM_PROFILE,
                        "server": server_addr,
                        "port": str(SERVER_PORT),
                        "interface": UPSTREAM_INTERFACE,
                        "auth_type": "password",
                        "username": VPN_USERNAME,
                        "password": VPN_PASSWORD,
                        "server_cert_pin": server_cert_pin,
                        "check_host": check_host,
                    }
                ],
            },
            "routing": {
                "client_policy": client_policy,
                "host_policy": host_policy,
                "main_interface": "auto",
            },
        },
    )
    initialize_runtime(ns, root.config_path)
    korctl(ns, root.config_path, "config", "render")
    exits = json.loads(korctl(ns, root.config_path, "net", "plan", "--json").stdout)["exits"]
    exit_ = next(item for item in exits if item["name"] == f"upstream:{UPSTREAM_PROFILE}")
    handle = UpstreamHandle(
        config_path=root.config_path,
        root=root,
        namespace=ns,
        table=str(exit_["table"]),
        fwmark=exit_["mark"],
    )
    try:
        korctl(ns, root.config_path, "upstream", "connect", UPSTREAM_PROFILE)
        _wait_until(lambda: _interface_exists(ns, handle.interface), f"{handle.interface} exists")
        _wait_until(lambda: _policy_table_has_default(ns, handle.table), f"table {handle.table}")
    except BaseException:
        # openconnect may already be backgrounded even though connect failed.
        handle.kill_leftover()
        raise
    return handle


def write_kornode_config(
    lab: Lab,
    name: str,
    tmp: Path,
    patch: dict[str, Any],
) -> KornodeRoot:
    root = tmp / name
    data_dir = root / "data"
    generated_dir = root / "generated"
    secrets_dir = root / "secrets"
    log_dir = root / "logs"
    config_path = root / "config.yaml"
    for path in (data_dir / "certs", generated_dir, secrets_dir, log_dir):
        path.mkdir(parents=True, exist_ok=True)
    lab.log_dirs.append(log_dir)
    base: dict[str, Any] = {
        "system": {
            "data_dir": str(data_dir),
            "generated_dir": str(generated_dir),
            "secrets_dir": str(secrets_dir),
            "log_dir": str(log_dir),
        },
        "identity": {
            "config_per_group_dir": str(generated_dir / "config-per-group"),
            "config_per_user_dir": str(generated_dir / "config-per-user"),
        },
        "routing": {
            "split": {
                "routes_file": str(generated_dir / "routes.txt"),
                "domains_file": str(generated_dir / "domains.txt"),
            },
            "host_split": {
                "routes_file": str(generated_dir / "host-routes.txt"),
                "domains_file": str(generated_dir / "host-domains.txt"),
            },
        },
        "web": {
            "enabled": False,
            "static_dir": str(root / "web-static"),
        },
    }
    config = _deep_merge(base, patch)
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return KornodeRoot(
        root=root,
        config_path=config_path,
        data_dir=data_dir,
        generated_dir=generated_dir,
        secrets_dir=secrets_dir,
        log_dir=log_dir,
    )


def initialize_runtime(ns: Namespace, cfg_path: Path) -> None:
    code = (
        "from pathlib import Path\n"
        "from kornode.main import initialize_runtime\n"
        "initialize_runtime(Path(__import__('sys').argv[1]))\n"
    )
    bin_dir = Path(sys.executable).absolute().parent
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    ns.run([sys.executable, "-c", code, str(cfg_path)], env=env, timeout=120)


def _popen_in_namespace(
    ns: Namespace,
    argv: list[str],
    log_file: Path,
) -> subprocess.Popen[bytes]:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log = log_file.open("ab")
    try:
        return subprocess.Popen(  # noqa: S603 - explicit argv, no shell
            ["ip", "netns", "exec", ns.full_name, *argv],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    finally:
        log.close()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _interface_exists(ns: Namespace, name: str) -> bool:
    return ns.run(["ip", "link", "show", "dev", name], check=False).ok


def _kill_openconnect(pid_file: Path) -> None:
    """Stop exactly this profile's openconnect via its pid file.

    Not `pkill -f openconnect` inside `ip netns exec`: network namespaces
    don't isolate PIDs, so that would kill every openconnect on the host,
    including other labs' tunnels running in parallel.
    """
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    for sig, wait in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 1.0)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)


def _policy_table_has_default(ns: Namespace, table: str) -> bool:
    result = ns.run(["ip", "route", "show", "table", table], check=False)
    return result.ok and "default" in result.stdout


def _wait_until(
    check: Callable[[], bool],
    description: str,
    timeout: float = 10.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {description}")


def _deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged
