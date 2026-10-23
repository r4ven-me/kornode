"""Orchestration: strict preflight -> leases -> images -> isolated cases -> cleanup."""

from __future__ import annotations

import base64
import hashlib
import secrets
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tests.e2e.inventory import E2EError, Inventory
from tests.e2e.transport import SSH
from tests.e2e.worker import CASES, atomic

REPOSITORY = Path(__file__).resolve().parents[2]


def wait_for(check: Callable[[], bool], seconds: float, message: str) -> float:
    start = time.monotonic()
    deadline = start + seconds
    while True:
        try:
            passed = check()
        except E2EError:
            passed = False
        now = time.monotonic()
        if passed and now <= deadline:
            return now - start
        if now >= deadline:
            raise E2EError(message)
        time.sleep(min(0.5, deadline - now))


def local(argv: list[str], *, timeout: int = 1800) -> bytes:
    if argv and argv[0] == "docker":
        argv = ["docker", "--host", "unix:///var/run/docker.sock", *argv[1:]]
    try:
        with tempfile.TemporaryFile() as log:
            result = subprocess.run(
                argv, cwd=REPOSITORY, stdout=log, stderr=log, timeout=timeout, check=False
            )
            if result.returncode:
                raise E2EError("E2E local image command failed; output withheld")
            log.seek(0)
            return log.read(1024 * 1024)
    except E2EError:
        raise
    except Exception:
        raise E2EError("E2E local image command failed; output withheld") from None


class Fleet:
    def __init__(self, inventory: Inventory, *, run_id: str | None = None) -> None:
        self.inventory = inventory
        self.run_id = run_id or secrets.token_hex(12)
        self.connections = {
            host.role: SSH(inventory, host, self.run_id) for host in inventory.hosts
        }
        self.claimed: list[str] = []
        self.active: set[str] = set()
        self.previous_loaded = False
        self.images = {
            "hub": f"kornode-e2e:hub-{self.run_id}",
            "agent": f"kornode-e2e:agent-{self.run_id}",
        }
        self.image_ids: dict[str, str] = {}
        self.artifacts = REPOSITORY / "artifacts" / "e2e" / self.run_id
        self.results: dict[str, Any] = {}
        self.closed = False

    def ledger(self) -> None:
        if self.artifacts.exists():
            path = self.artifacts / "active.json"
            atomic(path, {"run_id": self.run_id, "roles": self.claimed, "closed": self.closed})

    def call(self, role: str, action: str, case: str = "", **payload: Any) -> Any:
        return self.connections[role].call(action, case, **payload)

    def preflight(self) -> dict[str, Any]:
        results = {
            role: connection.call("preflight") for role, connection in self.connections.items()
        }
        machines = {row.get("machine") for row in results.values()}
        if len(machines) != 4 or any(
            not isinstance(value, str) or len(value) != 64 for value in machines
        ):
            raise E2EError("E2E requires four distinct machine identities")
        # The specification places the runner on hub. This also prevents an
        # explicit remote opt-in from quietly building images on a dev host.
        machine = hashlib.sha256(Path("/etc/machine-id").read_text().strip().encode()).hexdigest()
        if machine != results["hub"]["machine"]:
            raise E2EError("E2E must execute on the designated hub runner")
        return results

    def start(self) -> None:
        self.preflight()
        self.artifacts.mkdir(parents=True, mode=0o700)
        self.ledger()
        for role in self.connections:
            self.call(role, "claim")
            self.claimed.append(role)
            self.ledger()
        for kind, dockerfile in (("hub", "Dockerfile"), ("agent", "Dockerfile.agent")):
            local(
                [
                    "docker",
                    "build",
                    "--builder",
                    "default",
                    "--file",
                    dockerfile,
                    "--tag",
                    self.images[kind],
                    ".",
                ]
            )
            identifier = (
                local(["docker", "image", "inspect", "--format", "{{.Id}}", self.images[kind]])
                .decode()
                .strip()
            )
            if not identifier.startswith("sha256:"):
                raise E2EError("invalid built image identity")
            self.image_ids[kind] = identifier
        with tempfile.TemporaryDirectory(prefix="kornode-e2e-images-") as tmp:
            archive = Path(tmp) / "images.tar"
            local(["docker", "save", "--output", str(archive), *self.images.values()])
            for connection in self.connections.values():
                connection.load(archive)

    def setup(self, case: str) -> Cluster:
        if case not in CASES:
            raise E2EError("unknown E2E case")
        previous = case == "upgrade"
        if previous and not self.previous_loaded:
            if not (self.inventory.previous_hub and self.inventory.previous_agent):
                raise E2EError("previous images are required for upgrade")
            for role in self.connections:
                result = self.call(
                    role,
                    "pull_previous",
                    hub=self.inventory.previous_hub,
                    agent=self.inventory.previous_agent,
                )
                if (
                    result["hub"] == self.image_ids["hub"]
                    or result["agent"] == self.image_ids["agent"]
                ):
                    raise E2EError("upgrade baseline must differ from current images")
            self.previous_loaded = True
        self.active.add(case)
        for role in ("ext", "hub", "agent-a", "agent-b"):
            kind = "agent" if role.startswith("agent-") else "hub"
            image = self.images[kind]
            if previous and role != "ext":
                baseline = (
                    self.inventory.previous_hub if role == "hub" else self.inventory.previous_agent
                )
                if baseline is None:
                    raise E2EError("previous image is missing")
                image = baseline
            endpoint = (
                self.inventory.hub_address if role == "hub" else self.inventory.host(role).address
            )
            result = self.call(role, "deploy", case, image=image, endpoint=endpoint)
            if not previous and result["image_id"] != self.image_ids[kind]:
                raise E2EError("loaded image does not match built image")
        for role in ("hub", "ext"):

            def listener_ready(role: str = role) -> bool:
                return bool(self.call(role, "ready", case)["ready"])

            wait_for(
                listener_ready,
                120,
                "E2E VPN/control listener did not become ready",
            )
        self.call("hub", "relay", case)
        cluster = Cluster(self, case)
        cluster.enroll()
        return cluster

    def finish(self, case: str, *, outcome: str) -> None:
        directory = self.artifacts / case
        storage_failed = False
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            storage_failed = True
        for role in ("agent-a", "agent-b"):
            try:
                if storage_failed:
                    raise E2EError("artifact storage unavailable")
                reply = self.call(role, "diagnostics", case)
                data = base64.b64decode(reply["archive"], validate=True)
                if len(data) > 5 * 1024 * 1024:
                    raise E2EError("diagnostic exceeds limit")
                path = directory / f"{role}.tar.gz"
                with path.open("xb") as handle:
                    handle.write(data)
                path.chmod(0o600)
            except Exception:
                self.results[f"{case}.{role}.diagnostics"] = "unavailable"
        failures = []
        for role in reversed(tuple(self.connections)):
            try:
                self.call(role, "cleanup", case)
            except E2EError:
                failures.append(role)
        self.results[case] = {"outcome": outcome, "cleanup_failed_roles": failures}
        if not failures:
            self.active.discard(case)
        try:
            self.summary()
        except OSError:
            storage_failed = True
        if failures:
            raise E2EError("E2E cleanup incomplete; remote lease retained for owner recovery")
        if storage_failed:
            raise E2EError("E2E evidence could not be stored; owned workloads were cleaned")

    def summary(self) -> None:
        if self.artifacts.exists():
            path = self.artifacts / "summary.json"
            from tests.e2e.test_routed_interlink import BLOCKED, NETLAB_COVERAGE

            atomic(
                path,
                {
                    "run_id": self.run_id,
                    "results": self.results,
                    "scope": "Container-isolated VM tests; not host-network acceptance",
                    "blocked_contracts": BLOCKED,
                    "netlab_coverage": NETLAB_COVERAGE,
                    "upgrade_baseline_available": bool(
                        self.inventory.previous_hub and self.inventory.previous_agent
                    ),
                },
            )

    def close(self) -> None:
        failures = []
        for case in tuple(self.active):
            try:
                self.finish(case, outcome="interrupted")
            except E2EError:
                failures.append(case)
        for role in reversed(self.claimed):
            try:
                self.call(role, "release")
            except E2EError:
                failures.append(role)
        self.closed = not failures
        self.ledger()
        self.summary()
        if failures:
            raise E2EError("E2E teardown incomplete; owner recovery required")


class Cluster:
    def __init__(self, fleet: Fleet, case: str) -> None:
        self.fleet, self.case = fleet, case
        self.enrollment_seconds: dict[str, float] = {}
        self.last_upstream_status: dict[str, Any] = {}

    def call(self, role: str, action: str, **payload: Any) -> Any:
        return self.fleet.call(role, action, self.case, **payload)

    def status(self, role: str) -> dict[str, Any]:
        data = self.call(role, "status")["data"]
        if not isinstance(data, dict):
            raise E2EError("invalid agent status reply")
        return data

    def ping(self, role: str, *, relay: bool = False) -> int:
        gateway = self.fleet.inventory.host("hub").address if relay else None
        return int(self.call(role, "probe", gateway=gateway)["status"])

    def enroll(self) -> None:
        for role in ("agent-a", "agent-b"):
            started = time.monotonic()
            created = self.call("hub", "create_agent", name=role)
            token = created.pop("token")
            self.call(role, "enroll", token=token)
            del token

            def connected(role: str = role) -> bool:
                return self.ping(role) == 204

            wait_for(
                connected,
                30,
                "agent enrollment/interlink exceeded deadline",
            )
            self.enrollment_seconds[role] = time.monotonic() - started
        self.fleet.results[f"{self.case}.enrollment_seconds"] = dict(self.enrollment_seconds)
        for role in ("agent-a", "agent-b"):

            def confirmed(role: str = role) -> bool:
                return int(self.status(role).get("applied_version", 0)) > 0

            wait_for(
                confirmed,
                150,
                "initial agent bundle was not confirmed",
            )

    def tcp_unreachable(
        self,
        listener: str,
        connector: str,
        host: str,
        *,
        source: str | None = None,
        seconds: int = 25,
        client: bool = False,
        awg: bool = False,
    ) -> bool:
        """True when nothing connecting `connector` -> host:9100 for `seconds` reaches the
        listener: the fail-closed check of an exit that is down."""
        result: dict[str, Any] = {}

        def listen() -> None:
            try:
                result["peer"] = self.call(listener, "interlink_listen", seconds=seconds)["peer"]
            except E2EError as exc:
                result["error"] = exc

        thread = threading.Thread(target=listen, daemon=True)
        thread.start()
        deadline = time.monotonic() + seconds - 3
        reached = False
        attempts = 0
        while thread.is_alive() and time.monotonic() < deadline:
            attempts += 1
            reached = bool(
                self.call(
                    connector, "interlink_connect", host=host, source=source, client=client, awg=awg
                )["ok"]
            )
            if reached:
                break
            time.sleep(1)
        thread.join(seconds + 30)
        if "error" in result:
            raise result["error"]
        if not attempts or thread.is_alive() or "peer" not in result:
            raise E2EError("fail-closed listener did not complete its observation window")
        if reached or result.get("peer") is not None:
            lines = [f"{connector} -> {host} reached {listener} (peer {result.get('peer')})"]
            for role in ("hub", listener):
                for name, text in self.call(role, "net_dump").items():
                    lines.append(f"--- {role} {name}\n{text}")
            raise E2EError("\n".join(lines))
        return True

    def tcp_peer(
        self,
        listener: str,
        connector: str,
        host: str,
        *,
        source: str | None = None,
        seconds: int = 120,
        client: bool = False,
        listener_client: bool = False,
        awg: bool = False,
    ) -> str:
        """Open a TCP connection `connector` -> host:9100 where `listener` accepts it;
        return the peer address the listener saw (NAT would change it). `client` /
        `listener_client` run the connecting / listening side in the throwaway client
        container of agent-b instead of its node container."""
        result: dict[str, Any] = {}

        def listen() -> None:
            try:
                result["peer"] = self.call(
                    listener, "interlink_listen", seconds=seconds, client=listener_client
                )["peer"]
            except E2EError as exc:
                result["error"] = exc

        thread = threading.Thread(target=listen, daemon=True)
        thread.start()
        deadline = time.monotonic() + seconds
        while thread.is_alive() and time.monotonic() < deadline:
            if self.call(
                connector, "interlink_connect", host=host, source=source, client=client, awg=awg
            )["ok"]:
                break
            time.sleep(2)
        thread.join(30)
        if "error" in result:
            raise result["error"]
        peer = result.get("peer")
        if not isinstance(peer, str):
            roles = dict.fromkeys(("hub", "agent-a", listener, connector))
            dumps = {role: self.call(role, "net_dump") for role in roles}
            lines = [f"no connection {connector} -> {host} reached {listener}"]
            for role, dump in dumps.items():
                lines += [f"--- {role} {name}\n{text}" for name, text in dump.items()]
            raise E2EError("\n".join(lines))
        return peer

    def changed(self, role: str, dpd: int = 25, *, seconds: float = 10) -> int:
        started = time.monotonic()
        updated = self.call("hub", "change", name=role, dpd=dpd)
        version = int(updated["desired_version"])
        wait_for(
            lambda: self.status(role).get("applied_version", 0) >= version,
            max(0.01, seconds - (time.monotonic() - started)),
            "registry change did not reach confirmed agent state within SLA",
        )
        if time.monotonic() - started > seconds:
            raise E2EError("registry-to-agent SLA exceeded")
        self.fleet.results[f"{self.case}.registry_apply_seconds"] = time.monotonic() - started
        return version

    def configure_upstream(self) -> None:
        password = secrets.token_urlsafe(32)
        pin = self.call("ext", "ext_user", password=password)["pin"]
        self.call(
            "hub",
            "upstream",
            spec={
                "interface": "oc-office",
                "server": self.fleet.inventory.host("ext").address,
                "port": 443,
                "auth_type": "password",
                "username": "e2e",
                "password": password,
                "transport": "tcp",
                "server_cert_pin": pin,
                "check_host": "10.8.0.1",
            },
        )
        del password
        wait_for(lambda: self.upstream_healthy(), 150, "external upstream did not become healthy")

    def upstream_summary(self) -> str:
        """Non-secret tunnel state of the last health check, for assertion messages."""
        status = self.last_upstream_status
        tunnels = [
            (t.get("name"), t.get("up"), str(t.get("error") or "")[:80])
            for t in status.get("tunnels") or []
        ]
        return (
            f"running={status.get('running')} hub_reachable={status.get('hub_reachable')} "
            f"pending={status.get('pending_version')} tunnels={tunnels}"
        )

    def upstream_healthy(self) -> bool:
        status = self.status("agent-a")
        self.last_upstream_status = status
        return status.get("pending_version") is None and any(
            tunnel.get("name") == "upstream:office" and tunnel.get("up")
            for tunnel in status.get("tunnels") or []
        )

    def upgrade(self) -> float:
        self.call("ext", "upgrade_traffic_start")
        self.call(
            "agent-b", "upgrade_traffic_start",
            host=self.fleet.inventory.host("ext").address,
            expected=self.fleet.inventory.host("agent-a").address,
        )
        traffic: dict[str, Any] = {}

        def client_ready(after: int = 1) -> bool:
            traffic.update(self.call("agent-b", "upgrade_traffic_status"))
            return bool(traffic["healthy"] and traffic["successes"] > after)

        wait_for(client_ready, 30, "upgrade access-client baseline forwarding failed")
        stop = threading.Event()
        samples: list[tuple[float, bool]] = []

        def observe() -> None:
            while not stop.is_set():
                try:
                    healthy = self.ping("agent-a") == 204
                except E2EError:
                    healthy = False
                samples.append((time.monotonic(), healthy))
                stop.wait(0.5)

        thread = threading.Thread(target=observe, daemon=True)
        thread.start()
        try:
            wait_for(
                lambda: len([v for _, v in samples if v]) >= 2,
                20,
                "upgrade baseline traffic failed",
            )
            result = self.call("hub", "restart", image=self.fleet.images["hub"])
            if result["image_id"] != self.fleet.image_ids["hub"]:
                raise E2EError("hub upgrade image mismatch")
            for role in ("agent-a", "agent-b"):
                result = self.call(role, "restart", image=self.fleet.images["agent"])
                if result["image_id"] != self.fleet.image_ids["agent"]:
                    raise E2EError("agent upgrade image mismatch")
            wait_for(
                lambda: self.ping("agent-a") == 204 and self.ping("agent-b") == 204,
                120,
                "upgrade did not reconnect agents",
            )
            # Read after all image replacements; cached pre-upgrade successes cannot
            # satisfy recovery. The observer lives in the independent client container.
            previous_successes = int(self.call("agent-b", "upgrade_traffic_status")["successes"])
            wait_for(
                lambda: client_ready(previous_successes),
                40,
                "upgrade access-client forwarding did not recover automatically",
            )
            completed = time.monotonic()
            wait_for(
                lambda: any(timestamp > completed and healthy for timestamp, healthy in samples),
                40,
                "upgrade traffic did not recover",
            )
        finally:
            stop.set()
            thread.join(timeout=40)
        if thread.is_alive():
            raise E2EError("upgrade traffic observer did not terminate")
        good = [timestamp for timestamp, healthy in samples if healthy]
        if len(good) < 2:
            raise E2EError("upgrade has insufficient traffic samples")
        gap = max((b - a for a, b in zip(good, good[1:], strict=False)), default=0)
        self.fleet.results[f"{self.case}.max_probe_gap_seconds"] = gap
        client_gap = float(traffic["max_gap_seconds"])
        self.fleet.results[f"{self.case}.client_traffic"] = dict(traffic)
        self.fleet.results[f"{self.case}.max_client_gap_seconds"] = client_gap
        if traffic["wrong_peer"]:
            raise E2EError("upgrade client traffic bypassed the access node")
        return max(gap, client_gap)
