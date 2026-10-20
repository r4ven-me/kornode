from __future__ import annotations

import subprocess
import time

import pytest
from tests.netlab.helpers import tcp_check
from tests.netlab.lab import Lab, namespace_names


@pytest.mark.netlab
def test_lab_wires_two_namespaces_and_tears_down() -> None:
    lab = Lab()
    server_process: subprocess.Popen[bytes] | None = None
    try:
        left = lab.add_namespace("left")
        right = lab.add_namespace("right")
        lab.add_veth(left, right, addr_a="10.200.1.1/24", addr_b="10.200.1.2/24")

        server_process = subprocess.Popen(  # noqa: S603 - explicit argv, no shell
            [
                "ip",
                "netns",
                "exec",
                right.full_name,
                "python3",
                "-m",
                "http.server",
                "18080",
                "--bind",
                "10.200.1.2",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if tcp_check(left, "10.200.1.2", 18080, timeout=1.0):
                break
            time.sleep(0.1)
        assert tcp_check(left, "10.200.1.2", 18080, timeout=1.0)
    finally:
        if server_process is not None:
            server_process.terminate()
            try:
                server_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                server_process.kill()
                server_process.wait()
        created_names = {namespace.full_name for namespace in lab.namespaces}
        lab.teardown()

    remaining = namespace_names(lab.runner.run(["ip", "netns", "list"], check=False))
    assert created_names.isdisjoint(remaining)
