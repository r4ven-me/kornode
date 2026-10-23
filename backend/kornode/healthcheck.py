"""Bounded, read-only local runtime readiness for Docker.

The static web /healthz route is liveness only. Readiness additionally requires
configured service processes and a recent, successful reconciler pass. Even an
intentionally disabled VPN/web runtime still needs its always-on reconciler.

Limits: reconciler status has no applied-config revision or post-apply readback
acknowledgement; its schema_hash is not a config hash. This cannot certify exact
config convergence, control API application readiness, or external VPN/DNS
availability. External outages are deliberately not container-health failures.
"""

from __future__ import annotations

import http.client
import math
import os
import ssl
import time
import xmlrpc.client

import yaml

from kornode.config.loader import load_config
from kornode.config.models import AppConfig
from kornode.net.reconciler import TIMER_SECONDS, control_request
from kornode.services.supervisor_rpc import SupervisorRpcClient, SupervisorRpcError

# No startup sleeps/retries: the first successful pass can be ready within
# Docker's 20 s start period. Short local probes leave room in its 5 s timeout.
_PROBE_TIMEOUT = 1.0
_MAX_PASS_AGE = 3 * TIMER_SECONDS


def _runtime_ready(config: AppConfig) -> bool:
    required = {"reconciler"}
    if config.server.enabled:
        required.add("ocserv")
    if config.web.enabled:
        required.add("api")
    if config.control.enabled:
        required.add("control-api")
    if config.dns_tunnel_active():
        required.add("dnsmasq")
    if config.upstream.enabled:
        required.add("upstream-watchdog")
    info = SupervisorRpcClient(
        config.generated_path("supervisor.sock"),
        timeout=_PROBE_TIMEOUT,
    ).get_all_process_info()
    if not isinstance(info, list) or any(not isinstance(entry, dict) for entry in info):
        return False
    observed = {entry.get("name"): entry.get("statename") for entry in info}
    if any(observed.get(name) != "RUNNING" for name in required):
        return False

    # Status only: never call NetService.apply/plan or probe an upstream here.
    reply = control_request(
        config.generated_path("reconciler.sock"),
        "status",
        timeout=_PROBE_TIMEOUT,
    )
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        return False
    status = reply.get("status")
    if not isinstance(status, dict):
        return False
    passes = status.get("passes")
    errors = status.get("consecutive_errors")
    last_pass = status.get("last_pass_at")
    if (
        type(passes) is not int
        or passes < 1
        or type(errors) is not int
        or errors != 0
        or status.get("last_error", "missing") is not None
        or not isinstance(last_pass, (int, float))
        or isinstance(last_pass, bool)
    ):
        return False
    age = time.time() - last_pass
    return math.isfinite(age) and 0 <= age <= _MAX_PASS_AGE


def _web_alive(config: AppConfig) -> bool:
    # Bind-all addresses are not portable connect targets. Keep explicit
    # addresses (including loopback aliases), and preserve the address family.
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(config.web.listen, config.web.listen)
    if config.web.tls:
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            host,
            config.web.port,
            timeout=_PROBE_TIMEOUT,
            context=ssl._create_unverified_context(),
        )
    else:
        connection = http.client.HTTPConnection(host, config.web.port, timeout=_PROBE_TIMEOUT)
    try:
        connection.request("GET", "/healthz")
        return connection.getresponse().status == 200
    finally:
        connection.close()


def check() -> bool:
    try:
        config_path = os.getenv("KORNODE_CONFIG")
        config = load_config(config_path) if config_path else load_config()
        return _runtime_ready(config) and (not config.web.enabled or _web_alive(config))
    except (
        OSError,
        ValueError,
        TypeError,
        yaml.YAMLError,
        SupervisorRpcError,
        xmlrpc.client.Error,
        http.client.HTTPException,
    ):
        # Config/transport errors may contain credentials; Docker only needs
        # the exit status, never exception details in its persisted health log.
        return False


def main() -> None:
    raise SystemExit(0 if check() else 1)


if __name__ == "__main__":
    main()
