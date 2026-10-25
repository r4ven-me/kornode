"""P4-03 (D-66): real dnsmasq of the hub and of an agent in namespaces.

The configurations are what the hub renderer and the agent render from a
compiled bundle; the veth stands in for the interlink session (routes only, the
tunnel itself is covered by the P3/P4 suites).
"""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from tests.netlab.helpers import NetlabCommandError, dns_query
from tests.netlab.lab import Lab, Namespace
from tests.test_bundle_service import Env

from kornode.renderers import DnsmasqConfigRenderer
from kornode.services.agents import AgentService
from kornode.services.interlink_dns import DnsRecordInput, InterlinkDnsService
from kornode_agent.dns import render

pytestmark = pytest.mark.netlab

HUB_RESOLVER = "10.100.1.1"
AGENT_RESOLVER = "10.100.3.1"


@dataclass
class DnsLab:
    hub: Namespace
    agent: Namespace
    hub_conf: Path
    agent_conf: Path
    processes: dict[str, subprocess.Popen[bytes]]
    agent_link: str

    def interlink_up(self) -> None:
        self.agent.run(["ip", "addr", "add", "10.99.0.3/24", "dev", self.agent_link])
        self.agent.run(["ip", "route", "add", "10.100.1.0/24", "via", "10.99.0.1"])

    def start(self, which: str) -> None:
        ns, conf = (self.hub, self.hub_conf) if which == "hub" else (self.agent, self.agent_conf)
        self.processes[which] = subprocess.Popen(  # noqa: S603 - explicit argv, no shell
            [
                "ip",
                "netns",
                "exec",
                ns.full_name,
                "/usr/sbin/dnsmasq",
                "--keep-in-foreground",
                f"--conf-file={conf}",
                "--pid-file=",
                "--user=root",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def stop(self, which: str) -> None:
        process = self.processes.pop(which, None)
        if process is not None:
            process.terminate()
            process.wait(timeout=5)


def _resolve(ns: Namespace, name: str, server: str, *, timeout: float = 10.0) -> str | None:
    deadline = time.monotonic() + timeout
    answer = None
    while time.monotonic() < deadline:
        answer = dns_query(ns, name, server, timeout=1.0)
        if answer is not None:
            return answer
        time.sleep(0.2)
    return answer


def _no_answer(ns: Namespace, name: str, server: str) -> bool:
    """NXDOMAIN/timeout (None) or an error rcode such as SERVFAIL/REFUSED."""
    try:
        return dns_query(ns, name, server, timeout=3.0) is None
    except NetlabCommandError:
        return True


@pytest.fixture
def dns_lab(lab: Lab, tmp_path: Path) -> Iterator[DnsLab]:
    env = Env(tmp_path)
    env.add(3)
    agents = AgentService(env.config, bundles=env.service, sync=lambda: None)
    dns = InterlinkDnsService(env.config, agents=agents, restart_dnsmasq=lambda: None)
    dns.add(DnsRecordInput(name="monitoring", type="A", value="10.100.1.20"))
    dns.add(DnsRecordInput(name="nas", type="A", value="192.168.3.10", node="node3"))
    bundle = env.check(env.registry.latest_bundle(3)).bundle
    agent_conf = tmp_path / "agent-dnsmasq.conf"
    agent_conf.write_text(render(bundle) or "", encoding="utf-8")
    hub_conf = DnsmasqConfigRenderer().target_path(env.config)

    hub = lab.add_namespace("hub")
    agent = lab.add_namespace("agent")
    # The agent side of the "interlink" gets its address in the test: the
    # resolver must cope with a source address that appears later.
    lab.add_veth(hub, agent, addr_a="10.99.0.1/24")
    hub.run(["ip", "addr", "add", f"{HUB_RESOLVER}/32", "dev", "lo"])
    hub.run(["ip", "route", "add", "10.100.3.0/24", "via", "10.99.0.3"])
    handle = DnsLab(hub, agent, hub_conf, agent_conf, {}, lab.veths[-1][1])
    try:
        yield handle
    finally:
        for which in list(handle.processes):
            handle.stop(which)
        env.registry.conn.close()


def test_agent_resolves_own_zone_locally_and_the_rest_through_the_hub(dns_lab: DnsLab) -> None:
    dns_lab.start("hub")
    # The agent's resolver starts before its listen address (bind-dynamic) and
    # its forwarding source, the interlink address, exist: as at boot, before the
    # reconciler binds lo and before the interlink session is up.
    dns_lab.start("agent")
    time.sleep(0.5)
    dns_lab.agent.run(["ip", "addr", "add", f"{AGENT_RESOLVER}/32", "dev", "lo"])
    dns_lab.interlink_up()

    agent = dns_lab.agent
    assert _resolve(agent, "node3.kornode.lan", AGENT_RESOLVER) == AGENT_RESOLVER
    assert _resolve(agent, "nas.node3.kornode.lan", AGENT_RESOLVER) == "192.168.3.10"
    assert _resolve(agent, "monitoring.kornode.lan", AGENT_RESOLVER) == "10.100.1.20"
    assert _resolve(agent, "hub.kornode.lan", AGENT_RESOLVER) == HUB_RESOLVER
    # The hub answers the whole zone, node zones included, from local data.
    assert _resolve(agent, "nas.node3.kornode.lan", HUB_RESOLVER) == "192.168.3.10"
    assert _no_answer(agent, "missing.kornode.lan", HUB_RESOLVER)


def test_agent_zone_keeps_resolving_with_the_hub_resolver_down(dns_lab: DnsLab) -> None:
    dns_lab.agent.run(["ip", "addr", "add", f"{AGENT_RESOLVER}/32", "dev", "lo"])
    dns_lab.interlink_up()
    dns_lab.start("agent")
    agent = dns_lab.agent
    assert _resolve(agent, "nas.node3.kornode.lan", AGENT_RESOLVER) == "192.168.3.10"
    assert _no_answer(agent, "monitoring.kornode.lan", AGENT_RESOLVER)


def test_agent_set_resolver_asks_the_hub_resolver_over_the_interlink(dns_lab: DnsLab) -> None:
    """D-78: the node pre-resolves its domain sets through the hub resolver (stdlib client)."""
    dns_lab.start("hub")
    dns_lab.interlink_up()
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        "from kornode_agent.resolver import TYPE_A, udp_lookup;"
        f"print(udp_lookup('monitoring.kornode.lan', ['{HUB_RESOLVER}'], TYPE_A)[0][0])"
    )
    backend = str(Path(__file__).resolve().parents[2] / "backend")
    deadline = time.monotonic() + 10
    answer = ""
    while time.monotonic() < deadline and not answer.strip():
        answer = dns_lab.agent.run([sys.executable, "-I", "-c", code, backend], check=False).stdout
        time.sleep(0.2)
    assert answer.strip() == "10.100.1.20"
