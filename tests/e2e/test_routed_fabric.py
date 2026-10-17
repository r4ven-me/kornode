"""Unimplemented P4 expectations are explicit blockers, never fabricated success.

The P3 cache/upgrade probes exercise fabric/upstream connectivity, not client
throughput, no-NAT routed prefixes or wg-easy access/exit runtime.
"""

import pytest

pytestmark = pytest.mark.e2e

BLOCKED = {
    "E2E-07": "P4 access/exit, source routing and domain resolution are not implemented",
    "NL-01": "P4 routed fabric/Prometheus export (no fabric NAT)",
    "NL-02": "P4 fabric internal DNS",
    "NL-03": "P4 agent access server and client forwarding/MSS",
    "NL-04": "P4 iroute/LAN prefix forwarding",
    "NL-05": "P4 attached wg-easy source and fail-closed packet capture",
    "NL-06": "P4 source-prefix export to hub monitoring",
    "NL-07": "P4 local delivery with the new egress model",
    "NL-08": "VM client leak capture requires the P4 client data path",
    "NL-09": "VM client loss/MTU transfer requires the P4 client data path",
    "NL-13-forwarding": "cache/upstream connectivity covered; client continuity requires P4",
    "E2E-06-clients": "fabric probes covered; upgrade with access-client traffic requires P4",
}


@pytest.mark.parametrize("scenario,reason", BLOCKED.items(), ids=BLOCKED)
def test_pending_runtime_contract(scenario: str, reason: str) -> None:
    pytest.skip(f"{scenario} blocked: {reason}")
