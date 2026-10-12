from __future__ import annotations

import ipaddress
import time

import pytest

from kornode.net.addressing import (
    LocalNetwork,
    OwnedPrefix,
    check_overlaps,
    derive_addresses,
    render_template,
    validate_templates,
)
from kornode.net.errors import PolicyError

DEFAULTS = {
    "fabric_cidr": "10.99.0.0/24",
    "client_pool": "10.100.{id}.0/24",
    "source_pool": "10.8.{id}.0/24",
}


def net(text: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(text)


def test_node3_matches_the_spec_table() -> None:
    derived = derive_addresses(3, domain="kornode.internal", **DEFAULTS)

    assert str(derived.fabric_address) == "10.99.0.3"
    assert str(derived.client_pool) == "10.100.3.0/24"
    assert str(derived.service_address) == "10.100.3.1"
    assert str(derived.source_pool) == "10.8.3.0/24"
    assert derived.dns_zone == "node3.kornode.internal"


def test_hub_is_node1() -> None:
    derived = derive_addresses(1, domain="kornode.internal", **DEFAULTS)

    assert str(derived.fabric_address) == "10.99.0.1"
    assert str(derived.service_address) == "10.100.1.1"


def test_default_templates_are_valid_and_fast() -> None:
    started = time.monotonic()
    validate_templates(**DEFAULTS)
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"client_pool": "10.100.3.0/24"}, "exactly one"),
        ({"client_pool": "10.{id}.{x}.0/24"}, "exactly one"),
        ({"client_pool": "10.100.{id}.128/24"}, "not a valid network"),
        ({"client_pool": "10.100.{id}0.0/24"}, "not a valid network"),
        # /16 per id: every id's pool overlaps the next one's.
        ({"client_pool": "10.{id}.0.0/15"}, "not a valid network|overlaps"),
        ({"source_pool": "10.100.{id}.0/24"}, "overlaps"),
        ({"fabric_cidr": "10.100.0.0/16"}, "overlaps"),
    ],
)
def test_bad_templates_are_rejected(overrides: dict[str, str], message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        validate_templates(**{**DEFAULTS, **overrides})


def test_template_overlapping_reserved_is_rejected() -> None:
    with pytest.raises(PolicyError, match="reserved 10.8.0.0/16"):
        validate_templates(**DEFAULTS, reserved=["10.8.0.0/16"])


def test_render_template() -> None:
    assert render_template("10.100.{id}.0/24", 42) == net("10.100.42.0/24")


def test_derive_rejects_ids_out_of_range_and_tiny_fabric() -> None:
    with pytest.raises(PolicyError, match="outside"):
        derive_addresses(255, domain="d", **DEFAULTS)
    with pytest.raises(PolicyError, match="no host address"):
        derive_addresses(9, domain="d", **{**DEFAULTS, "fabric_cidr": "10.99.0.0/29"})


def test_rule1_prefixes_of_different_nodes() -> None:
    result = check_overlaps(
        [
            OwnedPrefix(net("10.100.3.0/24"), 3, "client_pool"),
            OwnedPrefix(net("10.100.0.0/16"), 2, "lan", adding=True),
        ],
        fabric_cidr="10.99.0.0/24",
        local_networks=[LocalNetwork(net("10.100.0.0/16"), 2, "eth1")],
    )

    assert [c.to_dict() for c in result.errors] == [
        {
            "prefix": "10.100.0.0/16",
            "node": 2,
            "with": "10.100.3.0/24",
            "owner": "node 3 client_pool",
        }
    ]


def test_same_node_prefixes_may_nest() -> None:
    result = check_overlaps(
        [
            OwnedPrefix(net("192.168.3.0/24"), 3, "lan"),
            OwnedPrefix(net("192.168.3.128/25"), 3, "source"),
        ],
        fabric_cidr="10.99.0.0/24",
        local_networks=[LocalNetwork(net("192.168.3.0/24"), 3, "eth1")],
    )

    assert result.ok and not result.warnings


def test_rule2_fabric_cidr_and_reserved() -> None:
    result = check_overlaps(
        [
            OwnedPrefix(net("10.99.0.0/25"), 2, "lan"),
            OwnedPrefix(net("172.16.5.0/24"), 2, "source"),
        ],
        fabric_cidr="10.99.0.0/24",
        reserved=["172.16.0.0/12"],
    )

    owners = sorted(conflict.owner for conflict in result.errors)
    assert owners == ["fabric.cidr", "fabric.reserved"]


def test_rule3_error_when_adding_warning_when_existing() -> None:
    local = LocalNetwork(net("10.100.0.0/16"), 2, "eth1")
    adding = check_overlaps(
        [OwnedPrefix(net("10.100.3.0/24"), 3, "client_pool", adding=True)],
        fabric_cidr="10.99.0.0/24",
        local_networks=[local],
    )
    existing = check_overlaps(
        [OwnedPrefix(net("10.100.3.0/24"), 3, "client_pool")],
        fabric_cidr="10.99.0.0/24",
        local_networks=[local],
    )

    expected = {
        "prefix": "10.100.3.0/24",
        "node": 3,
        "with": "10.100.0.0/16",
        "owner": "node 2 local (eth1)",
    }
    assert [c.to_dict() for c in adding.errors] == [expected]
    assert adding.error_body() == {"error": "address_overlap", "conflicts": [expected]}
    assert existing.ok
    assert [c.to_dict() for c in existing.warnings] == [expected]


def test_rule3_ignores_the_nodes_own_local_networks() -> None:
    result = check_overlaps(
        [OwnedPrefix(net("192.168.3.0/24"), 3, "lan", adding=True)],
        fabric_cidr="10.99.0.0/24",
        local_networks=[LocalNetwork(net("192.168.3.0/24"), 3, "eth1")],
    )

    assert result.ok and not result.warnings


def test_rule4_exported_lan_not_reported_is_a_warning() -> None:
    result = check_overlaps(
        [OwnedPrefix(net("192.168.3.0/24"), 3, "lan", adding=True)],
        fabric_cidr="10.99.0.0/24",
    )

    assert result.ok
    assert [c.owner for c in result.warnings] == ["not reported as local on node 3"]
