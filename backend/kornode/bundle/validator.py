"""The one validator, run by the agent on receipt and by the hub on its own output."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import ValidationError

from kornode.bundle.canonical import MAX_BODY_BYTES
from kornode.bundle.errors import BundleError
from kornode.bundle.models import Bundle
from kornode.bundle.sealing import unseal, walk_sealed
from kornode.bundle.signing import verify
from kornode.net.compile import NodeFacts, TunnelFact, compile_policy
from kornode.net.errors import PolicyError


@dataclass(frozen=True)
class Validated:
    bundle: Bundle
    key_id: str
    secrets: dict[str, str]  # JSON pointer -> plaintext (empty when not unsealed)


def _version_tuple(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError as exc:
        raise BundleError("malformed", f"invalid version {value!r}") from exc


def facts_for(bundle: Bundle) -> NodeFacts:
    """NodeFacts that make the policy compile as if every tunnel were up."""
    prefixes: dict[int, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
    for item in bundle.fabric.prefixes:
        prefixes.setdefault(item.node_id, []).append(
            ipaddress.ip_network(item.prefix, strict=False)
        )
    tunnels = {"fabric": TunnelFact(interface=bundle.tunnels.fabric.interface, up=True)}
    for upstream in bundle.tunnels.upstreams:
        tunnels[f"upstream:{upstream.name}"] = TunnelFact(interface=upstream.interface, up=True)
    return NodeFacts(
        node_id=bundle.node_id,
        client_pool=ipaddress.IPv4Network(bundle.node.client_pool, strict=False),
        tunnels=tunnels,
        upstreams=tuple(upstream.name for upstream in bundle.tunnels.upstreams),
        node_prefixes={key: tuple(value) for key, value in prefixes.items()},
        fabric_ifaces=(bundle.tunnels.fabric.interface,),
        uplink="auto",
    )


def validate(
    body: bytes,
    envelope: str,
    *,
    trusted: dict[str, Ed25519PublicKey],
    high_water_version: int,
    agent_version: str,
    expected_node_id: int,
    seal_private_key: X25519PrivateKey | None = None,
    revalidate: bool = False,
) -> Validated:
    """Spec 05 "Validator". The hub passes no `seal_private_key`: it cannot
    unseal (only the agent holds the key), so step 4 checks structure only.

    `revalidate` re-checks an already accepted (cached) bundle, whose version
    is by definition not above the high-water mark: the replay check is
    skipped, everything else runs."""
    if len(body) > MAX_BODY_BYTES:
        raise BundleError("too_large", "bundle body exceeds 1 MiB")
    signer = verify(body, envelope, trusted)
    try:
        raw: Any = json.loads(body)
        bundle = Bundle.model_validate(raw)
    except (ValueError, ValidationError) as exc:
        raise BundleError("malformed", f"bundle does not match the schema: {exc}") from exc
    if bundle.node_id != expected_node_id:
        raise BundleError("wrong_node", f"bundle is for node {bundle.node_id}")
    if not revalidate and bundle.version <= high_water_version:
        raise BundleError(
            "replay", f"version {bundle.version} is not above high-water {high_water_version}"
        )
    if bundle.min_agent_version and _version_tuple(bundle.min_agent_version) > _version_tuple(
        agent_version
    ):
        raise BundleError("too_old", f"bundle needs agent >= {bundle.min_agent_version}")
    secrets: dict[str, str] = {}
    for pointer, sealed in walk_sealed(raw):
        if seal_private_key is not None:
            secrets[pointer] = unseal(sealed, seal_private_key, bundle.node_id, pointer)
    try:
        compile_policy(bundle.policy, facts_for(bundle))
    except (PolicyError, ValueError) as exc:
        raise BundleError("policy", f"policy does not compile: {exc}") from exc
    if not bundle.tunnels.fabric.interface:
        raise BundleError("no_fabric", "bundle has no fabric tunnel")
    if not any(rule.parsed_via.kind == "fabric" for rule in bundle.policy.egress):
        raise BundleError("no_fabric", "bundle has no rule using the fabric exit")
    return Validated(bundle=bundle, key_id=signer, secrets=secrets)
