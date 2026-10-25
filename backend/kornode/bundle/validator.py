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
from kornode.bundle.models import BUNDLE_FORMAT, LEGACY_BUNDLE_FORMAT, MIN_AGENT_VERSION, Bundle
from kornode.bundle.sealing import unseal, walk_sealed
from kornode.bundle.signing import verify
from kornode.net.compile import NodeFacts, TunnelFact, compile_policy, gateway_tunnels
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
    for item in bundle.interlink.prefixes:
        prefixes.setdefault(item.node_id, []).append(
            ipaddress.ip_network(item.prefix, strict=False)
        )
    tunnels = {"interlink": TunnelFact(interface=bundle.tunnels.interlink.interface, up=True)}
    for upstream in bundle.tunnels.upstreams:
        tunnels[f"upstream:{upstream.name}"] = TunnelFact(interface=upstream.interface, up=True)
    tunnels.update(gateway_tunnels(bundle.policy, bundle.tunnels.interlink.interface, True))
    return NodeFacts(
        node_id=bundle.node_id,
        client_pool=ipaddress.IPv4Network(bundle.node.client_pool, strict=False),
        tunnels=tunnels,
        upstreams=tuple(upstream.name for upstream in bundle.tunnels.upstreams),
        node_prefixes={key: tuple(value) for key, value in prefixes.items()},
        interlink_ifaces=(bundle.tunnels.interlink.interface,),
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
    minimum = bundle.min_agent_version or "0.0.0"
    if raw["format"] == BUNDLE_FORMAT:
        minimum = max(minimum, MIN_AGENT_VERSION, key=_version_tuple)
    if _version_tuple(minimum) > _version_tuple(agent_version):
        raise BundleError("too_old", f"bundle needs agent >= {minimum}")
    secrets: dict[str, str] = {}
    for pointer, sealed in walk_sealed(raw):
        if seal_private_key is not None:
            plaintext = unseal(sealed, seal_private_key, bundle.node_id, pointer)
            # v1 ciphertext is bound to its original path. Only translate the
            # lookup key after authentication, never the AAD or signed body.
            if raw["format"] == LEGACY_BUNDLE_FORMAT and pointer == "/tunnels/fabric/camouflage":
                pointer = "/tunnels/interlink/camouflage"
            secrets[pointer] = plaintext
    try:
        compile_policy(bundle.policy, facts_for(bundle))
    except (PolicyError, ValueError) as exc:
        raise BundleError("policy", f"policy does not compile: {exc}") from exc
    if not bundle.tunnels.interlink.interface:
        raise BundleError("no_interlink", "bundle has no interlink tunnel")
    if not any(rule.parsed_via.kind == "interlink" for rule in bundle.policy.egress):
        raise BundleError("no_interlink", "bundle has no rule using the interlink exit")
    return Validated(bundle=bundle, key_id=signer, secrets=secrets)
