from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from kornode.bundle.canonical import MAX_BODY_BYTES, canonical_json, content_hash
from kornode.bundle.errors import BundleError
from kornode.bundle.models import Bundle
from kornode.bundle.sealing import (
    SECRET_MARKER,
    digest_secrets,
    public_bytes,
    seal,
    seal_secrets,
    unseal,
    walk_sealed,
)
from kornode.bundle.signing import key_id, load_or_create_signing_key, sign, verify
from kornode.bundle.validator import validate

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/spec/examples/bundle.node3.example.json"


def _example() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    return data


def test_example_parses_into_model() -> None:
    Bundle.model_validate(_example())


def test_example_matches_json_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")  # declared in the dev extras
    schemas = EXAMPLE.parents[1] / "schemas"
    bundle_schema = json.loads((schemas / "bundle.v1.schema.json").read_text(encoding="utf-8"))
    egress_schema = json.loads((schemas / "egress.v1.schema.json").read_text(encoding="utf-8"))
    from referencing import Registry, Resource

    registry = Registry().with_resource(
        "egress.v1.schema.json", Resource.from_contents(egress_schema)
    )
    jsonschema.Draft202012Validator(bundle_schema, registry=registry).validate(_example())


def test_sign_verify_roundtrip_and_tamper() -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {key_id(key.public_key()): key.public_key()}
    body = canonical_json({"a": 1})
    envelope = sign(body, key)

    assert verify(body, envelope, trusted) == key_id(key.public_key())
    with pytest.raises(BundleError) as bad:
        verify(body + b" ", envelope, trusted)
    assert bad.value.code == "bad_signature"
    with pytest.raises(BundleError):
        verify(body, envelope, {})  # unknown key id


def test_signature_is_domain_separated() -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {key_id(key.public_key()): key.public_key()}
    body = b"{}"
    raw = base64.b64encode(key.sign(body)).decode()  # signed without the domain prefix
    with pytest.raises(BundleError):
        verify(body, f"ed25519:{key_id(key.public_key())}:{raw}", trusted)


def test_oversized_body_rejected_before_verify() -> None:
    key = Ed25519PrivateKey.generate()
    with pytest.raises(BundleError) as bad:
        verify(b"x" * (MAX_BODY_BYTES + 1), sign(b"x", key), {})
    assert bad.value.code == "too_large"


def test_signing_key_persisted_with_mode_0600(tmp_path: Path) -> None:
    path = tmp_path / "control" / "signing.ed25519"
    first = load_or_create_signing_key(path)
    second = load_or_create_signing_key(path)

    assert path.stat().st_mode & 0o777 == 0o600
    assert key_id(first.public_key()) == key_id(second.public_key())


def test_canonical_json_rejects_floats() -> None:
    with pytest.raises(BundleError):
        canonical_json({"a": 1.5})
    assert canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()


def test_seal_unseal_and_path_binding() -> None:
    private = X25519PrivateKey.generate()
    pub = public_bytes(private.public_key())
    sealed = seal("hunter2", pub, 3, "/tunnels/upstreams/0/password")

    assert unseal(sealed, private, 3, "/tunnels/upstreams/0/password") == "hunter2"
    with pytest.raises(BundleError) as moved:
        unseal(sealed, private, 3, "/tunnels/upstreams/0/key")
    assert moved.value.code == "unseal_failed"
    with pytest.raises(BundleError):
        unseal(sealed, private, 4, "/tunnels/upstreams/0/password")
    with pytest.raises(BundleError):
        unseal(sealed, X25519PrivateKey.generate(), 3, "/tunnels/upstreams/0/password")


def test_sealing_is_randomized_but_digest_is_stable() -> None:
    private = X25519PrivateKey.generate()
    pub = public_bytes(private.public_key())
    plan = {"version": 1, "generated_at": "a", "x": [{"password": {SECRET_MARKER: "s3cr3t-value"}}]}

    first = seal_secrets(plan, pub, 3)
    second = seal_secrets(plan, pub, 3)
    assert first != second
    assert [p for p, _ in walk_sealed(first)] == ["/x/0/password"]
    assert "s3cr3t-value" not in json.dumps(first)

    later = {**plan, "version": 9, "generated_at": "b"}
    key = b"k" * 32
    assert content_hash(digest_secrets(plan, key, 3)) == content_hash(digest_secrets(later, key, 3))
    changed = copy.deepcopy(plan)
    changed["x"][0]["password"][SECRET_MARKER] = "other"
    assert content_hash(digest_secrets(plan, key, 3)) != content_hash(
        digest_secrets(changed, key, 3)
    )


def _signed(doc: dict[str, Any], key: Ed25519PrivateKey) -> tuple[bytes, str]:
    body = canonical_json(doc)
    return body, sign(body, key)


def test_validator_accepts_example_without_unsealing() -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {key_id(key.public_key()): key.public_key()}
    body, envelope = _signed(_example(), key)

    result = validate(
        body,
        envelope,
        trusted=trusted,
        high_water_version=41,
        agent_version="2.0.0",
        expected_node_id=3,
    )

    assert result.bundle.version == 42
    assert result.secrets == {}


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda d: d.update(version=5), "replay"),
        (lambda d: d.update(min_agent_version="9.0.0"), "too_old"),
        (lambda d: d.update(unknown=1), "malformed"),
        (lambda d: d["policy"].update(egress=[]), "no_fabric"),
        (lambda d: d["policy"]["egress"][1].update(via="upstream:nope"), "policy"),
    ],
)
def test_validator_rejections(mutate: Any, code: str) -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {key_id(key.public_key()): key.public_key()}
    doc = _example()
    mutate(doc)
    body, envelope = _signed(doc, key)

    with pytest.raises(BundleError) as bad:
        validate(
            body,
            envelope,
            trusted=trusted,
            high_water_version=10,
            agent_version="2.0.0",
            expected_node_id=3,
        )
    assert bad.value.code == code


def test_validator_unseals_with_agent_key() -> None:
    private = X25519PrivateKey.generate()
    key = Ed25519PrivateKey.generate()
    trusted = {key_id(key.public_key()): key.public_key()}
    doc = _example()
    doc["tunnels"]["upstreams"][0]["password"] = seal(
        "pw", public_bytes(private.public_key()), 3, "/tunnels/upstreams/0/password"
    )
    doc["access"]["server_key"] = seal(
        "pem", public_bytes(private.public_key()), 3, "/access/server_key"
    )
    body, envelope = _signed(doc, key)

    result = validate(
        body,
        envelope,
        trusted=trusted,
        high_water_version=0,
        agent_version="2.0.0",
        expected_node_id=3,
        seal_private_key=private,
    )
    assert result.secrets == {"/tunnels/upstreams/0/password": "pw", "/access/server_key": "pem"}

    doc["access"]["server_key"] = seal("pem", public_bytes(private.public_key()), 3, "/other")
    body, envelope = _signed(doc, key)
    with pytest.raises(BundleError) as bad:
        validate(
            body,
            envelope,
            trusted=trusted,
            high_water_version=0,
            agent_version="2.0.0",
            expected_node_id=3,
            seal_private_key=private,
        )
    assert bad.value.code == "unseal_failed"


def test_validator_rejects_bundle_for_another_node() -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {key_id(key.public_key()): key.public_key()}
    body, envelope = _signed(_example(), key)  # compiled for node 3

    with pytest.raises(BundleError) as bad:
        validate(
            body,
            envelope,
            trusted=trusted,
            high_water_version=0,
            agent_version="2.0.0",
            expected_node_id=4,
        )
    assert bad.value.code == "wrong_node"


def test_bad_signature_wins_over_malformed_body() -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {key_id(key.public_key()): key.public_key()}
    envelope = sign(b"{}", key)

    with pytest.raises(BundleError) as bad:
        validate(
            b"not json",
            envelope,
            trusted=trusted,
            high_water_version=0,
            agent_version="2.0.0",
            expected_node_id=3,
        )
    assert bad.value.code == "bad_signature"


def test_pointer_escaping_binds_keys_with_slash_and_tilde() -> None:
    private = X25519PrivateKey.generate()
    pub = public_bytes(private.public_key())
    plan = {"a/b": {"c~d": {SECRET_MARKER: "value-1"}}}

    sealed = seal_secrets(plan, pub, 3)
    ((pointer, leaf),) = list(walk_sealed(sealed))

    assert pointer == "/a~1b/c~0d"
    assert unseal(leaf, private, 3, pointer) == "value-1"


def test_validator_revalidate_skips_only_the_replay_check() -> None:
    key = Ed25519PrivateKey.generate()
    trusted = {key_id(key.public_key()): key.public_key()}
    doc = _example()
    body, envelope = _signed(doc, key)
    common = {
        "trusted": trusted,
        "high_water_version": doc["version"],
        "agent_version": "2.0.0",
        "expected_node_id": 3,
    }
    with pytest.raises(BundleError) as replay:
        validate(body, envelope, **common)  # type: ignore[arg-type]
    assert replay.value.code == "replay"
    assert validate(body, envelope, revalidate=True, **common).bundle.version == doc["version"]  # type: ignore[arg-type]

    other = Ed25519PrivateKey.generate()
    with pytest.raises(BundleError) as bad:
        validate(body, sign(body, other), revalidate=True, **common)  # type: ignore[arg-type]
    assert bad.value.code == "bad_signature"
