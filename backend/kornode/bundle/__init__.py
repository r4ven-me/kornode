"""kornode.bundle: the signed desired-state document shared by hub and agent.

Models, canonical encoding, Ed25519 signing, secret sealing and the single
validator (docs/spec/05-control-plane.md, D-34..D-37). Imports are restricted
to the stdlib, pydantic, cryptography and kornode.net / this package;
tests/test_bundle_imports.py enforces it.
"""
