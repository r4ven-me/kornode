"""kornode.net: the only code that changes kernel networking state.

Pure desired-state model, egress compiler, diff, kernel adapter and
reconciler shared by the hub and agents (docs/spec/04-netcore-reconciler.md).
Imports are restricted to the stdlib, pydantic, pyroute2 and this package;
tests/test_net_imports.py enforces it.
"""
