from __future__ import annotations


class NetError(Exception):
    """Base class for kornode.net errors."""


class PolicyError(NetError):
    """An egress policy or its inputs failed validation."""


class ApplyError(NetError):
    """Applying a plan to the kernel failed."""
