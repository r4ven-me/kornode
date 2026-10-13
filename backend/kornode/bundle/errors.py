from __future__ import annotations


class BundleError(Exception):
    """A bundle (or one of its parts) is not acceptable.

    `code` is stable and machine-readable (`too_large`, `bad_signature`,
    `malformed`, `replay`, ...); the message never contains secret material.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
