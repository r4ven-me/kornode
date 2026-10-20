from __future__ import annotations

from typing import Any

_STATUS = {
    "unauthorized": 401,
    "revoked": 403,
    "not_found": 404,
    "conflict": 409,
    "rate_limited": 429,
    "invalid": 400,
    "internal": 500,
}


class ControlError(Exception):
    """An API failure rendered as `{"error": code, "message": ...}`."""

    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status if status is not None else _STATUS[code]

    def body(self) -> dict[str, Any]:
        return {"error": self.code, "message": self.message}
