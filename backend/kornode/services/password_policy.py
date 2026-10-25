from __future__ import annotations

MIN_ADMIN_PASSWORD_LENGTH = 12
# Values shipped in examples/compose defaults or guessed first. Compared case-insensitively.
PLACEHOLDER_PASSWORDS = frozenset({"change-me", "changeme", "admin", "password", "kornode"})


def is_placeholder_password(password: str) -> bool:
    return password.strip().lower() in PLACEHOLDER_PASSWORDS


def validate_new_admin_password(password: str) -> str:
    """Policy for *new* admin passwords only; existing configs are never rejected at load."""
    if len(password) < MIN_ADMIN_PASSWORD_LENGTH:
        raise ValueError(
            f"the administrator password must be at least {MIN_ADMIN_PASSWORD_LENGTH} characters"
        )
    if is_placeholder_password(password):
        raise ValueError("the administrator password must not be a well-known placeholder")
    return password
